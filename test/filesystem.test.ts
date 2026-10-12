import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { Envelope } from '../src/core/receipt.ts'
import { createTools } from '../src/tools.ts'
import { DEFAULT_LIMITS, resolveLimits } from '../src/limits.ts'
import { extensionOf, walkDirectory } from '../src/core/dirwalk.ts'
import { hashFile } from '../src/core/duplicates.ts'

const tools = createTools({ limits: DEFAULT_LIMITS })

/** Look up a registered definition by name. */
function tool(name: string, set: ToolDefinition[] = tools): ToolDefinition {
  const found = set.find((candidate) => candidate.name === name)
  assert.ok(found, `tool ${name} is not registered`)
  return found
}

/** Execute a tool with a synthetic, always-live execution context. */
async function run(name: string, args: Record<string, unknown>, set: ToolDefinition[] = tools): Promise<Envelope<Record<string, unknown>>> {
  return (await tool(name, set).execute(args, { signal: new AbortController().signal } as never)) as Envelope<
    Record<string, unknown>
  >
}

/** A fixture tree with exact, asserted sizes. */
async function makeFixtureTree(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-win-native-fs-'))
  await mkdir(join(root, 'nested', 'deeper'), { recursive: true })
  // 1000 + 512 + 256 + 128 + 64 + 32 + 16 = 2008 bytes in 7 files.
  await writeFile(join(root, 'a.txt'), 'a'.repeat(1000))
  await writeFile(join(root, 'b.txt'), 'b'.repeat(512))
  await writeFile(join(root, 'nested', 'c.log'), 'c'.repeat(256))
  await writeFile(join(root, 'nested', 'deeper', 'd.bin'), 'd'.repeat(128))
  await writeFile(join(root, 'nested', 'deeper', 'e.bin'), 'e'.repeat(64))
  await writeFile(join(root, 'f'), 'f'.repeat(32))
  await writeFile(join(root, 'g.TXT'), 'g'.repeat(16))
  return root
}

test('extensionOf is case-insensitive and reports extensionless files', () => {
  assert.equal(extensionOf('C:\\a\\b\\file.TXT'), '.txt')
  assert.equal(extensionOf('C:\\a\\b\\file.tar.gz'), '.gz')
  assert.equal(extensionOf('C:\\a\\b\\noext'), '(none)')
  assert.equal(extensionOf('C:\\a\\b\\trailing.'), '(none)')
  assert.equal(extensionOf('/posix/style/file.json'), '.json')
  assert.equal(extensionOf('/posix/style/trailing.'), '(none)')
  // A leading dot is a hidden-file marker, not an extension, on both platforms:
  // the same rule yields the same answer everywhere.
  assert.equal(extensionOf('C:\\repo\\.gitignore'), '(none)')
  assert.equal(extensionOf('/repo/.gitignore'), '(none)')
})

test('walkDirectory accounts exact sizes, depths, and the extension histogram', async () => {
  const root = await makeFixtureTree()
  try {
    const walk = await walkDirectory(root, {
      maxFiles: 100,
      maxDepth: 8,
      maxBytes: 1_000_000,
      topN: 3,
      maxErrors: 10,
      signal: new AbortController().signal,
    })
    assert.equal(walk.total_bytes, 2008)
    assert.equal(walk.files, 7)
    assert.equal(walk.directories, 3)
    assert.equal(walk.truncated, false)
    assert.deepEqual(walk.notes, [])
    assert.deepEqual(walk.skipped_links, [])
    assert.deepEqual(walk.unreadable, [])
    assert.deepEqual(
      walk.largest.map((file) => `${file.path.slice(root.length + 1)}:${file.size}:${file.depth}`),
      [`a.txt:1000:1`, `b.txt:512:1`, `${join('nested', 'c.log')}:256:2`],
    )
    assert.deepEqual(
      walk.extensions.map((entry) => `${entry.extension}:${entry.files}:${entry.bytes}`),
      [
        // `.txt` covers a.txt, b.txt and the upper-case g.TXT; the extension is
        // normalized to lower case.
        '.txt:3:1528',
        '.log:1:256',
        '.bin:2:192',
        '(none):1:32',
      ],
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('walkDirectory stops at each budget and explains which one stopped it', async () => {
  const root = await makeFixtureTree()
  try {
    const byFiles = await walkDirectory(root, {
      maxFiles: 2,
      maxDepth: 8,
      maxBytes: 1_000_000,
      topN: 5,
      maxErrors: 10,
      signal: new AbortController().signal,
    })
    assert.equal(byFiles.truncated, true)
    assert.equal(byFiles.files, 2)
    assert.match(byFiles.notes.join('\n'), /maxFiles=2/)

    const byBytes = await walkDirectory(root, {
      maxFiles: 100,
      maxDepth: 8,
      maxBytes: 1500,
      topN: 5,
      maxErrors: 10,
      signal: new AbortController().signal,
    })
    assert.equal(byBytes.truncated, true)
    assert.ok(byBytes.total_bytes <= 1500)
    assert.match(byBytes.notes.join('\n'), /maxBytes=1500/)

    const byDepth = await walkDirectory(root, {
      maxFiles: 100,
      maxDepth: 1,
      maxBytes: 1_000_000,
      topN: 5,
      maxErrors: 10,
      signal: new AbortController().signal,
    })
    assert.equal(byDepth.truncated, true)
    // `maxDepth: 1` accounts the root's own directory only, so `nested` is
    // reported as the budget boundary instead of being descended into.
    assert.equal(byDepth.directories, 1)
    assert.equal(byDepth.files, 4)
    assert.equal(byDepth.total_bytes, 1560)
    assert.match(byDepth.notes.join('\n'), /maxDepth=1/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('walkDirectory observes the abort signal so a caller can cancel it', async () => {
  const root = await makeFixtureTree()
  try {
    const done = new AbortController()
    const walk = await walkDirectory(root, {
      maxFiles: 100,
      maxDepth: 8,
      maxBytes: 1_000_000,
      topN: 5,
      maxErrors: 10,
      signal: done.signal,
    })
    assert.equal(walk.files, 7)
    assert.equal(done.signal.aborted, false)

    // A pre-aborted signal must reject before any entry is accounted.
    const aborted = new AbortController()
    aborted.abort()
    await assert.rejects(
      () =>
        walkDirectory(root, {
          maxFiles: 100,
          maxDepth: 8,
          maxBytes: 1_000_000,
          topN: 5,
          maxErrors: 10,
          signal: aborted.signal,
        }),
      (error: unknown) => error instanceof Error && error.name === 'AbortError',
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('hashFile streams a real digest and reports a missing file as an error', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-win-native-hash-'))
  try {
    await writeFile(join(root, 'payload.txt'), 'duplicate payload')
    const ok = await hashFile(join(root, 'payload.txt'), new AbortController().signal)
    assert.equal(ok.ok, true)
    if (ok.ok) {
      // SHA-256("duplicate payload"), asserted as a golden value.
      assert.equal(ok.digest, '9ecdebad208a0bd80f82fee680af0c2bea0cfca1a6049f7cb3bcb81bbd859d55')
      assert.equal(ok.bytes, 17)
    }
    const missing = await hashFile(join(root, 'nope.txt'), new AbortController().signal)
    assert.equal(missing.ok, false)
    if (!missing.ok) {
      assert.equal((missing.error as { code?: string }).code, 'ENOENT')
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('dir_usage reports exact totals, largest files, and a clean receipt', async () => {
  const root = await makeFixtureTree()
  try {
    const value = await run('dir_usage', { path: root, top_n: 2 })
    const result = value.result as unknown as {
      root: string
      total_bytes: number
      files: number
      directories: number
      largest: { path: string; size: number; depth: number }[]
      extensions: { extension: string; files: number; bytes: number }[]
      skipped_links: unknown[]
      unreadable: unknown[]
      truncated: boolean
      notes: string[]
    }
    assert.equal(result.root, root)
    assert.equal(result.total_bytes, 2008)
    assert.equal(result.files, 7)
    assert.equal(result.directories, 3)
    assert.equal(result.largest.length, 2)
    assert.equal(result.largest[0]?.size, 1000)
    assert.deepEqual(result.skipped_links, [])
    assert.deepEqual(result.unreadable, [])
    assert.equal(result.truncated, false)
    assert.deepEqual(result.notes, [])
    assert.equal(value.meta.bytesIn, Buffer.byteLength(root, 'utf8'))
    const histogram = new Map(result.extensions.map((entry) => [entry.extension, entry]))
    assert.deepEqual(histogram.get('.txt'), { extension: '.txt', files: 3, bytes: 1528 })
    assert.deepEqual(histogram.get('(none)'), { extension: '(none)', files: 1, bytes: 32 })
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('dir_usage is honest when a budget stops the walk', async () => {
  const root = await makeFixtureTree()
  try {
    const value = await run('dir_usage', { path: root, max_files: 3, max_bytes: 100_000 })
    const result = value.result as unknown as { files: number; truncated: boolean }
    assert.equal(result.files, 3)
    assert.equal(result.truncated, true)
    assert.equal(value.meta.truncated, true)
    assert.ok(value.meta.notes.some((note) => note.includes('maxFiles=3')))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('dir_usage reports a missing root with its error code rather than throwing', async () => {
  const missing = join(tmpdir(), 'dsh-win-native-missing-root-71c0')
  const value = await run('dir_usage', { path: missing })
  const result = value.result as unknown as { files: number; unreadable: { path: string; code: string; message: string }[] }
  assert.equal(result.files, 0)
  assert.equal(result.unreadable.length, 1)
  assert.equal(result.unreadable[0]?.code, 'ENOENT')
  assert.equal(result.unreadable[0]?.path, missing)
  assert.equal(value.meta.truncated, true)
})

test('file_duplicates finds exact groups by size then hash, and totals the reclaimable bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-win-native-dupes-'))
  try {
    const shared = 'the same payload in three places'
    await mkdir(join(root, 'sub'))
    await writeFile(join(root, 'copy-a.txt'), shared)
    await writeFile(join(root, 'copy-b.txt'), shared)
    await writeFile(join(root, 'sub', 'copy-c.txt'), shared)
    await writeFile(join(root, 'twin-1.bin'), 'q'.repeat(64))
    await writeFile(join(root, 'twin-2.bin'), 'q'.repeat(64))
    // Same size as the twins, different content: the size pre-filter must not
    // merge them, and the hash must separate them.
    await writeFile(join(root, 'decoy.bin'), 'r'.repeat(64))
    await writeFile(join(root, 'lonely.txt'), 'unique')
    const value = await run('file_duplicates', { path: root })
    const result = value.result as unknown as {
      groups: { hash: string; size: number; count: number; reclaimable: number; paths: string[] }[]
      groups_total: number
      reclaimable_bytes: number
      files_seen: number
      candidates_hashed: number
      files_hashed: number
      bytes_hashed: number
      unreadable: unknown[]
      truncated: boolean
    }
    assert.equal(result.groups_total, 2)
    assert.equal(result.files_seen, 7)
    assert.equal(result.candidates_hashed, 6, 'the three copies plus the three 64-byte files are the size candidates')
    assert.equal(result.files_hashed, 6)
    assert.equal(result.bytes_hashed, shared.length * 3 + 64 * 3)
    assert.equal(result.reclaimable_bytes, shared.length * 2 + 64)
    assert.equal(result.truncated, false)
    assert.deepEqual(result.unreadable, [])
    assert.equal(value.meta.truncated, false)

    const threeCopies = result.groups.find((group) => group.count === 3)!
    assert.equal(threeCopies.size, shared.length)
    assert.equal(threeCopies.reclaimable, shared.length * 2)
    assert.equal(threeCopies.hash.length, 64)
    assert.deepEqual(
      threeCopies.paths.map((path) => path.slice(root.length + 1)),
      ['copy-a.txt', 'copy-b.txt', join('sub', 'copy-c.txt')],
    )
    const twins = result.groups.find((group) => group.count === 2)!
    assert.deepEqual(
      twins.paths.map((path) => path.slice(root.length + 1)),
      ['twin-1.bin', 'twin-2.bin'],
    )
    assert.equal(result.groups[0]?.reclaimable, shared.length * 2, 'largest reclaimable first')
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('file_duplicates reports the hashing budget instead of assuming the rest is unique', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-win-native-budget-'))
  try {
    await writeFile(join(root, 'one.bin'), 'x'.repeat(100))
    await writeFile(join(root, 'two.bin'), 'x'.repeat(100))
    const value = await run('file_duplicates', { path: root, max_bytes_hashed: 50 })
    const result = value.result as unknown as { groups_total: number; files_hashed: number; truncated: boolean }
    assert.equal(result.groups_total, 0)
    assert.equal(result.files_hashed, 0)
    assert.equal(result.truncated, true)
    assert.equal(value.meta.truncated, true)
    assert.match(value.meta.notes.join('\n'), /maxBytesHashed=50/)
    assert.match(value.meta.notes.join('\n'), /may or may not be duplicates/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('file_duplicates reports unreadable paths with their error code and never writes anything', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-win-native-unreadable-'))
  try {
    const missing = join(tmpdir(), 'dsh-win-native-not-a-directory-3ac1')
    const value = await run('file_duplicates', { path: missing })
    const result = value.result as unknown as {
      files_seen: number
      unreadable: { path: string; code: string; stage: string }[]
      notes: string[]
    }
    assert.equal(result.files_seen, 0)
    assert.equal(result.unreadable.length, 1)
    assert.equal(result.unreadable[0]?.stage, 'list')
    assert.equal(result.unreadable[0]?.code, 'ENOENT')
    assert.ok(value.meta.notes.some((note) => note.includes('unreadable paths')))

    // The scan must not have created, moved or removed anything in the parent.
    const untouched = await run('file_duplicates', { path: root })
    assert.deepEqual((untouched.result as unknown as { unreadable: unknown[] }).unreadable, [])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('the filesystem tools refuse relative paths and honor the abort signal', async () => {
  await assert.rejects(() => run('dir_usage', { path: 'some\\relative' }), /not absolute/)
  await assert.rejects(() => run('file_duplicates', { path: 'some\\relative' }), /not absolute/)

  const root = await mkdtemp(join(tmpdir(), 'dsh-win-native-abort-'))
  try {
    await writeFile(join(root, 'file.txt'), 'payload')
    const controller = new AbortController()
    controller.abort()
    await assert.rejects(
      () => tool('dir_usage').execute({ path: root }, { signal: controller.signal } as never),
      (error: unknown) => error instanceof Error && error.name === 'AbortError',
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
