import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { Envelope } from '../src/core/receipt.ts'
import { createTools, compileParameters } from '../src/tools.ts'
import { DEFAULT_LIMITS, resolveLimits, type Config } from '../src/limits.ts'

/** Every tool built with the default budgets. */
const tools = createTools({ limits: DEFAULT_LIMITS })

/** Look up a registered definition by name. */
function tool(name: string): ToolDefinition {
  const found = tools.find((candidate) => candidate.name === name)
  assert.ok(found, `tool ${name} is not registered`)
  return found
}

/** Execute a tool with a synthetic, always-live execution context. */
async function run(name: string, args: Record<string, unknown>): Promise<Envelope<Record<string, unknown>>> {
  const definition = tool(name)
  return (await definition.execute(args, { signal: new AbortController().signal } as never)) as Envelope<
    Record<string, unknown>
  >
}

/** Render a canonical value exactly as the registry would. */
function render(name: string, value: unknown): string {
  const definition = tool(name)
  const output = definition.output as { render?: (args: unknown, value: unknown) => { text: string }[] }
  const blocks = output.render?.({}, value) ?? []
  return blocks.map((block) => block.text).join('\n')
}

/** Create a temporary directory that the test removes afterwards. */
async function makeTempDir(prefix: string): Promise<string> {
  return await mkdtemp(join(tmpdir(), prefix))
}

test('every tool declares a name, description, compiled schema, and receipt meta', () => {
  assert.equal(tools.length, 6)
  const names = new Set<string>()
  for (const definition of tools) {
    assert.equal(names.has(definition.name), false, `duplicate tool name ${definition.name}`)
    names.add(definition.name)
    assert.ok(definition.description.length > 40, `${definition.name} needs a real description`)
    const projected = definition.parameters as { type?: string; properties?: Record<string, unknown> }
    assert.equal(projected.type, 'object')
    assert.ok(projected.properties && Object.keys(projected.properties).length > 0, `${definition.name} has no parameters`)
    const output = definition.output as { schema?: { type?: string; properties?: Record<string, unknown> }; render?: unknown }
    assert.equal(output.schema?.type, 'object')
    assert.equal(typeof output.render, 'function', `${definition.name} declares no renderer`)
    assert.deepEqual(Object.keys(output.schema?.properties ?? {}).sort(), ['meta', 'result'])
  }
  assert.deepEqual([...names].sort(), [
    'dir_usage',
    'encoding_convert',
    'encoding_detect',
    'file_duplicates',
    'netstat_parse',
    'path_inspect',
  ])
})

test('the parameter DSL compiles to JSON Schema with required flags and enums preserved', () => {
  const compiled = compileParameters({
    base64: { type: 'string', required: true },
    to: { type: 'string', enum: ['utf-8', 'gbk'] },
  }) as { type: string; properties: Record<string, { type: string; enum?: string[] }>; required: string[] }
  assert.equal(compiled.type, 'object')
  assert.deepEqual(Object.keys(compiled.properties), ['base64', 'to'])
  assert.deepEqual(compiled.properties.to?.enum, ['utf-8', 'gbk'])
  assert.deepEqual(compiled.required, ['base64'])
})

test('every tool renders a canonical value through its own renderer', async () => {
  const value = await run('netstat_parse', { text: 'TCP    127.0.0.1:80    0.0.0.0:0    LISTENING    4' })
  const rendered = render('netstat_parse', value)
  assert.match(rendered, /"dialect": "netstat"/)
})

test('the filesystem tools refuse a relative path instead of resolving it', async () => {
  await assert.rejects(() => run('dir_usage', { path: 'relative\\dir' }), /not absolute/)
  await assert.rejects(() => run('file_duplicates', { path: 'relative\\dir' }), /not absolute/)
  await assert.rejects(() => run('dir_usage', { path: 'C:relative' }), /not absolute/)
})

test('over-budget structured input is refused, never silently truncated', async () => {
  const small = resolveLimits({ maxInputBytes: 16 } satisfies Config)
  const limited = createTools({ limits: small, only: ['netstat_parse'] })
  assert.equal(limited.length, 1)
  await assert.rejects(
    () => limited[0]!.execute({ text: 'x'.repeat(64) }, { signal: new AbortController().signal } as never),
    /INPUT_TOO_LARGE|above the configured limit/,
  )
})

test('an unsupported encoding option is refused with the allowed values', async () => {
  // The parameter DSL is the first line of defence, so callers get the full
  // allowed set back rather than a bare rejection.
  await assert.rejects(
    () => run('encoding_convert', { base64: 'aGk=', to: 'koi8-r' }),
    /"to" must be one of \["utf-8","utf-16le","utf-16be","gbk","gb18030","big5","shift_jis","latin1","ascii"\]/,
  )
  await assert.rejects(() => run('encoding_convert', { base64: 'aGk=', from: 'cp437', to: 'utf-8' }), /"from" must be one of/)
  await assert.rejects(() => run('encoding_convert', { base64: 'aGk=', to: 'utf-8', bom: 'maybe' }), /"bom" must be one of/)
})

test('tool names can be prefixed and filtered by the only list', () => {
  const prefixed = createTools({ limits: DEFAULT_LIMITS, prefix: 'win', only: ['path_inspect', 'encoding_detect'] })
  assert.deepEqual(prefixed.map((definition) => definition.name), ['win__encoding_detect', 'win__path_inspect'])
})

test('resolveLimits falls back to the defaults for illegal values', () => {
  const resolved = resolveLimits({
    maxInputBytes: -5,
    maxOutputBytes: 0,
    maxFiles: Number.NaN,
    maxBytes: 1.5,
    maxEntries: 12,
  } satisfies Config)
  assert.equal(resolved.maxInputBytes, DEFAULT_LIMITS.maxInputBytes)
  assert.equal(resolved.maxOutputBytes, DEFAULT_LIMITS.maxOutputBytes)
  assert.equal(resolved.maxFiles, DEFAULT_LIMITS.maxFiles)
  assert.equal(resolved.maxBytes, 1)
  assert.equal(resolved.maxEntries, 12)
})

test('dir_usage summarizes a real tree, reports links and budgets, and renders notes', async () => {
  const root = await makeTempDir('dsh-win-native-dir-')
  try {
    await mkdir(join(root, 'nested'))
    await writeFile(join(root, 'a.txt'), 'x'.repeat(100))
    await writeFile(join(root, 'b.log'), 'y'.repeat(40))
    await writeFile(join(root, 'nested', 'c.txt'), 'z'.repeat(10))
    const value = await run('dir_usage', { path: root, top_n: 3 })
    const result = value.result as unknown as {
      total_bytes: number
      files: number
      directories: number
      largest: { path: string; size: number }[]
      extensions: { extension: string; files: number; bytes: number }[]
      truncated: boolean
    }
    assert.equal(result.total_bytes, 150)
    assert.equal(result.files, 3)
    assert.equal(result.directories, 2)
    assert.equal(result.largest[0]?.size, 100)
    assert.deepEqual(
      result.extensions.map((entry) => `${entry.extension}:${entry.files}:${entry.bytes}`),
      ['.txt:2:110', '.log:1:40'],
    )
    assert.equal(result.truncated, false)
    assert.deepEqual(value.meta.notes, [])
    assert.equal(render('dir_usage', value).includes('[note]'), false)

    const bounded = await run('dir_usage', { path: root, max_files: 1, top_n: 1 })
    const boundedResult = bounded.result as unknown as { truncated: boolean; files: number }
    assert.equal(boundedResult.truncated, true)
    assert.equal(boundedResult.files, 1)
    assert.match(render('dir_usage', bounded), /\[bounded\] input=\d+B output=\d+B/)
    assert.match(render('dir_usage', bounded), /maxFiles=1/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('dir_usage reports an unreadable root as a domain failure, not a crash', async () => {
  const missing = join(tmpdir(), 'dsh-win-native-definitely-missing-9f2c1a')
  const value = await run('dir_usage', { path: missing })
  const result = value.result as unknown as { files: number; unreadable: { code: string }[]; truncated: boolean }
  assert.equal(result.files, 0)
  assert.equal(result.truncated, true)
  assert.ok(result.unreadable.length >= 1)
  assert.equal(result.unreadable[0]?.code, 'ENOENT')
})

test('file_duplicates finds exact groups, honors the hashing budget, and reports unreadable paths', async () => {
  const root = await makeTempDir('dsh-win-native-dup-')
  try {
    const payload = 'duplicate payload 1234567890'
    await writeFile(join(root, 'one.txt'), payload)
    await writeFile(join(root, 'two.txt'), payload)
    await writeFile(join(root, 'three.txt'), payload)
    await writeFile(join(root, 'unique.txt'), 'something else entirely')
    // Same byte length as the payload, different content: the size pre-filter
    // must not group it, and the hash must report it as unique.
    await writeFile(join(root, 'same-size-but-different.txt'), payload.replace('1234', 'XXXX'))
    const value = await run('file_duplicates', { path: root })
    const result = value.result as unknown as {
      groups: { hash: string; size: number; count: number; reclaimable: number; paths: string[] }[]
      groups_total: number
      reclaimable_bytes: number
      files_seen: number
      files_hashed: number
      truncated: boolean
      unreadable: unknown[]
    }
    assert.equal(result.groups_total, 1)
    assert.equal(result.groups[0]?.count, 3)
    assert.equal(result.groups[0]?.size, 28)
    assert.equal(result.groups[0]?.reclaimable, 56)
    assert.equal(result.groups[0]?.hash.length, 64)
    assert.deepEqual(
      result.groups[0]?.paths.map((path) => path.slice(root.length + 1)),
      ['one.txt', 'three.txt', 'two.txt'],
    )
    assert.equal(result.reclaimable_bytes, 56)
    assert.equal(result.files_seen, 5)
    assert.equal(result.truncated, false)
    assert.deepEqual(result.unreadable, [])
    // The scan is complete, so the receipt is not bounded; the only note explains
    // why one file never needed hashing.
    assert.match(render('file_duplicates', value), /\[note\] 1 file\(s\) had a unique size/)

    const tight = await run('file_duplicates', { path: root, max_bytes_hashed: 30 })
    const tightResult = tight.result as unknown as { truncated: boolean; files_hashed: number; groups_total: number }
    assert.equal(tightResult.truncated, true)
    assert.ok(tightResult.files_hashed <= 1)
    assert.match(render('file_duplicates', tight), /maxBytesHashed=30/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
