import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { Envelope } from '../src/core/receipt.ts'
import { createTools } from '../src/tools.ts'
import { DEFAULT_LIMITS, resolveLimits } from '../src/limits.ts'
import {
  MAX_PATH,
  foldRelative,
  inspectPath,
  isReservedName,
  isShortNameSafe,
  splitSegments,
  toExtendedPath,
} from '../src/core/winpath.ts'

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

/** The findings of one tool envelope, as `severity:code` strings. */
function codes(value: Envelope<Record<string, unknown>>): string[] {
  const result = value.result as unknown as { issues: { code: string; severity: string }[] }
  return result.issues.map((issue) => `${issue.severity}:${issue.code}`)
}

/** The findings of one direct inspection, as `severity:code` strings. */
function codesOf(inspection: { issues: { code: string; severity: string }[] }): string[] {
  return inspection.issues.map((issue) => `${issue.severity}:${issue.code}`)
}

test('reserved DOS device names are detected case-insensitively, with or without extension', () => {
  for (const name of ['CON', 'con', 'Con.txt', 'PRN', 'aux', 'AUX.log', 'NUL', 'nul.dat', 'COM1', 'com9.tar.gz', 'LPT1', 'lpt9.doc']) {
    assert.equal(isReservedName(name), true, `${name} must be reserved`)
  }
  for (const name of ['CONSOLE.txt', 'COM0', 'COM10', 'LPT0', 'NULL', 'AUXILIARY', 'PRINT', 'COM', 'LPT', 'conx']) {
    assert.equal(isReservedName(name), false, `${name} must not be reserved`)
  }
})

test('8.3 safety follows the short-name grammar', () => {
  assert.equal(isShortNameSafe('OK.TXT'), true)
  assert.equal(isShortNameSafe('a.b'), true)
  assert.equal(isShortNameSafe('verylongname.txt'), false)
  assert.equal(isShortNameSafe('name.toolong'), false)
  assert.equal(isShortNameSafe('..'), true)
  assert.equal(isShortNameSafe('with space.txt'), false)
})

test('inspectPath accepts an ordinary absolute path and canonicalizes it', () => {
  const inspection = inspectPath('C:\\Users\\ax2\\AppData\\Local\\Temp\\file.txt')
  assert.equal(inspection.absolute, true)
  assert.equal(inspection.kind, 'drive')
  assert.equal(inspection.drive, 'C')
  assert.equal(inspection.extended, false)
  assert.equal(inspection.safe_for_max_path, true)
  assert.equal(inspection.requires_extended_prefix, false)
  assert.deepEqual(inspection.issues, [])
  assert.equal(inspection.canonical, 'C:\\Users\\ax2\\AppData\\Local\\Temp\\file.txt')
  assert.equal(inspection.canonical_length, 40)
  assert.equal(inspection.length, 40)
  assert.equal(inspection.max_path_limit, MAX_PATH)
  assert.deepEqual(inspection.segments.map((segment) => segment.value), ['Users', 'ax2', 'AppData', 'Local', 'Temp', 'file.txt'])
})

test('inspectPath classifies root forms: drive-relative, root-relative, relative, UNC, extended', () => {
  const driveRelative = inspectPath('C:foo')
  assert.equal(driveRelative.absolute, false)
  assert.equal(driveRelative.kind, 'drive')
  assert.ok(driveRelative.issues.some((issue) => issue.code === 'drive_relative'))
  assert.equal(driveRelative.issues.find((issue) => issue.code === 'drive_relative')?.position, 2)
  assert.equal(driveRelative.safe_for_max_path, false)
  // The drive designator is the root, not part of the first segment, so `foo`
  // must not be reported for containing `:`.
  assert.equal(driveRelative.canonical, 'C:foo')
  assert.deepEqual(driveRelative.segments.map((segment) => segment.value), ['foo'])
  assert.deepEqual(driveRelative.issues.map((issue) => issue.code), ['drive_relative'])

  const rooted = inspectPath('\\foo\\bar')
  assert.equal(rooted.absolute, false)
  assert.equal(rooted.kind, 'rooted')
  assert.equal(rooted.canonical, '\\foo\\bar')
  assert.deepEqual(codesOf(rooted), ['error:root_relative'])

  const relative = inspectPath('foo\\bar')
  assert.equal(relative.absolute, false)
  assert.equal(relative.kind, 'none')
  assert.equal(relative.canonical, 'foo\\bar')
  assert.deepEqual(codesOf(relative), ['error:not_absolute'])

  const unc = inspectPath('\\\\server\\share\\dir\\file.txt')
  assert.equal(unc.absolute, true)
  assert.equal(unc.kind, 'unc')
  assert.equal(unc.canonical, '\\\\server\\share\\dir\\file.txt')
  assert.deepEqual(unc.issues, [])
  assert.deepEqual(unc.segments.map((segment) => segment.value), ['dir', 'file.txt'])

  const incompleteUnc = inspectPath('\\\\server')
  assert.equal(incompleteUnc.absolute, false)
  assert.ok(incompleteUnc.issues.some((issue) => issue.code === 'no_root'))
})

test('inspectPath reports reserved names, illegal characters, control characters, and trailing space or dot', () => {
  const reserved = inspectPath('C:\\temp\\CON.txt')
  assert.deepEqual(codesOf(reserved), ['error:reserved_name'])
  assert.equal(reserved.issues[0]?.position, 8)

  const illegal = inspectPath('C:\\temp\\bad<name>|x.txt')
  assert.deepEqual(codesOf(illegal), [
    'error:illegal_char',
    'error:illegal_char',
    'error:illegal_char',
  ])
  assert.match(illegal.issues[0]?.detail ?? '', /"<"/)

  const control = inspectPath('C:\\temp\\a\u0001b.txt')
  assert.deepEqual(codesOf(control), ['error:control_char'])
  assert.match(control.issues[0]?.detail ?? '', /U\+0001/)

  const trailing = inspectPath('C:\\temp\\name.txt ')
  assert.deepEqual(codesOf(trailing), ['error:segment_trailing_space_or_dot'])
  assert.equal(trailing.safe_for_max_path, false)
})

test('inspectPath compares the length against MAX_PATH and the extended limit', () => {
  const long = `C:\\data\\${'segment\\'.repeat(40)}file.txt`
  assert.ok(long.length > MAX_PATH)
  const inspection = inspectPath(long)
  assert.equal(inspection.requires_extended_prefix, true)
  assert.equal(inspection.safe_for_max_path, false)
  assert.ok(inspection.issues.some((issue) => issue.code === 'above_max_path'))
  assert.match(inspection.issues.find((issue) => issue.code === 'above_max_path')?.detail ?? '', /without \\\\\?\\ or the LongPathsEnabled/)

  const extendedLong = `\\\\?\\C:\\${'a'.repeat(320)}`
  const extendedInspection = inspectPath(extendedLong)
  assert.equal(extendedInspection.extended, true)
  assert.equal(extendedInspection.requires_extended_prefix, false)
  assert.deepEqual(codesOf(extendedInspection), ['warning:extended_prefix', 'error:segment_too_long'])

  const tooLong = `C:\\${'a'.repeat(400)}`
  assert.ok(inspectPath(tooLong).issues.some((issue) => issue.code === 'segment_too_long'))
})

test('inspectPath flags relative segments after an extended prefix and folds them otherwise', () => {
  const extended = inspectPath('\\\\?\\C:\\a\\..\\b')
  const extendedCodes = extended.issues.map((issue) => issue.code)
  assert.ok(extendedCodes.includes('dot_segment'))
  assert.ok(extendedCodes.includes('extended_prefix_with_relative'))
  assert.equal(extended.issues.find((issue) => issue.code === 'dot_segment')?.severity, 'error')

  const folded = inspectPath('C:\\a\\.\\b\\..\\c')
  assert.equal(folded.canonical, 'C:\\a\\c')
  assert.equal(folded.issues.find((issue) => issue.code === 'dot_segment')?.severity, 'warning')
  assert.deepEqual(foldRelative('C:\\a\\.\\b\\..\\c'), { path: 'C:\\a\\c', unresolved: false })
  assert.deepEqual(foldRelative('..\\a'), { path: '..\\a', unresolved: true })
})

test('toExtendedPath and splitSegments are stable across path shapes', () => {
  assert.equal(toExtendedPath('C:\\a\\b'), '\\\\?\\C:\\a\\b')
  assert.equal(toExtendedPath('C:\\a\\\\b\\'), '\\\\?\\C:\\a\\b')
  assert.equal(toExtendedPath('\\\\srv\\share\\x'), '\\\\?\\UNC\\srv\\share\\x')
  assert.equal(toExtendedPath('\\\\srv'), '\\\\?\\UNC\\srv')
  assert.equal(toExtendedPath('\\\\?\\C:\\a'), '\\\\?\\C:\\a')
  assert.equal(toExtendedPath('\\\\?\\UNC\\srv\\share\\x'), '\\\\?\\UNC\\srv\\share\\x')
  assert.deepEqual(splitSegments('C:\\\\a\\\\\\b\\\\'), ['C:', 'a', 'b'])
  assert.deepEqual(splitSegments(''), [])
})

test('path_inspect returns per-issue findings, a canonical form, and the MAX_PATH verdict', async () => {
  const value = await run('path_inspect', { path: 'C:\\temp\\CON.txt' })
  const result = value.result as unknown as {
    absolute: boolean
    extended: boolean
    kind: string
    canonical: string
    length: number
    max_path_limit: number
    safe_for_max_path: boolean
    segments: { value: string; safe_8_3: boolean }[]
    issues: { code: string; severity: string; detail: string; position: number | null }[]
  }
  assert.equal(result.absolute, true)
  assert.equal(result.kind, 'drive')
  assert.equal(result.canonical, 'C:\\temp\\CON.txt')
  assert.equal(result.length, 15)
  assert.equal(result.max_path_limit, 260)
  assert.equal(result.safe_for_max_path, false)
  assert.deepEqual(result.issues.map((issue) => issue.code), ['reserved_name'])
  assert.equal(result.issues[0]?.position, 8)
  assert.deepEqual(result.segments.map((segment) => segment.value), ['temp', 'CON.txt'])
  assert.equal(value.meta.truncated, false)
  // Findings live in `issues`; a clean path costs no extra note tokens.
  assert.deepEqual(value.meta.notes, [])
  assert.match(result.issues[0]?.detail ?? '', /reserved DOS device name/)
})

test('path_inspect is honest about long paths and never touches the filesystem', async () => {
  const longPath = `C:\\data\\${'segment\\'.repeat(40)}file.txt`
  const value = await run('path_inspect', { path: longPath })
  const result = value.result as unknown as { requires_extended_prefix: boolean; safe_for_max_path: boolean; issues: unknown[] }
  assert.equal(result.requires_extended_prefix, true)
  assert.equal(result.safe_for_max_path, false)
  assert.equal(value.meta.truncated, false)
  assert.ok(value.meta.notes.some((note) => note.includes('LongPathsEnabled')))

  const clipped = createTools({ limits: resolveLimits({ maxEntries: 1 }) })
  const clippedValue = await run('path_inspect', { path: 'C:\\temp\\bad<name>|x.txt' }, clipped)
  assert.equal(clippedValue.meta.truncated, true)
  assert.equal((clippedValue.result as unknown as { issues: unknown[] }).issues.length, 1)
  assert.match(clippedValue.meta.notes.join(' '), /maxEntries=1/)
})

test('path_inspect refuses an over-budget path string rather than truncating it', async () => {
  const small = createTools({ limits: resolveLimits({ maxInputBytes: 32 }) })
  await assert.rejects(
    () => run('path_inspect', { path: `C:\\${'x'.repeat(64)}` }, small),
    /above the configured limit/,
  )
})


