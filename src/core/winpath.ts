/**
 * Pure Windows path legality analysis.
 *
 * This module never touches the filesystem: it answers "what is wrong with this
 * path string on Windows" from the text alone. That is deliberate, because the
 * paths an agent must judge are usually paths it should not open (a user pasted
 * a path that does not exist yet, or a path on a host that is not this one).
 * @module dsh-win-native/core/winpath
 */

/** Stable issue codes reported by {@link inspectPath}. */
export const PATH_ISSUE_CODES = [
  'empty',
  'not_absolute',
  'extended_prefix',
  'unc_path',
  'drive_relative',
  'root_relative',
  'no_root',
  'invalid_drive_letter',
  'illegal_char',
  'control_char',
  'reserved_name',
  'trailing_space_or_dot',
  'segment_trailing_space_or_dot',
  'segment_too_long',
  'path_too_long',
  'above_max_path',
  'empty_segment',
  'dot_segment',
  'not_8_3_safe',
  'extended_prefix_with_relative',
] as const

/** One issue code. */
export type PathIssueCode = (typeof PATH_ISSUE_CODES)[number]

/** One finding about a path. */
export interface PathIssue {
  /** Stable machine-readable code. */
  code: PathIssueCode
  /** `error` blocks the path, `warning` means it works but is fragile. */
  severity: 'error' | 'warning'
  /** Human-readable explanation of this specific occurrence. */
  detail: string
  /** 0-based character offset in the original input, or `null` for whole-path issues. */
  position: number | null
}

/** Result of analysing one Windows path. */
export interface PathInspection {
  /** The input, echoed unchanged so the caller can correlate. */
  input: string
  /** Whether the path names an absolute location. */
  absolute: boolean
  /** Whether the path carries the `\\?\` extended-length prefix. */
  extended: boolean
  /** `drive` (C:\...), `unc` (\\server\share), `rooted` (\foo) or `none`. */
  kind: 'drive' | 'unc' | 'rooted' | 'none'
  /** Drive letter without the colon, when present. */
  drive: string | null
  /** Normalized `\\?\`-style extended form. */
  canonical: string
  /** Character length of the original path, as Windows counts it. */
  length: number
  /** Length of the normalized form. */
  canonical_length: number
  /** Effective MAX_PATH ceiling for this path kind. */
  max_path_limit: number
  /** Whether the path is usable without long-path support. */
  safe_for_max_path: boolean
  /** Whether long-path (`\\?\` or the LongPathsEnabled policy) is required. */
  requires_extended_prefix: boolean
  /** Per-segment 8.3 compatibility. */
  segments: PathSegment[]
  /** All findings, in path order. */
  issues: PathIssue[]
}

/** One path segment. */
export interface PathSegment {
  /** Segment text as written. */
  value: string
  /** Index of the segment, the drive/UNC root counting as 0. */
  index: number
  /** Whether the segment is a legal 8.3 short name. */
  safe_8_3: boolean
  /** Length in characters. */
  length: number
}

/** Characters Windows forbids in a file or directory name. */
export const ILLEGAL_CHARACTERS = ['<', '>', ':', '"', '|', '?', '*'] as const

/** Reserved DOS device names, matched case-insensitively with or without an extension. */
export const RESERVED_NAMES = [
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
] as const

/** The classic MAX_PATH ceiling, which counts the terminating NUL. */
export const MAX_PATH = 260

/** Longest path Windows accepts through the extended-length prefix (32,767 including the NUL). */
export const EXTENDED_MAX_PATH = 32_767

/** Longest single segment (255 characters), the per-component NTFS limit. */
export const MAX_SEGMENT = 255

/** Extended-length prefixes that suppress all path parsing. */
const EXTENDED_PREFIXES = ['\\\\?\\', '\\\\.\\'] as const

/** Characters a legal 8.3 short name may contain. */
const SHORT_NAME = /^[A-Za-z0-9!#$%&'()\-@^_`{}~]{1,8}(\.[A-Za-z0-9!#$%&'()\-@^_`{}~]{1,3})?$/u

/** Device names allowed with a suffix when the name ends in a colon-free digit range. */
const RESERVED_PATTERN = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/iu

/** Whether a character is a C0/C1 control character, which no Windows name may contain. */
function isControl(char: string): boolean {
  const cp = char.codePointAt(0) ?? 0
  return cp < 0x20 || cp === 0x7f
}

/**
 * Split a Windows path into its segments, ignoring repeated separators.
 * @param path - path text.
 * @returns non-empty segments.
 */
export function splitSegments(path: string): string[] {
  return path.split(/[\\/]+/u).filter((segment) => segment.length > 0)
}

/**
 * Whether a name matches a reserved DOS device name, with or without extension.
 * `CON.txt`, `nul.log` and `COM1` are all reserved; `CONSOLE.txt` is not.
 * @param name - one path segment.
 */
export function isReservedName(name: string): boolean {
  const trimmed = name.replace(/[ .]+$/u, '')
  return RESERVED_PATTERN.test(trimmed)
}

/**
 * Whether one segment is a legal 8.3 short name. Long names are not "wrong" on
 * modern Windows, but they break on FAT-formatted removable media and on tools
 * that still generate short names, so this is reported as a warning.
 * @param name - one path segment.
 */
export function isShortNameSafe(name: string): boolean {
  if (name === '.' || name === '..') return true
  return SHORT_NAME.test(name)
}

/**
 * Build the canonical `\\?\`-prefixed form of an absolute path.
 *
 * The prefix is what actually lifts the 260-character limit; normalizing here
 * means a caller can take the result straight to `fs` or to a child process and
 * get the same file, instead of silently hitting MAX_PATH on a deep tree.
 * @param path - an absolute path, possibly already prefixed.
 * @returns the normalized form, or the input when it is not absolute.
 */
export function toExtendedPath(path: string): string {
  const normalized = path.replace(/\//gu, '\\')
  for (const prefix of EXTENDED_PREFIXES) {
    // Already prefixed: normalize the body only, because re-attaching the
    // separators would duplicate the prefix's own backslashes.
    if (normalized.startsWith(prefix)) return prefix + collapse(normalized.slice(prefix.length), 0)
  }
  if (/^[A-Za-z]:\\/u.test(normalized)) return `\\\\?\\${collapse(normalized, 0)}`
  // `\\?\UNC\` already ends in one separator, and the two leading separators of
  // the `\\server\share` root are dropped with the slice, so the body follows
  // with none of its own.
  if (normalized.startsWith('\\\\')) return `\\\\?\\UNC\\${collapse(normalized.slice(2), 0)}`
  return normalized
}

/**
 * Collapse repeated separators and drop a trailing separator.
 *
 * The leading separators a path shape needs are re-attached from the original
 * text rather than rebuilt from the collapsed body, because a UNC path's `\\` and
 * a rooted path's `\` are different shapes with the same body.
 * @param path - path text.
 * @param leading - how many leading separators the shape requires (0, 1 or 2).
 */
function collapse(path: string, leading: 0 | 1 | 2): string {
  for (const prefix of EXTENDED_PREFIXES) {
    if (path.startsWith(prefix)) {
      return prefix + collapse(path.slice(prefix.length), leading)
    }
  }
  const separator = path.startsWith('\\') ? '\\' : path.startsWith('/') ? '/' : '\\'
  const body = path.replace(/[\\/]+/gu, '\\').replace(/\\+$/u, '').replace(/^\\+/u, '')
  if (body === '') return ''
  return `${separator.repeat(leading)}${body}`
}

/**
 * Remove `.` and `..` segments from a path **textually**.
 *
 * This is deliberately not `path.resolve`: resolving against the process working
 * directory would make the answer depend on how the host was started, which is
 * exactly the class of bug this plugin exists to remove. `..` is folded only when
 * the preceding segment is a plain name, so `C:\..\x` and `..\x` keep their
 * meaning instead of being silently reinterpreted.
 * @param path - path text.
 * @returns folded path, plus whether any unprefixed `..` segment survived.
 */
export function foldRelative(path: string): { path: string; unresolved: boolean } {
  const parts = path.replace(/\//gu, '\\').split('\\')
  const out: string[] = []
  let unresolved = false
  for (const part of parts) {
    if (part === '.' || part === '') {
      if (part === '.') continue
      out.push(part)
      continue
    }
    if (part === '..') {
      const last = out[out.length - 1]
      if (last !== undefined && last !== '' && !/^[A-Za-z]:$/u.test(last)) {
        out.pop()
        continue
      }
      unresolved = true
      out.push('..')
      continue
    }
    out.push(part)
  }
  return { path: out.join('\\'), unresolved }
}

/** Escape control characters so a finding message can be printed safely. */
function escapeForMessage(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/gu, (char) => `\\u${(char.codePointAt(0) ?? 0).toString(16).padStart(4, '0')}`)
}

/**
 * Number of characters a path's root occupies, i.e. where its first segment
 * starts. An extended prefix, a UNC pair (`\\server\share`), a drive root
 * (`C:\`) and a rooted path (`\`) each consume a different amount.
 */
function rootOffset(
  forward: string,
  shape: { extended: boolean; unc: boolean; hasRootedDrive: boolean; driveRelative: boolean },
): number {
  if (shape.extended) {
    const prefix = EXTENDED_PREFIXES.find((candidate) => forward.startsWith(candidate)) ?? '\\\\?\\'
    const after = forward.slice(prefix.length)
    // `\\?\UNC\server\share` and `\\?\C:\...` both keep their root outside the
    // segment list, exactly like the unprefixed forms, so the same rules apply
    // to the names that follow.
    if (shape.unc) {
      const names = after.slice(4).split('\\').filter((part) => part.length > 0)
      const rootNames = names.slice(0, 2)
      return prefix.length + 4 + (rootNames.length === 2 ? rootNames[0]!.length + 1 + rootNames[1]!.length : 0)
    }
    if (/^[A-Za-z]:\\/u.test(after)) return prefix.length + 3
    if (shape.driveRelative && /^[A-Za-z]:/u.test(after)) return prefix.length + 2
    return prefix.length
  }
  if (forward.startsWith('\\\\')) {
    // The UNC root is `\\server\share`; both names are part of the root, not
    // segments, because neither can be a file.
    const names = forward.slice(2).split('\\').filter((part) => part.length > 0)
    const rootNames = names.slice(0, 2)
    return rootNames.length === 2 ? 2 + rootNames[0]!.length + 1 + rootNames[1]!.length : 2 + names.join('\\').length
  }
  if (shape.hasRootedDrive) return 3
  // `C:foo` is drive-relative, so the drive designator is the root and `foo` is
  // the first segment.
  if (shape.driveRelative) return 2
  if (forward.startsWith('\\')) return 1
  return 0
}

/**
 * Inspect a Windows path string for every legality rule an agent trips over.
 *
 * The checks, in the order a Windows API applies them: absolute vs relative,
 * extended-length prefix, UNC vs drive vs root-relative, drive-relative `C:foo`,
 * per-segment illegality (reserved names, illegal characters, control
 * characters, trailing space or dot, 255-character length), and finally the
 * whole-path length against both MAX_PATH and the extended limit.
 * @param input - candidate path, as the user wrote it.
 * @returns findings, canonical form, and length verdicts.
 */
export function inspectPath(input: string): PathInspection {
  const issues: PathIssue[] = []
  const path = input
  if (path.length === 0) {
    issues.push({ code: 'empty', severity: 'error', detail: 'the path is empty', position: null })
    return {
      input,
      absolute: false,
      extended: false,
      kind: 'none',
      drive: null,
      canonical: '',
      length: 0,
      canonical_length: 0,
      max_path_limit: MAX_PATH,
      safe_for_max_path: false,
      requires_extended_prefix: false,
      segments: [],
      issues,
    }
  }
  const forward = path.replace(/\//gu, '\\')
  const extended = EXTENDED_PREFIXES.some((prefix) => forward.startsWith(prefix))
  const devicePrefix = forward.startsWith('\\\\.\\')
  if (extended) {
    issues.push({
      code: 'extended_prefix',
      severity: 'warning',
      detail: devicePrefix
        ? 'the \\\\.\\ device prefix bypasses path parsing entirely'
        : 'the \\\\?\\ prefix disables path normalization and refuses relative segments',
      position: 0,
    })
  }
  const unc = !extended ? forward.startsWith('\\\\') : forward.toUpperCase().startsWith('\\\\?\\UNC\\')
  const driveMatch = /^([A-Za-z]):/u.exec(forward)
  let kind: PathInspection['kind'] = 'none'
  let absolute = false
  if (extended) {
    absolute = true
    kind = unc ? 'unc' : 'drive'
  } else if (forward.startsWith('\\\\')) {
    kind = 'unc'
    absolute = splitSegments(forward.slice(2)).length >= 2
    if (!absolute) {
      issues.push({
        code: 'no_root',
        severity: 'error',
        detail: 'a UNC path needs both a server and a share, for example \\\\server\\share',
        position: null,
      })
    }
  } else if (driveMatch !== null && forward[2] === '\\') {
    kind = 'drive'
    absolute = true
  } else if (driveMatch !== null) {
    kind = 'drive'
    issues.push({
      code: 'drive_relative',
      severity: 'error',
      detail: `"${driveMatch[0]}" is drive-relative: it resolves against the current directory of that drive, which differs per process`,
      position: 2,
    })
  } else if (forward.startsWith('\\')) {
    kind = 'rooted'
    issues.push({
      code: 'root_relative',
      severity: 'error',
      detail: 'a path starting with a single separator is rooted on the current drive, not absolute',
      position: 0,
    })
  } else {
    issues.push({
      code: 'not_absolute',
      severity: 'error',
      detail: 'the path is relative; this tool never resolves against the process working directory',
      position: null,
    })
  }
  const drive = driveMatch === null ? null : driveMatch[1]!.toUpperCase()
  if (drive !== null && !/[A-Za-z]/u.test(drive)) {
    issues.push({ code: 'invalid_drive_letter', severity: 'error', detail: `${drive} is not a drive letter`, position: 0 })
  }

  const rootLength = rootOffset(forward, {
    extended,
    unc,
    hasRootedDrive: driveMatch !== null && forward[2] === '\\',
    driveRelative: driveMatch !== null && forward[2] !== '\\',
  })
  const body = forward.slice(rootLength)
  const rawSegments = body.split('\\')
  const segments: PathSegment[] = []
  let offset = rootLength
  for (const [index, raw] of rawSegments.entries()) {
    const position = offset
    offset += raw.length + 1
    if (raw === '') {
      // A separator that follows another separator collapses; the leading
      // separators of a UNC path are part of the root, not empty segments.
      const previous = rawSegments[index - 1]
      if (previous === undefined || previous === '') continue
      if (index < rawSegments.length - 1) {
        issues.push({ code: 'empty_segment', severity: 'warning', detail: 'repeated separator collapses to one', position })
      }
      continue
    }
    if (raw === '.' || raw === '..') {
      issues.push({
        code: 'dot_segment',
        severity: extended && !devicePrefix ? 'error' : 'warning',
        detail:
          extended && !devicePrefix
            ? `"${raw}" is not allowed after \\\\?\\: the prefix disables normalization, so Windows would look for a file literally named "${raw}"`
            : `"${raw}" will be folded by the filesystem`,
        position,
      })
      segments.push({ value: raw, index, safe_8_3: true, length: raw.length })
      continue
    }
    let hardError = false
    const controls = new Set<string>()
    const illegal = new Set<string>()
    for (const char of raw) {
      if (isControl(char)) controls.add(char)
      if ((ILLEGAL_CHARACTERS as readonly string[]).includes(char)) illegal.add(char)
    }
    for (const char of controls) {
      hardError = true
      issues.push({
        code: 'control_char',
        severity: 'error',
        detail: `segment "${escapeForMessage(raw)}" contains the control character U+${(char.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
        position,
      })
    }
    for (const char of illegal) {
      hardError = true
      issues.push({
        code: 'illegal_char',
        severity: 'error',
        detail: `segment "${raw}" contains "${char}", which Windows forbids in a file or directory name`,
        position,
      })
    }
    const trailingMatch = /[ .]+$/u.exec(raw)
    if (trailingMatch !== null) {
      hardError = true
      issues.push({
        code: 'segment_trailing_space_or_dot',
        severity: 'error',
        detail: `segment "${raw}" ends with ${JSON.stringify(trailingMatch[0])}; Win32 strips it, so this names a different file than it looks like`,
        position,
      })
    }
    if (isReservedName(raw)) {
      hardError = true
      issues.push({
        code: 'reserved_name',
        severity: 'error',
        detail: `segment "${raw}" is a reserved DOS device name, even with an extension or a path prefix`,
        position,
      })
    }
    if (raw.length > MAX_SEGMENT) {
      hardError = true
      issues.push({
        code: 'segment_too_long',
        severity: 'error',
        detail: `segment is ${raw.length} characters, above the ${MAX_SEGMENT}-character limit`,
        position,
      })
    }
    if (!hardError && !isShortNameSafe(raw)) {
      issues.push({
        code: 'not_8_3_safe',
        severity: 'warning',
        detail: `segment "${raw}" is not a legal 8.3 short name, so FAT media and legacy tooling may rename or reject it`,
        position,
      })
    }
    segments.push({ value: raw, index, safe_8_3: isShortNameSafe(raw) && !hardError, length: raw.length })
  }
  if (extended && segments.some((segment) => segment.value === '.' || segment.value === '..')) {
    issues.push({
      code: 'extended_prefix_with_relative',
      severity: 'error',
      detail: 'an extended-length path cannot contain "." or ".." segments',
      position: null,
    })
  }
  if (/[ .]$/u.test(forward) && !segments.some((segment) => /[ .]$/u.test(segment.value))) {
    issues.push({
      code: 'trailing_space_or_dot',
      severity: 'error',
      detail: 'the path ends with a space or dot',
      position: forward.length - 1,
    })
  }

  // MAX_PATH counts the terminating NUL, so the usable text length is 259. A
  // path at or above that needs `\\?\` or the machine-wide LongPathsEnabled
  // policy; anything at or above the extended ceiling cannot be represented at
  // all by the Win32 path APIs.
  const limit = MAX_PATH
  const requiresExtended = forward.length >= limit && !extended
  if (requiresExtended) {
    issues.push({
      code: 'above_max_path',
      severity: 'warning',
      detail: `the path is ${forward.length} characters; without \\\\?\\ or the LongPathsEnabled policy, Win32 APIs fail at ${limit - 1} characters`,
      position: null,
    })
  }
  if (forward.length >= EXTENDED_MAX_PATH) {
    issues.push({
      code: 'path_too_long',
      severity: 'error',
      detail: `the path is ${forward.length} characters, at or above the ${EXTENDED_MAX_PATH}-character extended limit that even \\\\?\\ cannot exceed`,
      position: null,
    })
  }
  // The canonical form keeps the separators the shape requires: none for a
  // relative path, one for a rooted path, two for a UNC path.
  const leading: 0 | 1 | 2 = forward.startsWith('\\\\') ? 2 : forward.startsWith('\\') ? 1 : 0
  const canonical = extended ? collapse(forward, leading) : collapse(foldRelative(forward).path, leading)
  const canonicalLength = canonical.length
  const hasError = issues.some((issue) => issue.severity === 'error')
  const safeForMaxPath = !hasError && !requiresExtended && forward.length < MAX_PATH
  return {
    input,
    absolute,
    extended,
    kind,
    drive,
    canonical,
    length: forward.length,
    canonical_length: canonicalLength,
    max_path_limit: limit,
    safe_for_max_path: safeForMaxPath,
    requires_extended_prefix: requiresExtended,
    segments,
    issues,
  }
}
