/**
 * UTF-8 byte accounting, hard input bounds, base64 transport helpers, and
 * lossless text clipping.
 *
 * Framework-agnostic on purpose: every rule here is testable without a DSH host
 * and reusable by any surface that embeds these tools.
 * @module dsh-win-native/core/bytes
 */

/** Raised when a payload exceeds the configured input budget. */
export class BoundedInputError extends Error {
  /** Stable, machine-readable failure code. */
  readonly code = 'INPUT_TOO_LARGE'
  /** Measured UTF-8 size of the rejected payload. */
  readonly actualBytes: number
  /** Configured ceiling in UTF-8 bytes. */
  readonly limitBytes: number

  /**
   * @param actualBytes - measured UTF-8 size of the rejected payload.
   * @param limitBytes - configured ceiling in UTF-8 bytes.
   * @param what - short label for the payload, used in the message.
   */
  constructor(actualBytes: number, limitBytes: number, what = 'input') {
    super(
      `${what} is ${actualBytes} UTF-8 bytes, above the configured limit of ${limitBytes} bytes. ` +
        'Split the payload and call the tool again; nothing was truncated or partially processed.',
    )
    this.name = 'BoundedInputError'
    this.actualBytes = actualBytes
    this.limitBytes = limitBytes
  }
}

/** Raised when a requested operation or option value is not supported. */
export class UnsupportedOptionError extends Error {
  /** Stable, machine-readable failure code. */
  readonly code = 'UNSUPPORTED_OPTION'
  /** The option name that carried the bad value. */
  readonly option: string

  /**
   * @param option - the option name that carried the bad value.
   * @param value - the unsupported value.
   * @param allowed - permitted values.
   */
  constructor(option: string, value: unknown, allowed: readonly string[]) {
    super(`Unsupported ${option} ${JSON.stringify(value)}; allowed values: ${allowed.join(', ')}.`)
    this.name = 'UnsupportedOptionError'
    this.option = option
  }
}

/** Raised when a caller passes a relative path to a filesystem tool. */
export class AbsolutePathRequiredError extends Error {
  /** Stable, machine-readable failure code. */
  readonly code = 'ABSOLUTE_PATH_REQUIRED'

  /**
   * @param path - the rejected path.
   */
  constructor(path: string) {
    super(
      `path ${JSON.stringify(path)} is not absolute. These tools never resolve paths against the process working ` +
        'directory, because that makes the result depend on how the host was launched. Pass a fully qualified path ' +
        'such as C:\\work or \\\\server\\share.',
    )
    this.name = 'AbsolutePathRequiredError'
  }
}

/** UTF-8 byte length of a string. */
export function utf8Bytes(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}

/**
 * Enforce that a caller-supplied path is absolute in Windows terms.
 *
 * `path.win32.isAbsolute` is used rather than the host's `isAbsolute` so the
 * refusal is identical on a Windows host, a Linux CI runner and a container:
 * `C:\x` and `\\server\share` are absolute everywhere, `C:x` and `x\y` are not.
 * @param value - candidate path.
 * @returns the path when it is absolute.
 * @throws {AbsolutePathRequiredError} when it is not.
 */
export function assertAbsolutePath(value: string): string {
  if (!isAbsoluteWindows(value)) throw new AbsolutePathRequiredError(value)
  return value
}

/**
 * Whether a path is absolute under Windows rules.
 * @param value - candidate path.
 */
export function isAbsoluteWindows(value: string): boolean {
  return /^[A-Za-z]:[\\/]/u.test(value) || /^[\\/]{2}[^\\/]/u.test(value) || /^\\\\[?.]\\/u.test(value)
}

/** UTF-8 byte length of any canonical JSON value. */
export function jsonBytes(value: unknown): number {
  return utf8Bytes(JSON.stringify(value) ?? '')
}

/**
 * Measure a payload and refuse it when it exceeds the budget.
 * @param text - payload to measure.
 * @param limitBytes - configured ceiling.
 * @param what - label used in the error message.
 * @returns the measured byte length when the payload fits.
 */
export function assertWithinInput(text: string, limitBytes: number, what = 'input'): number {
  const bytes = utf8Bytes(text)
  if (bytes > limitBytes) throw new BoundedInputError(bytes, limitBytes, what)
  return bytes
}

/**
 * Clip a string to a byte budget without splitting a code point.
 * @param text - source string.
 * @param maxBytes - byte ceiling.
 * @returns the clipped text, its byte length, and whether clipping happened.
 */
export function clipToBytes(text: string, maxBytes: number): { text: string; bytes: number; truncated: boolean } {
  const total = utf8Bytes(text)
  if (total <= maxBytes) return { text, bytes: total, truncated: false }
  let out = ''
  let used = 0
  for (const ch of text) {
    const size = utf8Bytes(ch)
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return { text: out, bytes: used, truncated: true }
}

/**
 * Clip an array to a maximum number of entries.
 * @param items - source array.
 * @param maxItems - entry ceiling.
 * @returns the clipped array and whether clipping happened.
 */
export function clipItems<T>(items: readonly T[], maxItems: number): { items: T[]; truncated: boolean } {
  if (items.length <= maxItems) return { items: [...items], truncated: false }
  return { items: items.slice(0, maxItems), truncated: true }
}

/** Stable failure code for a base64 payload that is not decodable. */
export class InvalidBase64Error extends Error {
  /** Stable, machine-readable failure code. */
  readonly code = 'INVALID_BASE64'

  /**
   * @param detail - what exactly was rejected.
   */
  constructor(detail: string) {
    super(`input is not valid base64: ${detail}. Send raw bytes as standard base64 (padding optional); models cannot carry raw bytes reliably.`)
    this.name = 'InvalidBase64Error'
  }
}

/**
 * Decode a base64 payload, accepting standard and URL-safe alphabets with or
 * without padding and ignoring embedded whitespace/newlines.
 *
 * Models routinely emit line-wrapped or URL-safe base64; rejecting those would
 * turn a formatting quirk into a failed task, so the alphabet is normalized
 * before the strict length/padding check runs.
 * @param text - candidate base64 text.
 * @returns decoded bytes.
 * @throws {InvalidBase64Error} when the payload is not decodable base64.
 */
export function decodeBase64(text: string): Buffer {
  const compact = text.replace(/\s+/gu, '')
  if (compact.length === 0) throw new InvalidBase64Error('the payload is empty')
  const normalized = compact.replace(/-/gu, '+').replace(/_/gu, '/')
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(normalized)) {
    throw new InvalidBase64Error('it contains characters outside the base64 alphabet')
  }
  const body = normalized.replace(/=+$/u, '')
  if (body.length % 4 === 1) throw new InvalidBase64Error('its length is not a valid base64 length')
  const padded = body + '='.repeat((4 - (body.length % 4)) % 4)
  const buffer = Buffer.from(padded, 'base64')
  // Node silently drops trailing garbage, so verify the round trip instead of
  // trusting the decoder to have consumed the whole payload.
  if (buffer.toString('base64').replace(/=+$/u, '') !== body) {
    throw new InvalidBase64Error('it does not round-trip through the base64 decoder')
  }
  return buffer
}

/**
 * Encode bytes as canonical padded standard base64.
 * @param bytes - raw bytes.
 */
export function encodeBase64(bytes: Buffer): string {
  return bytes.toString('base64')
}

/**
 * Render a short, deterministic lowercase hex preview of a byte buffer.
 * @param bytes - raw bytes.
 * @param maxBytes - number of leading bytes to include.
 * @returns hex preview plus whether bytes were withheld.
 */
export function hexPreview(bytes: Buffer, maxBytes: number): { hex: string; previewBytes: number; truncated: boolean } {
  const slice = bytes.subarray(0, maxBytes)
  return {
    hex: slice.toString('hex').replace(/(..)(?=.)/gu, '$1 '),
    previewBytes: slice.length,
    truncated: bytes.length > slice.length,
  }
}
