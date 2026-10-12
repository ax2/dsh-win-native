/**
 * Plugin configuration and the per-call budgets derived from it.
 * @module dsh-win-native/limits
 */
import z from '@deepseek-ai/schemastery'

/** Effective budgets for one plugin instance. */
export interface Limits {
  /** Hard ceiling on a structured (text or base64) input payload, in UTF-8 bytes. */
  maxInputBytes: number
  /** Soft ceiling on a rendered result, in UTF-8 bytes. */
  maxOutputBytes: number
  /** Hard ceiling on decoded raw bytes for the encoding tools, in bytes. */
  maxRawBytes: number
  /** Ceiling on listening/established entries reported by a socket parse. */
  maxEntries: number
  /** Ceiling on characters of decoded text echoed by a conversion. */
  maxTextChars: number
  /** Default ceiling on files walked by `dir_usage`, when the call omits one. */
  maxFiles: number
  /** Default ceiling on total accounted bytes for `dir_usage`. */
  maxBytes: number
  /** Default ceiling on bytes hashed by `file_duplicates`. */
  maxBytesHashed: number
  /** Ceiling on unreadable-path records reported by a filesystem tool. */
  maxErrors: number
}

/** Default budgets: large enough for one real directory, small enough to stay bounded. */
export const DEFAULT_LIMITS: Limits = {
  maxInputBytes: 262_144,
  maxOutputBytes: 262_144,
  maxRawBytes: 2_097_152,
  maxEntries: 2_000,
  maxTextChars: 200,
  maxFiles: 20_000,
  maxBytes: 536_870_912,
  maxBytesHashed: 268_435_456,
  maxErrors: 50,
}

/** User-facing configuration. */
export interface Config {
  /** Hard ceiling on a structured input payload, in UTF-8 bytes. */
  maxInputBytes?: number
  /** Soft ceiling on a rendered result, in UTF-8 bytes. */
  maxOutputBytes?: number
  /** Hard ceiling on decoded raw bytes for the encoding tools. */
  maxRawBytes?: number
  /** Ceiling on socket entries reported by `netstat_parse`. */
  maxEntries?: number
  /** Ceiling on characters of decoded text echoed by `encoding_convert`. */
  maxTextChars?: number
  /** Default file budget for `dir_usage` and `file_duplicates`. */
  maxFiles?: number
  /** Default byte-accounting budget for `dir_usage`. */
  maxBytes?: number
  /** Default hashing budget for `file_duplicates`. */
  maxBytesHashed?: number
  /** Ceiling on unreadable-path records. */
  maxErrors?: number
  /** Tool-name prefix, e.g. `win` yields `win__path_inspect`. Empty by default. */
  toolPrefix?: string
  /** Register only these tool names (empty or omitted registers every tool). */
  only?: string[]
}

/** Schemastery schema for {@link Config}. */
export const Config: z<Config> = z.object({
  maxInputBytes: z.natural().default(262_144).description('Hard ceiling on structured input, in UTF-8 bytes.'),
  maxOutputBytes: z.natural().default(262_144).description('Soft ceiling on rendered results, in UTF-8 bytes.'),
  maxRawBytes: z.natural().default(2_097_152).description('Hard ceiling on decoded raw bytes for encoding tools.'),
  maxEntries: z.natural().default(2_000).description('Ceiling on socket entries reported by netstat_parse.'),
  maxTextChars: z.natural().default(200).description('Ceiling on decoded text echoed by encoding_convert.'),
  maxFiles: z.natural().default(20_000).description('Default file budget for dir_usage and file_duplicates.'),
  maxBytes: z.natural().default(536_870_912).description('Default byte-accounting budget for dir_usage.'),
  maxBytesHashed: z.natural().default(268_435_456).description('Default hashing budget for file_duplicates.'),
  maxErrors: z.natural().default(50).description('Ceiling on unreadable-path records reported.'),
  toolPrefix: z.string().default('').description('Optional prefix for registered tool names.'),
  only: z.array(z.string()).default([]).description('Register only these tool names; empty registers every tool.'),
})

/**
 * Merge user configuration over the defaults.
 * @param config - user configuration, possibly empty.
 */
export function resolveLimits(config: Config = {}): Limits {
  const pick = (value: number | undefined, fallback: number): number =>
    typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
  return {
    maxInputBytes: pick(config.maxInputBytes, DEFAULT_LIMITS.maxInputBytes),
    maxOutputBytes: pick(config.maxOutputBytes, DEFAULT_LIMITS.maxOutputBytes),
    maxRawBytes: pick(config.maxRawBytes, DEFAULT_LIMITS.maxRawBytes),
    maxEntries: pick(config.maxEntries, DEFAULT_LIMITS.maxEntries),
    maxTextChars: pick(config.maxTextChars, DEFAULT_LIMITS.maxTextChars),
    maxFiles: pick(config.maxFiles, DEFAULT_LIMITS.maxFiles),
    maxBytes: pick(config.maxBytes, DEFAULT_LIMITS.maxBytes),
    maxBytesHashed: pick(config.maxBytesHashed, DEFAULT_LIMITS.maxBytesHashed),
    maxErrors: pick(config.maxErrors, DEFAULT_LIMITS.maxErrors),
  }
}
