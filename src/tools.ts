/**
 * DSH tool definitions. Each tool is a thin, declarative binding: a parameter
 * schema for the model, a bounded body, and the shared receipt renderer.
 *
 * Two families live here. `encoding_detect`, `encoding_convert`, `path_inspect`
 * and `netstat_parse` are pure functions over text. `dir_usage` and
 * `file_duplicates` read the local filesystem and nothing else: they never
 * write, never follow reparse points, never resolve relative paths against the
 * process working directory, and report every budget and every unreadable path.
 * @module dsh-win-native/tools
 */
import {
  defineTool,
  parameterSchemaSpecToJsonSchema,
  type ParameterSchemaSpec,
  type ToolDefinition,
  type ValueSchemaSpec,
} from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { renderEnvelope, type Envelope } from './core/receipt.ts'
import {
  assertAbsolutePath,
  assertWithinInput,
  clipItems,
  clipToBytes,
  decodeBase64,
  encodeBase64,
  hexPreview,
  jsonBytes,
  utf8Bytes,
  UnsupportedOptionError,
} from './core/bytes.ts'
import {
  BOM_POLICIES,
  SOURCE_ENCODINGS,
  TARGET_ENCODINGS,
  convertEncoding,
  detectEncoding,
  isBomPolicy,
  isSourceEncoding,
  isTargetEncoding,
  type BomPolicy,
  type SourceEncoding,
  type TargetEncoding,
} from './core/encoding.ts'
import { inspectPath } from './core/winpath.ts'
import { parseNetstat } from './core/netstat.ts'
import { walkDirectory } from './core/dirwalk.ts'
import { findDuplicates } from './core/duplicates.ts'
import type { Limits } from './limits.ts'

/** Tool groups, used by the `only` config filter and documentation. */
export type ToolGroup = 'encoding' | 'path' | 'network' | 'filesystem'

/** Shared meta schema for the receipt envelope. */
const META_SPEC = {
  type: 'object',
  additionalProperties: false,
  properties: {
    bytesIn: { type: 'integer', required: true, description: 'UTF-8 bytes read from the primary input.' },
    bytesOut: { type: 'integer', required: true, description: 'UTF-8 bytes of the canonical result.' },
    truncated: { type: 'boolean', required: true, description: 'True when a configured budget clipped input or output.' },
    notes: { type: 'array', items: { type: 'string' }, required: true, description: 'Ordered notes: budgets, fallbacks, skipped entries.' },
  },
} as const

/** Result schema slot for a body that does not declare one. */
const RESULT_SPEC = { type: 'json' } as const

/** One tool body: model-facing schema plus a bounded implementation. */
export interface ToolBody {
  /** Tool name as the model sees it. */
  name: string
  /** Model-facing description; states the bounds and what the tool refuses. */
  description: string
  /** Parameter schema. */
  parameters: ParameterSchemaSpec
  /** Canonical result schema for the `result` field. */
  result: ValueSchemaSpec
  /** Group used by the `only` filter. */
  group: ToolGroup
  /** Implementation receiving validated arguments and the effective budgets. */
  run(args: Record<string, unknown>, limits: Limits, exec: { signal: AbortSignal }): Envelope<JsonValue> | Promise<Envelope<JsonValue>>
}

/** Options shared by every tool built for one plugin instance. */
export interface ToolFactoryOptions {
  /** Effective budgets. */
  limits: Limits
  /** Optional tool-name prefix, joined with `__`. */
  prefix?: string
  /** Register only these base tool names; empty registers every tool. */
  only?: readonly string[]
}

/**
 * Build a registry-ready definition with the shared receipt renderer.
 *
 * The registry validates the canonical value against the declared per-tool
 * `result` schema; only the author-facing generic is erased, because
 * `InferValue` collapses over a broad `ValueSchemaSpec` union. The pairing is
 * asserted by the tool tests instead.
 * @param body - tool body.
 * @param opts - budgets, name prefix, and allowlist for this plugin instance.
 */
export function defineReceiptTool(body: ToolBody, opts: ToolFactoryOptions) {
  const { limits, prefix = '' } = opts
  if (opts.only !== undefined && opts.only.length > 0 && !opts.only.includes(body.name)) return undefined
  const outputSchema = {
    type: 'object',
    additionalProperties: false,
    properties: { result: body.result ?? RESULT_SPEC, meta: META_SPEC },
  } as const
  const options = {
    name: prefix.length > 0 ? `${prefix}__${body.name}` : body.name,
    description: body.description,
    parameters: body.parameters,
    output: {
      schema: outputSchema,
      render: (_args: unknown, value: Envelope<unknown>) => renderEnvelope(value),
    },
    // `defineTool`'s const generics recurse through `InferObject` over the broad
    // `ParameterSchemaSpec` union; the schema is still compiled and checked
    // below, so only the erased generic is dropped here.
    async execute(args: unknown, exec: { signal: AbortSignal }) {
      exec.signal.throwIfAborted()
      return guardOutputSize(await body.run(args as Record<string, unknown>, limits, exec), limits)
    },
  }
  const compile = defineTool as unknown as (input: unknown) => ToolDefinition
  return compile(options)
}

/**
 * Flag a canonical payload larger than the configured output budget.
 *
 * Text payloads are clipped inside their own tool; a structured or encoded
 * payload cannot be partially clipped without becoming a different value, so it
 * is returned whole and marked instead of being silently mangled.
 * @param value - envelope produced by a tool body.
 * @param limits - effective budgets.
 */
function guardOutputSize(value: Envelope<unknown>, limits: Limits): Envelope<unknown> {
  const size = utf8Bytes(JSON.stringify(value.result ?? null) ?? '')
  if (size <= limits.maxOutputBytes) return value
  return {
    result: value.result,
    meta: {
      ...value.meta,
      truncated: true,
      notes: [
        ...value.meta.notes,
        `result payload is ${size} bytes, above maxOutputBytes=${limits.maxOutputBytes}; it was returned whole because a canonical value cannot be partially clipped`,
      ],
    },
  }
}

/** Compile a parameter schema to JSON Schema, proving the DSL node is valid. */
export function compileParameters(spec: ParameterSchemaSpec) {
  return parameterSchemaSpecToJsonSchema(spec)
}

/** Clip a rendered text result and record the truncation in the notes. */
function boundedText(text: string, limits: Limits, notes: string[] = []): { text: string; truncated: boolean } {
  const clipped = clipToBytes(text, limits.maxOutputBytes)
  if (!clipped.truncated) return { text, truncated: false }
  notes.push(
    `output clipped to ${limits.maxOutputBytes} bytes (of ${utf8Bytes(text)} bytes); raise maxOutputBytes or narrow the request`,
  )
  return { text: clipped.text, truncated: true }
}

/** Read an integer argument, clamped into a range. */
function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.max(min, Math.min(max, Math.floor(value)))
}

/** Read a string argument with a default. */
function stringArg(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback
}

/** One alternative encoding, as the model sees it. */
const ALTERNATIVE_SPEC = {
  type: 'object',
  additionalProperties: false,
  properties: {
    encoding: { type: 'string', required: true },
    score: { type: 'number', required: true },
    replacements: { type: 'integer', required: true, description: 'Characters the decoder could not map (U+FFFD).' },
    suspicious: { type: 'integer', required: true, description: 'Decoded characters that a real document in this code page would not contain.' },
    round_trip: { type: 'boolean', required: true, description: 'Whether re-encoding reproduces the original bytes.' },
    sample: { type: 'string', required: true, description: 'Decoded prefix, so a human can judge the guess.' },
  },
} as const

/** Issue shape shared by the path tool. */
const ISSUE_SPEC = {
  type: 'object',
  additionalProperties: false,
  properties: {
    code: { type: 'string', required: true },
    severity: { type: 'string', required: true, enum: ['error', 'warning'] },
    detail: { type: 'string', required: true },
    position: { oneOf: [{ type: 'integer' }, { type: 'null' }] },
  },
} as const

/**
 * Every tool this package registers, in registration order.
 * @param opts - budgets, name prefix, and optional allowlist.
 */
export function createTools(opts: ToolFactoryOptions) {
  const tools = [
    // ------------------------------------------------------------ encoding ---
    defineReceiptTool(
      {
        name: 'encoding_detect',
        group: 'encoding',
        description:
          'Detect the character encoding of raw bytes supplied as base64: checks the BOM first (UTF-8/UTF-16LE/BE/UTF-32), then validates strict UTF-8, then scores GB18030, Big5, Shift-JIS and Latin-1 by decoding each and counting replacement and implausible characters. Returns the best candidate with a confidence of high/medium/low plus every alternative that scored close. This is detection over bytes only; it never reads a file. Short payloads are genuinely ambiguous and are reported as low confidence with alternatives rather than guessed.',
        parameters: {
          base64: { type: 'string', required: true, description: 'Raw bytes as base64 (standard or URL-safe, padding optional, whitespace ignored).' },
          sample_chars: { type: 'integer', description: 'Decoded characters echoed per candidate (default 60, max 500).' },
        },
        result: {
          type: 'object',
          additionalProperties: false,
          properties: {
            encoding: { type: 'string', required: true, description: 'Best candidate encoding name.' },
            confidence: { type: 'string', required: true, enum: ['high', 'medium', 'low'] },
            bom: { type: 'string', required: true, description: 'Detected byte-order mark name, or `none`.' },
            byte_length: { type: 'integer', required: true },
            alternatives: { type: 'array', items: ALTERNATIVE_SPEC, required: true, description: 'Every candidate, best first.' },
            signals: { type: 'array', items: { type: 'string' }, required: true, description: 'Machine-readable evidence codes behind the decision.' },
          },
        },
        run: (args, limits) => {
          const raw = String(args.base64)
          const bytesIn = assertWithinInput(raw, limits.maxInputBytes, 'base64 input')
          const bytes = decodeBase64(raw)
          if (bytes.length > limits.maxRawBytes) {
            throw new Error(
              `decoded payload is ${bytes.length} bytes, above maxRawBytes=${limits.maxRawBytes}. ` +
                'Detection needs the whole payload to score code pages; send a smaller sample or raise maxRawBytes.',
            )
          }
          const sampleChars = clampInt(args.sample_chars, 60, 0, 500)
          const detection = detectEncoding(bytes, { sampleChars })
          const notes: string[] = []
          if (detection.confidence === 'low') {
            notes.push(
              'confidence is low: at least two code pages explain these bytes equally well. ' +
                'Pass an explicit `from` to encoding_convert, or confirm with a larger sample, before trusting the text.',
            )
          }
          if (detection.bom === 'utf-32le' || detection.bom === 'utf-32be') {
            notes.push('UTF-32 is detected but encoding_convert does not target it; convert to UTF-8 or UTF-16 instead')
          }
          const result = {
            encoding: detection.encoding,
            confidence: detection.confidence,
            bom: detection.bom,
            byte_length: detection.byte_length,
            // `ranked` is an internal ordering key (score plus the documented
            // code-page prior); it is deliberately not published, so the score a
            // caller sees is exactly the evidence, not the tie-break.
            alternatives: detection.alternatives.map((candidate) => ({
              encoding: candidate.encoding,
              sample: candidate.sample,
              score: candidate.score,
              replacements: candidate.replacements,
              suspicious: candidate.suspicious,
              implausible_scripts: candidate.implausible_scripts,
              round_trip: candidate.round_trip,
            })) as unknown as JsonValue,
            signals: detection.signals as unknown as JsonValue,
          }
          return { result, meta: { bytesIn, bytesOut: jsonBytes(result), truncated: false, notes } }
        },
      },
      opts,
    ),
    defineReceiptTool(
      {
        name: 'encoding_convert',
        group: 'encoding',
        description:
          'Convert raw bytes (supplied as base64) between Windows code pages: utf-8, utf-16le, utf-16be, gbk, gb18030, big5, shift_jis, latin1 and ascii, with `auto` to detect the source. Returns base64 of the converted bytes, in/out byte counts, a hex preview, and the exact number of characters the target could not represent. Lossy conversions are reported, never hidden: the note names the characters that became a substitute. Does not read or write files.',
        parameters: {
          base64: { type: 'string', required: true, description: 'Source bytes as base64.' },
          from: { type: 'string', enum: SOURCE_ENCODINGS, description: 'Source encoding, or `auto` (default) to detect it first.' },
          to: { type: 'string', required: true, enum: TARGET_ENCODINGS, description: 'Target encoding.' },
          bom: { type: 'string', enum: BOM_POLICIES, description: 'Byte-order-mark policy for the output: `keep` (default), `add`, or `strip`.' },
          text_chars: { type: 'integer', description: 'Characters of decoded source text to echo (default 200, max 2000).' },
          preview_bytes: { type: 'integer', description: 'Bytes included in the hex preview (default 32, max 256).' },
        },
        result: {
          type: 'object',
          additionalProperties: false,
          properties: {
            base64: { type: 'string', required: true, description: 'Converted bytes, base64 encoded.' },
            source_encoding: { type: 'string', required: true },
            target_encoding: { type: 'string', required: true },
            source_bom: { type: 'string', required: true },
            output_bom: { type: 'string', required: true },
            bytes_in: { type: 'integer', required: true },
            bytes_out: { type: 'integer', required: true },
            lossy_characters: { type: 'integer', required: true, description: 'Characters with no representation in the target encoding.' },
            lossy_list: {
              type: 'array',
              required: true,
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  code_point: { type: 'string', required: true },
                  char: { type: 'string', required: true },
                  count: { type: 'integer', required: true },
                },
              },
            },
            hex_preview: { type: 'string', required: true },
            text: { type: 'string', required: true },
            changed: { type: 'boolean', required: true },
            signals: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
        run: (args, limits) => {
          const raw = String(args.base64)
          const bytesIn = assertWithinInput(raw, limits.maxInputBytes, 'base64 input')
          const bytes = decodeBase64(raw)
          if (bytes.length > limits.maxRawBytes) {
            throw new Error(`decoded payload is ${bytes.length} bytes, above maxRawBytes=${limits.maxRawBytes}`)
          }
          const from = stringArg(args.from, 'auto')
          const to = stringArg(args.to, '')
          const bomPolicy = stringArg(args.bom, 'keep')
          if (!isSourceEncoding(from)) throw new UnsupportedOptionError('from', from, SOURCE_ENCODINGS)
          if (!isTargetEncoding(to)) throw new UnsupportedOptionError('to', to, TARGET_ENCODINGS)
          if (!isBomPolicy(bomPolicy)) throw new UnsupportedOptionError('bom', bomPolicy, BOM_POLICIES)
          const textChars = clampInt(args.text_chars, limits.maxTextChars, 0, 2_000)
          const previewBytes = clampInt(args.preview_bytes, 32, 0, 256)
          const converted = convertEncoding(bytes as Buffer, from as SourceEncoding, to as TargetEncoding, bomPolicy as BomPolicy, {
            textChars,
          })
          const notes: string[] = []
          if (converted.result.lossy_characters > 0) {
            const names = converted.result.lossy_list
              .slice(0, 8)
              .map((entry) => `${JSON.stringify(entry.char)} (${entry.code_point})`)
              .join(', ')
            notes.push(
              `LOSSY: ${converted.result.lossy_characters} character(s) have no representation in ${to} and were replaced; ` +
                `first offenders: ${names}. The output is not a faithful round trip.`,
            )
          }
          if (converted.detection !== undefined && converted.detection.confidence === 'low') {
            notes.push(
              `source encoding was auto-detected as ${converted.result.source_encoding} with low confidence; ` +
                'pass `from` explicitly if that is wrong',
            )
          }
          const preview = hexPreview(converted.output, previewBytes)
          if (preview.truncated) {
            // A clipped preview is a display bound, not a partial conversion: the
            // base64 field still carries every converted byte, so say so instead
            // of claiming the result was truncated.
            notes.push(
              `hex preview shows the first ${preview.previewBytes} of ${converted.output.length} bytes; the base64 field is complete`,
            )
          }
          const textClipped = converted.result.text.length < converted.result.fullTextLength
          if (textClipped) {
            notes.push(`decoded text clipped to ${textChars} characters; raise text_chars for more`)
          }
          const result = {
            base64: encodeBase64(converted.output),
            source_encoding: converted.result.source_encoding,
            target_encoding: converted.result.target_encoding,
            source_bom: converted.result.source_bom,
            output_bom: converted.result.output_bom,
            bytes_in: bytes.length,
            bytes_out: converted.output.length,
            lossy_characters: converted.result.lossy_characters,
            lossy_list: converted.result.lossy_list as unknown as JsonValue,
            hex_preview: preview.hex,
            text: converted.result.text,
            changed: converted.result.changed,
            signals: converted.result.signals as unknown as JsonValue,
          }
          return { result, meta: { bytesIn, bytesOut: jsonBytes(result), truncated: textClipped, notes } }
        },
      },
      opts,
    ),

    // ---------------------------------------------------------------- path ---
    defineReceiptTool(
      {
        name: 'path_inspect',
        group: 'path',
        description:
          'Analyse a Windows path string and report everything that will break: extended-length prefix (\\\\?\\), UNC vs drive vs root-relative vs drive-relative (C:foo), reserved device names anywhere in a segment (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without extension), illegal characters, control characters, trailing space or dot, 8.3 safety, per-segment length, and total length against the 260-character MAX_PATH limit. Returns each finding with a code and severity plus a canonical \\\\?\\ form. Pure string analysis: it does not touch the filesystem, so it is safe on paths that do not exist.',
        parameters: {
          path: { type: 'string', required: true, description: 'Path text to analyse, exactly as written.' },
        },
        result: {
          type: 'object',
          additionalProperties: false,
          properties: {
            input: { type: 'string', required: true },
            absolute: { type: 'boolean', required: true },
            extended: { type: 'boolean', required: true, description: 'Whether the path carries a \\\\?\\ or \\\\.\\ prefix.' },
            kind: { type: 'string', required: true, enum: ['drive', 'unc', 'rooted', 'none'] },
            drive: { oneOf: [{ type: 'string' }, { type: 'null' }] },
            canonical: { type: 'string', required: true, description: 'Normalized form with repeated separators collapsed and . / .. folded textually.' },
            length: { type: 'integer', required: true },
            canonical_length: { type: 'integer', required: true },
            max_path_limit: { type: 'integer', required: true },
            safe_for_max_path: { type: 'boolean', required: true },
            requires_extended_prefix: { type: 'boolean', required: true },
            segments: {
              type: 'array',
              required: true,
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  value: { type: 'string', required: true },
                  index: { type: 'integer', required: true },
                  safe_8_3: { type: 'boolean', required: true },
                  length: { type: 'integer', required: true },
                },
              },
            },
            issues: { type: 'array', items: ISSUE_SPEC, required: true },
          },
        },
        run: (args, limits) => {
          const path = String(args.path)
          const bytesIn = assertWithinInput(path, limits.maxInputBytes, 'path')
          const inspection = inspectPath(path)
          const notes: string[] = []
          const clipped = clipItems(inspection.issues, limits.maxEntries)
          if (clipped.truncated) notes.push(`issue list clipped to maxEntries=${limits.maxEntries}`)
          if (!inspection.absolute) notes.push('the path is not absolute; it would be resolved against the caller working directory')
          if (inspection.requires_extended_prefix) {
            notes.push('use the canonical form (or the LongPathsEnabled policy) or Win32 APIs will fail on this path')
          }
          const result = {
            input: inspection.input,
            absolute: inspection.absolute,
            extended: inspection.extended,
            kind: inspection.kind,
            drive: inspection.drive,
            canonical: inspection.canonical,
            length: inspection.length,
            canonical_length: inspection.canonical_length,
            max_path_limit: inspection.max_path_limit,
            safe_for_max_path: inspection.safe_for_max_path,
            requires_extended_prefix: inspection.requires_extended_prefix,
            segments: inspection.segments as unknown as JsonValue,
            issues: clipped.items as unknown as JsonValue,
          }
          return { result, meta: { bytesIn, bytesOut: jsonBytes(result), truncated: clipped.truncated, notes } }
        },
      },
      opts,
    ),

    // ------------------------------------------------------------- network ---
    defineReceiptTool(
      {
        name: 'netstat_parse',
        group: 'network',
        description:
          'Parse pasted `netstat -ano` / `netstat -anob` output, or PowerShell `Get-NetTCPConnection` table output, and report the dialect detected. Returns listening endpoints with owning PID and process name when the text carries one, established connections grouped by remote endpoint, duplicate binds (the same port on 0.0.0.0 and on a specific address), and counts by state and protocol. Rows the text does not describe are not invented: whether a listening PID still exists, and UDP connection state, cannot be known from this text and are reported as limitations.',
        parameters: {
          text: { type: 'string', required: true, description: 'Raw `netstat -ano`/`-anob` or `Get-NetTCPConnection` text, pasted as-is.' },
          include_rows: { type: 'boolean', description: 'Include every parsed row in the result (default false).' },
        },
        result: {
          type: 'object',
          additionalProperties: false,
          properties: {
            dialect: { type: 'string', required: true, enum: ['netstat', 'powershell', 'unknown'] },
            summary: { type: 'json' },
            state_counts: { type: 'json' },
            protocol_counts: { type: 'json' },
            listening: { type: 'json' },
            established: { type: 'json' },
            duplicate_binds: { type: 'json' },
            rows: { type: 'json' },
            limitations: { type: 'array', items: { type: 'string' }, required: true },
            notes: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
        run: (args, limits) => {
          const text = String(args.text)
          const bytesIn = assertWithinInput(text, limits.maxInputBytes, 'netstat text')
          const report = parseNetstat(text)
          const notes = [...report.notes]
          if (report.dialect === 'unknown') {
            notes.push('no netstat or Get-NetTCPConnection header was recognized; rows were matched by shape only')
          }
          const listening = clipItems(report.listening, limits.maxEntries)
          const established = clipItems(report.established, limits.maxEntries)
          const duplicates = clipItems(report.duplicate_binds, limits.maxEntries)
          const rows = clipItems(report.rows, limits.maxEntries)
          if (listening.truncated || established.truncated || duplicates.truncated || rows.truncated) {
            notes.push(`entry lists clipped to maxEntries=${limits.maxEntries}; counts in summary are complete, the lists are not`)
          }
          const result = {
            dialect: report.dialect,
            summary: report.summary as unknown as JsonValue,
            state_counts: report.state_counts as unknown as JsonValue,
            protocol_counts: report.protocol_counts as unknown as JsonValue,
            listening: listening.items as unknown as JsonValue,
            established: established.items as unknown as JsonValue,
            duplicate_binds: duplicates.items as unknown as JsonValue,
            rows: (args.include_rows === true ? rows.items : []) as unknown as JsonValue,
            limitations: report.limitations as unknown as JsonValue,
            notes: notes as unknown as JsonValue,
          }
          return {
            result,
            meta: {
              bytesIn,
              bytesOut: jsonBytes(result),
              truncated: listening.truncated || established.truncated || duplicates.truncated || rows.truncated,
              notes,
            },
          }
        },
      },
      opts,
    ),

    // ---------------------------------------------------------- filesystem ---
    defineReceiptTool(
      {
        name: 'dir_usage',
        group: 'filesystem',
        description:
          'READ-ONLY summary of a directory: total bytes, file and directory counts, the largest files, and an extension histogram. READS THE LOCAL FILESYSTEM and never writes, moves or deletes anything. Reparse points, junctions and symbolic links are skipped and reported in `skipped_links`, never followed. Bounded by max_files (20000), max_depth (8) and max_bytes (512 MiB accounted); hitting any budget sets `truncated` and explains it. The path must be absolute; relative paths are refused because they would depend on how the host was started.',
        parameters: {
          path: { type: 'string', required: true, description: 'Absolute directory to summarize, for example C:\\Users\\ax2\\AppData.' },
          max_files: { type: 'integer', description: 'File budget (default 20000).' },
          max_depth: { type: 'integer', description: 'Directory depth budget (default 8).' },
          max_bytes: { type: 'integer', description: 'Byte-accounting budget (default 536870912).' },
          top_n: { type: 'integer', description: 'Largest files to return (default 20, max 200).' },
        },
        result: {
          type: 'object',
          additionalProperties: false,
          properties: {
            root: { type: 'string', required: true },
            total_bytes: { type: 'integer', required: true },
            files: { type: 'integer', required: true },
            directories: { type: 'integer', required: true },
            largest: {
              type: 'array',
              required: true,
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  path: { type: 'string', required: true },
                  size: { type: 'integer', required: true },
                  depth: { type: 'integer', required: true },
                },
              },
            },
            extensions: { type: 'json' },
            skipped_links: { type: 'json' },
            unreadable: { type: 'json' },
            truncated: { type: 'boolean', required: true },
            notes: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
        run: async (args, limits, exec) => {
          const root = assertAbsolutePath(String(args.path))
          const bytesIn = utf8Bytes(root)
          const maxFiles = clampInt(args.max_files, limits.maxFiles, 1, 5_000_000)
          const maxDepth = clampInt(args.max_depth, 8, 0, 128)
          const maxBytes = clampInt(args.max_bytes, limits.maxBytes, 1, Number.MAX_SAFE_INTEGER)
          const topN = clampInt(args.top_n, 20, 1, 200)
          const walk = await walkDirectory(root, {
            maxFiles,
            maxDepth,
            maxBytes,
            topN,
            maxErrors: limits.maxErrors,
            signal: exec.signal,
          })
          const notes = [...walk.notes]
          if (walk.skipped_links.length > 0) {
            const sample = walk.skipped_links.slice(0, 3).map((link) => link.path)
            notes.push(`skipped reparse points (not followed): ${sample.join(', ')}${walk.skipped_links.length > 3 ? ', ...' : ''}`)
          }
          if (walk.unreadable.length > 0) {
            const sample = walk.unreadable.slice(0, 3).map((entry) => `${entry.path} (${entry.code})`)
            notes.push(`unreadable paths: ${sample.join(', ')}${walk.unreadable.length > 3 ? ', ...' : ''}`)
          }
          const result = {
            root: walk.root,
            total_bytes: walk.total_bytes,
            files: walk.files,
            directories: walk.directories,
            largest: walk.largest as unknown as JsonValue,
            extensions: walk.extensions as unknown as JsonValue,
            skipped_links: walk.skipped_links as unknown as JsonValue,
            unreadable: walk.unreadable as unknown as JsonValue,
            truncated: walk.truncated,
            notes,
          }
          return { result, meta: { bytesIn, bytesOut: jsonBytes(result), truncated: walk.truncated, notes } }
        },
      },
      opts,
    ),
    defineReceiptTool(
      {
        name: 'file_duplicates',
        group: 'filesystem',
        description:
          'READ-ONLY duplicate finder: groups files by size, then hashes only same-size candidates with streaming SHA-256. READS THE LOCAL FILESYSTEM and never writes, moves or deletes anything, not even to reclaim the duplicates it finds. Bounded by max_bytes_hashed (256 MiB) and max_files (20000); when the hashing budget runs out the remaining candidates are reported as un-not-hashed rather than assumed unique. Paths that could not be listed, stat\'ed or read are returned in `unreadable` with their error code. The path must be absolute.',
        parameters: {
          path: { type: 'string', required: true, description: 'Absolute directory to scan.' },
          max_files: { type: 'integer', description: 'File budget for the walk (default 20000).' },
          max_depth: { type: 'integer', description: 'Directory depth budget (default 8).' },
          max_bytes_hashed: { type: 'integer', description: 'Total bytes allowed through SHA-256 (default 268435456).' },
          max_groups: { type: 'integer', description: 'Duplicate groups to return (default 200, max 5000).' },
        },
        result: {
          type: 'object',
          additionalProperties: false,
          properties: {
            root: { type: 'string', required: true },
            groups: {
              type: 'array',
              required: true,
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  hash: { type: 'string', required: true },
                  size: { type: 'integer', required: true },
                  count: { type: 'integer', required: true },
                  reclaimable: { type: 'integer', required: true },
                  paths: { type: 'array', items: { type: 'string' }, required: true },
                },
              },
            },
            groups_total: { type: 'integer', required: true },
            reclaimable_bytes: { type: 'integer', required: true },
            files_seen: { type: 'integer', required: true },
            candidates_hashed: { type: 'integer', required: true },
            files_hashed: { type: 'integer', required: true },
            bytes_hashed: { type: 'integer', required: true },
            unreadable: { type: 'json' },
            truncated: { type: 'boolean', required: true },
            notes: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
        run: async (args, limits, exec) => {
          const root = assertAbsolutePath(String(args.path))
          const bytesIn = utf8Bytes(root)
          const maxFiles = clampInt(args.max_files, limits.maxFiles, 1, 5_000_000)
          const maxDepth = clampInt(args.max_depth, 8, 0, 128)
          const maxBytesHashed = clampInt(args.max_bytes_hashed, limits.maxBytesHashed, 1, Number.MAX_SAFE_INTEGER)
          const maxGroups = clampInt(args.max_groups, 200, 1, 5_000)
          const report = await findDuplicates(root, {
            maxFiles,
            maxDepth,
            maxBytesHashed,
            signal: exec.signal,
            maxErrors: limits.maxErrors,
          })
          const notes = [...report.notes]
          const groups = clipItems(report.groups, maxGroups)
          if (groups.truncated) notes.push(`duplicate groups clipped to max_groups=${maxGroups}; reclaimable_bytes totals every group found`)
          if (report.unreadable.length > 0) {
            const sample = report.unreadable.slice(0, 3).map((entry) => `${entry.path} (${entry.stage}/${entry.code})`)
            notes.push(`unreadable paths: ${sample.join(', ')}${report.unreadable.length > 3 ? ', ...' : ''}`)
          }
          const result = {
            root: report.root,
            groups: groups.items as unknown as JsonValue,
            groups_total: report.groups.length,
            reclaimable_bytes: report.reclaimable_bytes,
            files_seen: report.files_seen,
            candidates_hashed: report.candidates_hashed,
            files_hashed: report.files_hashed,
            bytes_hashed: report.bytes_hashed,
            unreadable: report.unreadable as unknown as JsonValue,
            truncated: report.truncated,
            notes,
          }
          return {
            result,
            meta: { bytesIn, bytesOut: jsonBytes(result), truncated: report.truncated || groups.truncated, notes },
          }
        },
      },
      opts,
    ),
  ]
  return tools.filter((tool): tool is NonNullable<typeof tool> => tool !== undefined)
}
