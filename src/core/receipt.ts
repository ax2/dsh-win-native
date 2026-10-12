/**
 * The uniform receipt envelope every tool in this package returns.
 *
 * One shape for all tools keeps PTC (`await tools.path_inspect({...})`) and
 * programmatic consumers honest: the payload is a field, never prose, and the
 * accounting numbers always describe the bytes that actually crossed the tool
 * boundary.
 * @module dsh-win-native/core/receipt
 */
import { jsonBytes, utf8Bytes } from './bytes.ts'

/** Token-neutral accounting attached to every successful result. */
export interface ToolMeta {
  /** UTF-8 bytes read from the primary input field. */
  bytesIn: number
  /** UTF-8 bytes of the canonical result payload. */
  bytesOut: number
  /** Whether a budget clipped the input or the result. */
  truncated: boolean
  /** Ordered, human-readable notes: budgets, fallbacks, skipped entries. */
  notes: string[]
}

/** Canonical value returned by every tool in this package. */
export interface Envelope<T> {
  /** The tool-specific payload. */
  result: T
  /** Byte accounting and notes for this call. */
  meta: ToolMeta
}

/** Model-facing text block (structurally identical to `@deepseek-ai/dsh-llm` ContentBlock). */
export interface TextBlock {
  readonly type: 'text'
  readonly text: string
}

/**
 * Build the meta block for one call.
 * @param bytesIn - measured input bytes.
 * @param result - canonical payload used to measure the output.
 * @param notes - accumulated notes.
 * @param truncated - whether a budget clipped anything.
 */
export function metaOf(bytesIn: number, result: unknown, notes: readonly string[] = [], truncated = false): ToolMeta {
  return {
    bytesIn,
    bytesOut: typeof result === 'string' ? utf8Bytes(result) : jsonBytes(result),
    truncated,
    notes: [...notes],
  }
}

/** Wrap a payload with its accounting. */
export function envelope<T>(result: T, bytesIn: number, notes: readonly string[] = [], truncated = false): Envelope<T> {
  return { result, meta: metaOf(bytesIn, result, notes, truncated) }
}

/**
 * Render an envelope for the model: the payload itself, plus a footer only when
 * something needs saying. A clean call costs no extra tokens.
 * @param value - canonical envelope.
 * @returns model-facing content blocks.
 */
export function renderEnvelope(value: Envelope<unknown>): TextBlock[] {
  const body = typeof value.result === 'string' ? value.result : JSON.stringify(value.result, null, 2)
  const footer: string[] = []
  if (value.meta.truncated) {
    footer.push(`[bounded] input=${value.meta.bytesIn}B output=${value.meta.bytesOut}B`)
  }
  for (const note of value.meta.notes) footer.push(`[note] ${note}`)
  const text = footer.length > 0 ? `${body}\n\n${footer.join('\n')}` : body
  return [{ type: 'text', text }]
}
