/**
 * Windows codepage detection and conversion.
 *
 * The interesting failure mode on Windows is not "which encoding is this" in the
 * abstract, it is a tool that silently reinterprets GBK bytes as UTF-8 and
 * reports mojibake as a value. Everything here is built to expose that
 * ambiguity: every candidate is decoded, scored, and reported with the signals
 * that produced the score, and a genuinely ambiguous payload returns `low`
 * confidence plus the competing candidates instead of a confident guess.
 * @module dsh-win-native/core/encoding
 */
import iconv from 'iconv-lite'

/** Every encoding this plugin can decode from or encode to. */
export const SOURCE_ENCODINGS = [
  'auto',
  'utf-8',
  'utf-16le',
  'utf-16be',
  'gbk',
  'gb18030',
  'big5',
  'shift_jis',
  'latin1',
  'ascii',
] as const

/** Every encoding accepted as a conversion target (`auto` is meaningless there). */
export const TARGET_ENCODINGS = [
  'utf-8',
  'utf-16le',
  'utf-16be',
  'gbk',
  'gb18030',
  'big5',
  'shift_jis',
  'latin1',
  'ascii',
] as const

/** BOM handling policy for the converted output. */
export const BOM_POLICIES = ['keep', 'add', 'strip'] as const

/** One encoding name accepted by this module. */
export type SourceEncoding = (typeof SOURCE_ENCODINGS)[number]

/** One conversion target name. */
export type TargetEncoding = (typeof TARGET_ENCODINGS)[number]

/** One BOM policy name. */
export type BomPolicy = (typeof BOM_POLICIES)[number]

/** Confidence that the reported encoding is the right one. */
export type Confidence = 'high' | 'medium' | 'low'

/** Byte-order marks, longest first so UTF-32 is not mistaken for UTF-16. */
export const BOMS: readonly { encoding: string; bytes: readonly number[] }[] = [
  { encoding: 'utf-32le', bytes: [0xff, 0xfe, 0x00, 0x00] },
  { encoding: 'utf-32be', bytes: [0x00, 0x00, 0xfe, 0xff] },
  { encoding: 'utf-8', bytes: [0xef, 0xbb, 0xbf] },
  { encoding: 'utf-16le', bytes: [0xff, 0xfe] },
  { encoding: 'utf-16be', bytes: [0xfe, 0xff] },
]

/** One candidate decoding of a payload. */
export interface EncodingCandidate {
  /** Canonical encoding name. */
  encoding: string
  /** 0 (implausible) to 1 (clean), derived from the signals listed below. */
  score: number
  /**
   * Internal ordering key: `score` plus the documented code-page prior. Two
   * candidates can share the same `score` and still be ordered by `ranked`.
   */
  ranked: number
  /** Characters the decoder could not map, i.e. U+FFFD. */
  replacements: number
  /** Characters that are structurally decodable but implausible in real text. */
  suspicious: number
  /** Characters in ranges that this code page only reaches with unusual byte pairs. */
  implausible_scripts: number
  /** Whether re-encoding the decoded text reproduces the original bytes exactly. */
  round_trip: boolean
  /** Short decoded sample, so a human can judge the guess. */
  sample: string
}

/** Detection result for one payload. */
export interface EncodingDetection {
  /** Best candidate encoding name. */
  encoding: string
  /** Confidence in `encoding`; `low` means "report the alternatives, do not act on this". */
  confidence: Confidence
  /** Detected byte-order mark, or `none`. */
  bom: string
  /** Payload length in bytes. */
  byte_length: number
  /** Ordered candidates, best first, including the winner. */
  alternatives: EncodingCandidate[]
  /** Machine-readable signal codes explaining the decision. */
  signals: string[]
}

/** Suspicious targets: characters a real document in these code pages rarely contains. */
const SUSPICIOUS = /[\uE000-\uF8FF\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}\u3400-\u4DBF\u{20000}-\u{3FFFF}\uFF61-\uFF9F\uFF9E\uFF9F\u3100-\u312F\u31A0-\u31BF\u2E80-\u2EFF\u31C0-\u31EF\uF900-\uFAFF]/u

/** Kana, the one script signal that separates Shift-JIS from the Chinese code pages. */
const KANA = /[\u3040-\u309F\u30A0-\u30FF]/u

/** Characters that make a Latin-1 reading implausible for a Windows text file. */
function c1Count(text: string): number {
  let n = 0
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0
    if (cp >= 0x80 && cp <= 0x9f) n++
  }
  return n
}

/**
 * Decode bytes with a canonical encoding name, including the UTF-16 variants
 * that `iconv-lite` does not expose directly.
 * @param bytes - raw bytes, without any BOM.
 * @param encoding - canonical encoding name.
 * @returns decoded text.
 */
export function decodeBytes(bytes: Buffer, encoding: string): string {
  if (encoding === 'utf-16le' || encoding === 'utf-16be') {
    const even = bytes.subarray(0, bytes.length - (bytes.length % 2))
    const swapped = Buffer.from(even)
    if (encoding === 'utf-16be') swapped.swap16()
    return swapped.toString('utf16le')
  }
  if (encoding === 'utf-32le') return decodeUtf32(bytes, false)
  if (encoding === 'utf-32be') return decodeUtf32(bytes, true)
  return iconv.decode(bytes, encoding)
}

/** Decode UTF-32 with explicit byte order; `iconv-lite` has no UTF-32 codec. */
function decodeUtf32(bytes: Buffer, bigEndian: boolean): string {
  let out = ''
  for (let i = 0; i + 3 < bytes.length; i += 4) {
    const cp = bigEndian
      ? (bytes[i]! << 24) | (bytes[i + 1]! << 16) | (bytes[i + 2]! << 8) | bytes[i + 3]!
      : (bytes[i + 3]! << 24) | (bytes[i + 2]! << 16) | (bytes[i + 1]! << 8) | bytes[i]!
    out += cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '\uFFFD'
  }
  return out
}

/**
 * Encode text with a canonical encoding name, including the UTF-16 variants.
 * @param text - text to encode.
 * @param encoding - canonical encoding name from {@link TARGET_ENCODINGS}.
 * @returns encoded bytes without a BOM.
 */
export function encodeText(text: string, encoding: string): Buffer {
  if (encoding === 'utf-16le') return Buffer.from(text, 'utf16le')
  if (encoding === 'utf-16be') {
    const little = Buffer.from(text, 'utf16le')
    little.swap16()
    return little
  }
  return iconv.encode(text, encoding)
}

/** Detect the BOM at the start of a payload. */
export function detectBom(bytes: Buffer): { encoding: string; length: number } {
  for (const bom of BOMS) {
    if (bytes.length >= bom.bytes.length && bom.bytes.every((byte, index) => bytes[index] === byte)) {
      return { encoding: bom.encoding, length: bom.bytes.length }
    }
  }
  return { encoding: 'none', length: 0 }
}

/** Return the BOM bytes for an encoding, or an empty buffer when it has none. */
export function bomFor(encoding: string): Buffer {
  const found = BOMS.find((bom) => bom.encoding === encoding)
  return found === undefined ? Buffer.alloc(0) : Buffer.from(found.bytes)
}

/**
 * Whether the payload is valid strict UTF-8. Uses the platform decoder with
 * `fatal`, which is a real validator rather than a permissive re-decode.
 * @param bytes - raw bytes.
 */
export function isStrictUtf8(bytes: Buffer): boolean {
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return true
  } catch {
    return false
  }
}

/** Count occurrences of U+FFFD. */
function replacementCount(text: string): number {
  let n = 0
  for (const ch of text) if (ch === '\uFFFD') n++
  return n
}

/**
 * Score one decoded candidate.
 *
 * The score is a penalty budget over four independent signals: replacements
 * (the decoder failed), suspicious characters (the decoder succeeded but
 * produced characters a real document would not contain), script mix (Shift-JIS
 * payloads decode to Kana, which the Chinese code pages do not produce in
 * volume), and round-trip failure (the byte stream is not stable under this
 * code page).
 * @param encoding - candidate encoding name.
 * @param text - the candidate decoding.
 * @param options - `roundTrip` is the measured stability of this candidate under
 * its own codec; `tieBreak` adds the documented, sub-evidence code-page priors.
 */
function scoreCandidate(
  encoding: string,
  text: string,
  options: { roundTrip: boolean; tieBreak: boolean; lowLeadShare: number },
): Omit<EncodingCandidate, 'encoding' | 'sample' | 'ranked'> & { ranked: number } {
  const analyzed = [...text].filter((ch) => (ch.codePointAt(0) ?? 0) > 0x7f)
  const total = analyzed.length
  const replacements = replacementCount(text)
  let suspicious = 0
  let implausibleScripts = 0
  for (const ch of analyzed) {
    if (SUSPICIOUS.test(ch)) suspicious++
    // Kana is legitimate in Shift-JIS and merely legal in the Chinese code pages,
    // so a Kana-heavy reading of a non-Shift-JIS candidate is a real warning.
    if (encoding !== 'shift_jis' && KANA.test(ch)) implausibleScripts++
  }
  const ratio = (n: number): number => (total === 0 ? 0 : n / total)
  let penalty = 0
  // A failed decode is near-conclusive: one replacement already means this code
  // page cannot represent the payload.
  penalty += Math.min(1, ratio(replacements) * 12) * 0.6
  penalty += Math.min(1, ratio(suspicious) * 4) * 0.35
  penalty += Math.min(1, ratio(implausibleScripts) * 4) * 0.2
  if (encoding === 'latin1') {
    // Latin-1 never fails to decode, which is exactly why it needs an explicit
    // prior: on a Windows box, a non-ASCII file is far more likely to be a CJK
    // code page than Latin-1, and Windows itself uses the ANSI code page for
    // such files. C1 control characters are the one thing Latin-1 genuinely
    // cannot explain in a text file.
    const c1 = c1Count(text)
    penalty += Math.min(1, ratio(c1) * 4) * 0.3
    if (total > 0) penalty += 0.25
  }
  if (!options.roundTrip) penalty += 0.25
  // Round-trip stability is weak evidence on its own (many byte streams are
  // valid in several code pages), so it only shifts the score, never decides it.
  const score = Math.max(0, Math.min(1, 1 - penalty))
  // The tie-break is added after rounding the published score, so it reorders
  // candidates without ever changing the number a caller reads.
  const ranked = score + (options.tieBreak ? tieBreakBonus(encoding, options.lowLeadShare) : 0)
  return {
    score: Number(score.toFixed(3)),
    ranked,
    replacements,
    suspicious,
    implausible_scripts: implausibleScripts,
    round_trip: options.roundTrip,
  }
}

/**
 * Documented code-page priors, applied only as tie-breakers.
 *
 * These are not evidence about the payload; they encode which code page a
 * Windows machine is more likely to have produced when the byte stream is
 * equally decodable under several. The weight is deliberately smaller than the
 * smallest real signal (0.25 for a failed round trip, 0.5 for suspicious
 * characters), so it can only order candidates that are already level.
 * @param encoding - candidate name.
 * @param lowLeadShare - share of multi-byte characters in the 0x81-0x9F lead
 * range, which is Shift-JIS territory rather than GBK territory.
 */
function tieBreakBonus(encoding: string, lowLeadShare: number): number {
  if (encoding === 'gb18030') {
    // A GBK/GB18030 document uses 0xB0-0xF7 for Chinese and rarely 0x81-0x9F, so
    // this prior evaporates as soon as the payload looks like Shift-JIS.
    return 0.01 * (1 - Math.min(1, lowLeadShare * 1.5))
  }
  if (encoding === 'shift_jis') return 0.005 // narrower byte space than GB18030, so a coincidental match is less likely
  return 0
}

/**
 * Share of lead bytes that only Shift-JIS uses in practice.
 *
 * GB18030's coverage of the 0x81-0x9F lead range is real but narrow (it reaches
 * Greek, Cyrillic and a few hundred rare CJK characters there), while Shift-JIS
 * puts its entire Hiragana block and much of its Kanji block there. A payload
 * whose multi-byte characters overwhelmingly live in that range is therefore
 * weak evidence for Shift-JIS, used only to avoid reporting a Japanese text file
 * as GB18030 with a straight face.
 * @param bytes - the payload.
 * @returns fraction in `[0, 1]`.
 */
export function lowLeadShare(bytes: Buffer): number {
  let pairs = 0
  let lowLead = 0
  for (let i = 0; i + 1 < bytes.length; i++) {
    const lead = bytes[i]!
    if (lead < 0x81 || lead > 0xfe) continue
    const trail = bytes[i + 1]!
    if (trail < 0x40 || trail === 0x7f || trail > 0xfe) continue
    pairs++
    if (lead <= 0x9f) lowLead++
    i++
  }
  return pairs === 0 ? 0 : lowLead / pairs
}

/** The candidate code pages considered when the payload has no BOM. */
const CANDIDATES = ['utf-8', 'gb18030', 'big5', 'shift_jis', 'latin1'] as const

/**
 * Detect the encoding of a payload.
 *
 * Order of evidence: BOM, then strict UTF-8 validation, then a scored decode of
 * each candidate code page. This mirrors how the failure actually happens on
 * Windows: a BOM is authoritative, a strict-UTF-8 payload is almost always
 * UTF-8, and everything else is a probabilistic call that must be reported as
 * such.
 * @param bytes - raw payload bytes.
 * @param options - `sampleChars` bounds the decoded sample per candidate.
 * @returns detection result with ordered alternatives and signal codes.
 */
export function detectEncoding(bytes: Buffer, options: { sampleChars?: number } = {}): EncodingDetection {
  const sampleChars = options.sampleChars ?? 60
  const bom = detectBom(bytes)
  const signals: string[] = []
  if (bom.encoding !== 'none') {
    const body = bytes.subarray(bom.length)
    const text = decodeBytes(body, bom.encoding)
    signals.push(`bom:${bom.encoding}`)
    const candidate: EncodingCandidate = {
      encoding: bom.encoding,
      score: 1,
      ranked: 1,
      replacements: replacementCount(text),
      suspicious: 0,
      implausible_scripts: 0,
      round_trip: true,
      sample: text.slice(0, sampleChars),
    }
    return {
      encoding: bom.encoding,
      confidence: candidate.replacements === 0 ? 'high' : 'medium',
      bom: bom.encoding,
      byte_length: bytes.length,
      alternatives: [candidate],
      signals: candidate.replacements === 0 ? signals : [...signals, 'bom-payload-has-replacement-characters'],
    }
  }
  if (bytes.length === 0) {
    signals.push('empty-payload')
    return {
      encoding: 'utf-8',
      confidence: 'low',
      bom: 'none',
      byte_length: 0,
      alternatives: [
        { encoding: 'utf-8', score: 1, ranked: 1, replacements: 0, suspicious: 0, implausible_scripts: 0, round_trip: true, sample: '' },
      ],
      signals,
    }
  }
  const allAscii = bytes.every((byte) => byte < 0x80)
  if (allAscii) {
    signals.push('all-bytes-ascii')
    return {
      encoding: 'ascii',
      confidence: 'high',
      bom: 'none',
      byte_length: bytes.length,
      alternatives: [
        {
          encoding: 'ascii',
          score: 1,
          ranked: 1,
          replacements: 0,
          suspicious: 0,
          implausible_scripts: 0,
          round_trip: true,
          sample: bytes.toString('latin1').slice(0, sampleChars),
        },
      ],
      signals,
    }
  }
  const validUtf8 = isStrictUtf8(bytes)
  if (validUtf8) {
    const text = bytes.toString('utf8')
    signals.push('strict-utf-8-valid')
    const candidate: EncodingCandidate = {
      encoding: 'utf-8',
      score: 1,
      ranked: 1,
      replacements: 0,
      suspicious: 0,
      implausible_scripts: 0,
      round_trip: true,
      sample: text.slice(0, sampleChars),
    }
    // A strict-UTF-8 payload still is not proof: ASCII runs inside GBK payloads
    // are common, and a coincidence can produce valid UTF-8 from GBK bytes. Only
    // non-ASCII decoding decides here.
    const nonAscii = [...text].filter((ch) => (ch.codePointAt(0) ?? 0) > 0x7f).length
    return {
      encoding: 'utf-8',
      confidence: nonAscii >= 2 ? 'high' : nonAscii === 1 ? 'medium' : 'low',
      bom: 'none',
      byte_length: bytes.length,
      alternatives: [candidate],
      signals,
    }
  }

  // No BOM and not valid UTF-8: this is the honest part. Score every code page.
  const scored: EncodingCandidate[] = []
  for (const encoding of CANDIDATES) {
    let text: string
    try {
      text = decodeBytes(bytes, encoding)
    } catch {
      continue
    }
    let roundTrip = false
    try {
      roundTrip = encodeText(text, encoding).equals(bytes)
    } catch {
      roundTrip = false
    }
    const scoredCandidate = scoreCandidate(encoding, text, {
      roundTrip,
      tieBreak: true,
      lowLeadShare: lowLeadShare(bytes),
    })
    scored.push({ encoding, sample: text.slice(0, sampleChars), ...scoredCandidate })
  }
  scored.sort((a, b) => b.ranked - a.ranked || a.encoding.localeCompare(b.encoding))
  const best = scored[0]
  if (best === undefined) {
    signals.push('no-candidate-decoded')
    return {
      encoding: 'latin1',
      confidence: 'low',
      bom: 'none',
      byte_length: bytes.length,
      alternatives: [],
      signals,
    }
  }
  {
    const tied = scored.filter((candidate) => Math.abs(candidate.ranked - best.ranked) < 1e-9)
    if (tied.length > 1) signals.push(`tie-broken-by-codepage-prior:${tied.map((candidate) => candidate.encoding).join('|')}`)
  }
  const runnerUp = scored[1]
  signals.push(`scored:${scored.map((candidate) => `${candidate.encoding}=${candidate.score}`).join(',')}`)
  if (best.replacements > 0) signals.push('best-candidate-still-has-replacements')
  // Confidence reflects the margin, not just the winner: a 10% score difference
  // between two code pages is not evidence.
  const margin = runnerUp === undefined ? 1 : best.ranked - runnerUp.ranked
  const confidence: Confidence = best.score >= 0.9 && margin >= 0.25 ? 'high' : best.score >= 0.6 && margin >= 0.08 ? 'medium' : 'low'
  if (confidence === 'low' && runnerUp !== undefined) {
    signals.push('ambiguous-candidates-within-score-margin')
  }
  return {
    encoding: best.encoding,
    confidence,
    bom: 'none',
    byte_length: bytes.length,
    alternatives: scored,
    signals,
  }
}

/** One character that a conversion could not represent. */
export interface LossyCharacter {
  /** The code point that had no target representation. */
  code_point: string
  /** `U+xxxx` spelling, for a human reader. */
  char: string
  /** How many times it occurred. */
  count: number
}

/** Result of converting one payload between encodings. */
export interface ConversionResult {
  /** Encoding actually used for the source. */
  source_encoding: string
  /** Encoding used for the output. */
  target_encoding: string
  /** Detected source BOM name, or `none`. */
  source_bom: string
  /** BOM name written to the output, or `none`. */
  output_bom: string
  /** Number of characters that could not be represented in the target. */
  lossy_characters: number
  /** The distinct characters responsible, bounded by the caller. */
  lossy_list: LossyCharacter[]
  /** Decoded source text (bounded by the caller). */
  text: string
  /** Length of the decoded source text before any caller bound was applied. */
  fullTextLength: number
  /** Whether the payload changed at all. */
  changed: boolean
  /** Machine-readable signal codes. */
  signals: string[]
}

/**
 * Convert bytes from one encoding to another, reporting every character the
 * target could not represent.
 *
 * Lossiness is measured by decoding the result back and comparing, not by
 * trusting the encoder: `iconv-lite` substitutes `?` without an error, so the
 * only reliable check is a round trip over the produced bytes.
 * @param bytes - source bytes, BOM included.
 * @param from - source encoding, or `auto` to detect.
 * @param to - target encoding.
 * @param bomPolicy - what to do with the byte-order mark.
 * @param options - `textChars` bounds the returned decoded text, `lossyListMax` the loss list.
 */
export function convertEncoding(
  bytes: Buffer,
  from: SourceEncoding,
  to: TargetEncoding,
  bomPolicy: BomPolicy,
  options: { textChars?: number; lossyListMax?: number } = {},
): { result: ConversionResult; output: Buffer; detection?: EncodingDetection } {
  const textChars = options.textChars ?? 200
  const lossyListMax = options.lossyListMax ?? 32
  const signals: string[] = []
  const sourceBom = detectBom(bytes)
  let sourceEncoding: string
  let detection: EncodingDetection | undefined
  if (from === 'auto') {
    detection = detectEncoding(bytes)
    sourceEncoding = detection.encoding
    signals.push(`auto-detected-source:${sourceEncoding}:${detection.confidence}`)
    if (detection.confidence === 'low') {
      signals.push('auto-detection-low-confidence-verify-or-pass-from-explicitly')
    }
  } else {
    sourceEncoding = from
    signals.push(`source-declared:${from}`)
  }
  const body = sourceBom.length > 0 ? bytes.subarray(sourceBom.length) : bytes
  const text = decodeBytes(body, sourceEncoding)

  // A non-UTF target that cannot even round-trip ASCII is a user error, not a
  // silent data loss: report it instead of writing a broken file.
  let encodedBody = encodeText(text, to)
  const decodedBack = decodeBytes(encodedBody, to)
  const lossy = collectLossy(text, decodedBack)
  if (lossy.total > 0) {
    signals.push(`lossy:${lossy.total}-characters-replaced`)
  } else {
    signals.push('lossless-round-trip')
  }

  let outputBom: Buffer
  if (bomPolicy === 'keep') {
    outputBom = bomFor(to)
    signals.push(outputBom.length > 0 ? `bom:kept-for-${to}` : 'bom:target-has-none')
  } else if (bomPolicy === 'add') {
    outputBom = bomFor(to)
    if (outputBom.length === 0) signals.push(`bom:add-requested-but-${to}-has-no-bom`)
  } else {
    outputBom = Buffer.alloc(0)
    signals.push('bom:stripped')
  }
  // Strip a BOM that the encoder itself may have emitted so it is never doubled.
  const selfBom = detectBom(encodedBody)
  if (selfBom.length > 0) encodedBody = encodedBody.subarray(selfBom.length)

  const output = Buffer.concat([outputBom, encodedBody])
  const result: ConversionResult = {
    source_encoding: sourceEncoding,
    target_encoding: to,
    source_bom: sourceBom.encoding,
    output_bom: outputBom.length > 0 ? (BOMS.find((bom) => bom.bytes.length === outputBom.length && bom.bytes.every((b, i) => outputBom[i] === b))?.encoding ?? 'none') : 'none',
    lossy_characters: lossy.total,
    lossy_list: lossy.list.slice(0, lossyListMax),
    text: text.slice(0, textChars),
    fullTextLength: [...text].length,
    changed: !output.equals(bytes),
    signals,
  }
  return { result, output, detection }
}

/**
 * Compare the original text with the text recovered from the encoded bytes and
 * list the characters that did not survive.
 * @param original - decoded source text.
 * @param recovered - text decoded back from the encoded bytes.
 */
export function collectLossy(original: string, recovered: string): { total: number; list: LossyCharacter[] } {
  const source = [...original]
  const back = [...recovered]
  const counts = new Map<string, number>()
  let total = 0
  const length = Math.max(source.length, back.length)
  for (let i = 0; i < length; i++) {
    const a = source[i]
    const b = back[i]
    if (a === b) continue
    total++
    const key = a ?? b ?? '\uFFFD'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  const list: LossyCharacter[] = [...counts.entries()]
    .map(([char, count]) => ({
      code_point: `U+${(char.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
      char,
      count,
    }))
    .sort((x, y) => y.count - x.count || x.code_point.localeCompare(y.code_point))
  return { total, list }
}

/** Whether an encoding name is a supported conversion source. */
export function isSourceEncoding(value: string): value is SourceEncoding {
  return (SOURCE_ENCODINGS as readonly string[]).includes(value)
}

/** Whether an encoding name is a supported conversion target. */
export function isTargetEncoding(value: string): value is TargetEncoding {
  return (TARGET_ENCODINGS as readonly string[]).includes(value)
}

/** Whether a BOM policy name is supported. */
export function isBomPolicy(value: string): value is BomPolicy {
  return (BOM_POLICIES as readonly string[]).includes(value)
}
