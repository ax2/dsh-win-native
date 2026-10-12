import { test } from 'node:test'
import assert from 'node:assert/strict'
import iconv from 'iconv-lite'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { Envelope } from '../src/core/receipt.ts'
import { createTools } from '../src/tools.ts'
import { detectBom, detectEncoding, isStrictUtf8, type Confidence } from '../src/core/encoding.ts'
import { decodeBase64, encodeBase64 } from '../src/core/bytes.ts'
import { DEFAULT_LIMITS, resolveLimits } from '../src/limits.ts'

const tools = createTools({ limits: DEFAULT_LIMITS })

/** Look up a registered definition by name. */
function tool(name: string, set: ToolDefinition[] = tools): ToolDefinition {
  const found = set.find((candidate) => candidate.name === name)
  assert.ok(found, `tool ${name} is not registered`)
  return found
}

/** Execute a tool with a synthetic, always-live execution context. */
async function run(name: string, args: Record<string, unknown>): Promise<Envelope<Record<string, unknown>>> {
  return (await tool(name).execute(args, { signal: new AbortController().signal } as never)) as Envelope<
    Record<string, unknown>
  >
}

/** GBK bytes for the documented Chinese fixture, asserted byte by byte. */
const GBK_FIXTURE_TEXT = '你好，世界！这是一个测试。配置文件路径：C:\\Users\\ax2 服务未启动，请检查日志。'
const GBK_FIXTURE = iconv.encode(GBK_FIXTURE_TEXT, 'gbk')

/** Traditional-Chinese Big5 fixture. */
const BIG5_FIXTURE_TEXT = '你好，世界！這是一個測試。設定檔路徑：C:\\Users\\ax2 服務未啟動，請檢查日誌。'
const BIG5_FIXTURE = iconv.encode(BIG5_FIXTURE_TEXT, 'big5')

/** Japanese Shift-JIS fixture. */
const SJIS_FIXTURE_TEXT = 'こんにちは、世界！これはテストです。設定ファイルのパス：C:\\Users\\ax2'
const SJIS_FIXTURE = iconv.encode(SJIS_FIXTURE_TEXT, 'shift_jis')

test('the GBK fixture is real GBK: bytes, round trip, and strict-UTF-8 rejection', () => {
  // Golden bytes: 你=C4E3 好=BAC3 ，=A3AC 世=CAC0 界=BDE7. If iconv ever changed its
  // GBK table these assertions would fail before the detection logic could.
  assert.deepEqual([...GBK_FIXTURE.subarray(0, 10)], [0xc4, 0xe3, 0xba, 0xc3, 0xa3, 0xac, 0xca, 0xc0, 0xbd, 0xe7])
  assert.equal(iconv.decode(GBK_FIXTURE, 'gbk'), GBK_FIXTURE_TEXT)
  assert.deepEqual(iconv.encode(GBK_FIXTURE_TEXT, 'gbk'), GBK_FIXTURE)
  assert.equal(isStrictUtf8(GBK_FIXTURE), false)
  assert.equal(detectBom(GBK_FIXTURE).encoding, 'none')
})

test('encoding_detect identifies GBK bytes for a Chinese string with high confidence', async () => {
  const value = await run('encoding_detect', { base64: encodeBase64(GBK_FIXTURE) })
  const result = value.result as unknown as {
    encoding: string
    confidence: Confidence
    bom: string
    byte_length: number
    alternatives: { encoding: string; score: number; replacements: number; round_trip: boolean }[]
    signals: string[]
  }
  assert.equal(result.encoding, 'gb18030')
  assert.equal(result.confidence, 'high')
  assert.equal(result.bom, 'none')
  assert.equal(result.byte_length, GBK_FIXTURE.length)
  const winner = result.alternatives[0]!
  assert.equal(winner.encoding, 'gb18030')
  assert.equal(winner.replacements, 0)
  assert.equal(winner.round_trip, true)
  const big5 = result.alternatives.find((candidate) => candidate.encoding === 'big5')!
  assert.ok(big5.score < winner.score, 'the wrong code page must score below the right one')
  assert.equal(value.meta.bytesIn, encodeBase64(GBK_FIXTURE).length)
  assert.deepEqual(value.meta.notes, [])
})

test('encoding_detect reports low confidence and alternatives for a genuinely ambiguous short payload', async () => {
  const ambiguous = iconv.encode('中文', 'gbk')
  const value = await run('encoding_detect', { base64: encodeBase64(ambiguous) })
  const result = value.result as unknown as {
    encoding: string
    confidence: Confidence
    alternatives: { encoding: string; score: number }[]
  }
  assert.equal(result.confidence, 'low')
  const encodings = result.alternatives.map((candidate) => candidate.encoding)
  assert.ok(encodings.includes('big5'))
  assert.ok(encodings.includes('gb18030'))
  assert.equal(result.alternatives[0]?.score, result.alternatives[1]?.score)
  assert.equal(value.meta.notes.length, 1)
  assert.match(value.meta.notes[0]!, /confidence is low/)
})

test('encoding_detect prefers the BOM, then strict UTF-8', async () => {
  const utf8Bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('UTF-8 带 BOM 的中文', 'utf8')])
  const bomValue = (await run('encoding_detect', { base64: encodeBase64(utf8Bom) })).result as unknown as {
    encoding: string
    confidence: Confidence
    bom: string
  }
  assert.equal(bomValue.bom, 'utf-8')
  assert.equal(bomValue.encoding, 'utf-8')
  assert.equal(bomValue.confidence, 'high')

  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('UTF-16LE 测试文本', 'utf16le')])
  const utf16Value = (await run('encoding_detect', { base64: encodeBase64(utf16) })).result as unknown as {
    encoding: string
    bom: string
  }
  assert.equal(utf16Value.bom, 'utf-16le')
  assert.equal(utf16Value.encoding, 'utf-16le')

  const utf16be = Buffer.concat([Buffer.from([0xfe, 0xff]), iconv.encode('UTF-16BE 测试', 'utf-16be')])
  const utf16beValue = (await run('encoding_detect', { base64: encodeBase64(utf16be) })).result as unknown as { bom: string }
  assert.equal(utf16beValue.bom, 'utf-16be')

  const plainUtf8 = Buffer.from('中文测试：编码检测与转换', 'utf8')
  const plainValue = (await run('encoding_detect', { base64: encodeBase64(plainUtf8) })).result as unknown as {
    encoding: string
    confidence: Confidence
  }
  assert.equal(plainValue.encoding, 'utf-8')
  assert.equal(plainValue.confidence, 'high')

  const ascii = Buffer.from('C:\\Windows\\System32\\drivers\\etc\\hosts', 'utf8')
  const asciiValue = (await run('encoding_detect', { base64: encodeBase64(ascii) })).result as unknown as { encoding: string }
  assert.equal(asciiValue.encoding, 'ascii')
})

test('encoding_detect recognizes Big5 and Shift-JIS fixtures, and never calls them UTF-8', async () => {
  const big5 = (await run('encoding_detect', { base64: encodeBase64(BIG5_FIXTURE) })).result as unknown as {
    encoding: string
    confidence: Confidence
    alternatives: { encoding: string; suspicious: number }[]
  }
  assert.equal(big5.encoding, 'big5')
  assert.ok(big5.confidence === 'high' || big5.confidence === 'medium')
  assert.equal(big5.alternatives[0]?.suspicious, 0)

  const sjis = (await run('encoding_detect', { base64: encodeBase64(SJIS_FIXTURE) })).result as unknown as {
    encoding: string
    alternatives: { encoding: string }[]
  }
  assert.equal(sjis.encoding, 'shift_jis')
  assert.equal(sjis.alternatives[0]?.encoding, 'shift_jis')
})

test('encoding_detect refuses a payload that is not base64', async () => {
  await assert.rejects(() => run('encoding_detect', { base64: 'not base64!!' }), /not valid base64/)
  await assert.rejects(() => run('encoding_detect', { base64: '' }), /not valid base64/)
  await assert.rejects(() => run('encoding_detect', { base64: 'AAAAA' }), /not valid base64/)
})

test('encoding_detect honors maxRawBytes as an explicit refusal', async () => {
  const tiny = createTools({ limits: resolveLimits({ maxRawBytes: 4 }) })
  await assert.rejects(
    () => tool('encoding_detect', tiny).execute({ base64: encodeBase64(GBK_FIXTURE) }, { signal: new AbortController().signal } as never),
    /above maxRawBytes=4/,
  )
})

test('encoding_convert auto-detects GBK and emits UTF-8 with a BOM on request', async () => {
  const value = await run('encoding_convert', { base64: encodeBase64(GBK_FIXTURE), to: 'utf-8', bom: 'add' })
  const result = value.result as unknown as {
    source_encoding: string
    target_encoding: string
    source_bom: string
    output_bom: string
    bytes_in: number
    bytes_out: number
    lossy_characters: number
    lossy_list: unknown[]
    hex_preview: string
    text: string
    changed: boolean
    base64: string
  }
  assert.equal(result.source_encoding, 'gb18030')
  assert.equal(result.target_encoding, 'utf-8')
  assert.equal(result.source_bom, 'none')
  assert.equal(result.output_bom, 'utf-8')
  assert.equal(result.bytes_in, GBK_FIXTURE.length)
  assert.equal(result.bytes_out, Buffer.byteLength(GBK_FIXTURE_TEXT, 'utf8') + 3)
  assert.equal(result.lossy_characters, 0)
  assert.deepEqual(result.lossy_list, [])
  assert.equal(result.hex_preview.startsWith('ef bb bf'), true)
  assert.equal(result.changed, true)
  const out = decodeBase64(result.base64)
  assert.equal(out.subarray(0, 3).toString('hex'), 'efbbbf')
  assert.equal(out.subarray(3).toString('utf8'), GBK_FIXTURE_TEXT)
  assert.equal(result.text, GBK_FIXTURE_TEXT.slice(0, 200))
  assert.equal(value.meta.truncated, false)
})

test('encoding_convert reports lossy characters instead of hiding them', async () => {
  const value = await run('encoding_convert', {
    base64: encodeBase64(Buffer.from('中文测试', 'utf8')),
    from: 'utf-8',
    to: 'latin1',
    bom: 'strip',
  })
  const result = value.result as unknown as {
    lossy_characters: number
    lossy_list: { code_point: string; char: string; count: number }[]
    bytes_out: number
  }
  assert.equal(result.lossy_characters, 4)
  assert.deepEqual(
    result.lossy_list.map((entry) => entry.code_point),
    ['U+4E2D', 'U+6587', 'U+6D4B', 'U+8BD5'],
  )
  assert.equal(result.bytes_out, 4)
  assert.equal(value.meta.notes.length, 1)
  assert.match(value.meta.notes[0]!, /^LOSSY: 4 character\(s\)/)
})

test('encoding_convert round-trips UTF-8 to GBK and back, and applies the BOM policy', async () => {
  const toGbk = await run('encoding_convert', {
    base64: encodeBase64(Buffer.from('配置：C:\\Program Files\\应用', 'utf8')),
    from: 'utf-8',
    to: 'gbk',
    bom: 'strip',
  })
  const gbkResult = toGbk.result as unknown as { lossy_characters: number; output_bom: string; base64: string }
  assert.equal(gbkResult.lossy_characters, 0)
  assert.equal(gbkResult.output_bom, 'none')
  assert.equal(iconv.decode(decodeBase64(gbkResult.base64), 'gbk'), '配置：C:\\Program Files\\应用')
  // Golden bytes for 配置：C in GBK: C5E4 D6C3 A3BA 43.
  assert.equal(decodeBase64(gbkResult.base64).subarray(0, 8).toString('hex'), 'c5e4d6c3a3ba433a')

  const back = await run('encoding_convert', {
    base64: gbkResult.base64,
    from: 'gbk',
    to: 'utf-8',
    bom: 'keep',
  })
  const backResult = back.result as unknown as { text: string; output_bom: string; lossy_characters: number }
  assert.equal(backResult.text, '配置：C:\\Program Files\\应用')
  assert.equal(backResult.output_bom, 'utf-8', 'utf-8 has a BOM, so `keep` writes one')
  assert.equal(backResult.lossy_characters, 0)
})

test('encoding_convert supports UTF-16 both ways and rejects unsupported targets', async () => {
  // A real BOM-delimited UTF-16LE file: iconv's utf-16le codec emits no BOM, so
  // the prefix is part of the fixture rather than something the encoder adds.
  const utf16Bytes = Buffer.concat([Buffer.from([0xff, 0xfe]), iconv.encode('UTF-16LE 测试', 'utf-16le')])
  const toUtf16 = await run('encoding_convert', {
    base64: encodeBase64(utf16Bytes),
    from: 'auto',
    to: 'utf-16le',
    bom: 'add',
    preview_bytes: 8,
  })
  const result = toUtf16.result as unknown as {
    source_encoding: string
    source_bom: string
    bytes_out: number
    hex_preview: string
    output_bom: string
    text: string
  }
  assert.equal(result.source_encoding, 'utf-16le')
  assert.equal(result.source_bom, 'utf-16le')
  assert.equal(result.output_bom, 'utf-16le')
  assert.equal(result.text, 'UTF-16LE 测试')
  assert.equal(result.hex_preview, 'ff fe 55 00 54 00 46 00')
  assert.equal(result.bytes_out, 2 + 'UTF-16LE 测试'.length * 2)

  // BOM-less UTF-16LE is genuinely undetectable from the byte stream alone: the
  // tool must report the uncertainty rather than pretend it knew.
  const noBom = await run('encoding_convert', {
    base64: encodeBase64(iconv.encode('UTF-16LE 测试', 'utf-16le')),
    from: 'auto',
    to: 'utf-8',
    bom: 'strip',
  })
  const noBomResult = noBom.result as unknown as { source_encoding: string; signals: string[] }
  assert.notEqual(noBomResult.source_encoding, 'utf-16le')
  assert.ok(
    noBomResult.signals.some((signal) => signal.startsWith('auto-detected-source:')),
    'the auto-detected source must be reported even when it is wrong',
  )

  const beBytes = iconv.encode('AB', 'utf-16be')
  const be = await run('encoding_convert', { base64: encodeBase64(beBytes), from: 'utf-16be', to: 'utf-8', bom: 'strip' })
  assert.equal((be.result as unknown as { text: string }).text, 'AB')

  await assert.rejects(
    () => run('encoding_convert', { base64: 'aGk=', to: 'utf-32le' }),
    /"to" must be one of/,
    'an unsupported target is refused by the parameter schema',
  )
})
