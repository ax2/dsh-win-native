import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { Envelope } from '../src/core/receipt.ts'
import { createTools } from '../src/tools.ts'
import { DEFAULT_LIMITS, resolveLimits } from '../src/limits.ts'
import { detectDialect, findDuplicateBinds, isWildcard, parseNetstat, splitEndpoint } from '../src/core/netstat.ts'

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

/** A realistic `netstat -ano` capture: wildcard and specific listeners, IPv6, established pairs, UDP. */
const NETSTAT_SAMPLE = `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1012
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:445          0.0.0.0:0              LISTENING       4
  TCP    192.168.1.20:139       0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       812
  TCP    192.168.1.20:49671     52.109.8.20:443        ESTABLISHED     4412
  TCP    192.168.1.20:49672     52.109.8.20:443        ESTABLISHED     4412
  TCP    192.168.1.20:49673     13.107.42.16:443       ESTABLISHED     11220
  TCP    192.168.1.20:49674     13.107.42.16:443       TIME_WAIT       0
  TCP    [::]:135               [::]:0                 LISTENING       1012
  TCP    [::1]:5354             [::]:0                 LISTENING       7788
  UDP    0.0.0.0:500            *:*                                    1012
  UDP    0.0.0.0:3702           *:*                                    3140
  UDP    [::]:3702              *:*                                    3140
`

/** A `netstat -anob` fragment, where the executable arrives on its own line. */
const NETSTAT_B_SAMPLE = `
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
 [System]
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       7912
 [svchost.exe]
  TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       14456
 [TeamViewer.exe]
`

/** PowerShell `Get-NetTCPConnection`-style output. */
const POWERSHELL_SAMPLE = `
LocalAddress LocalPort RemoteAddress RemotePort State       OwningProcess
------------ --------- ------------- ---------- -----       -------------
0.0.0.0      135       0.0.0.0       0          Listen      1012
0.0.0.0      445       0.0.0.0       0          Listen      4
127.0.0.1    445       0.0.0.0       0          Listen      4
192.168.1.20 49671     52.109.8.20   443        Established 4412
192.168.1.20 49672     52.109.8.20   443        Established 4412
`

test('splitEndpoint handles IPv4, IPv6 brackets, wildcards and service names', () => {
  assert.deepEqual(splitEndpoint('127.0.0.1:445'), { address: '127.0.0.1', port: 445, raw_port: '445' })
  assert.deepEqual(splitEndpoint('[::]:135'), { address: '[::]', port: 135, raw_port: '135' })
  assert.deepEqual(splitEndpoint('[fe80::1%12]:445'), { address: '[fe80::1%12]', port: 445, raw_port: '445' })
  assert.deepEqual(splitEndpoint('*:*'), { address: '*', port: null, raw_port: '*' })
  assert.deepEqual(splitEndpoint('0.0.0.0:0'), { address: '0.0.0.0', port: 0, raw_port: '0' })
  assert.deepEqual(splitEndpoint('host:https'), { address: 'host', port: null, raw_port: 'https' })
  assert.deepEqual(splitEndpoint('no-port'), { address: 'no-port', port: null, raw_port: '' })
  assert.deepEqual(splitEndpoint('[::]:70000'), { address: '[::]', port: null, raw_port: '70000' })
})

test('isWildcard recognizes every wildcard spelling', () => {
  for (const address of ['0.0.0.0', '*', '[::]', '::']) assert.equal(isWildcard(address), true)
  for (const address of ['127.0.0.1', '192.168.1.20', '[::1]']) assert.equal(isWildcard(address), false)
})

test('parseNetstat reads the netstat dialect: counts, listeners, established groups, duplicates', () => {
  const report = parseNetstat(NETSTAT_SAMPLE)
  assert.equal(report.dialect, 'netstat')
  assert.equal(report.rows.length, 14)
  assert.deepEqual(report.summary, {
    tcp_rows: 11,
    udp_rows: 3,
    listening_tcp: 7,
    listening_udp: 3,
    established: 3,
    distinct_pids: 8,
    ports: 11,
  })
  assert.deepEqual(
    report.state_counts.map((entry) => `${entry.state}=${entry.count}`),
    // Ties in count are ordered by state name, so UDP sorts before ESTABLISHED.
    ['LISTENING=7', 'ESTABLISHED=3', 'UDP=3', 'TIME_WAIT=1'],
  )
  assert.deepEqual(
    report.protocol_counts.map((entry) => `${entry.protocol}=${entry.count}`),
    ['tcp=11', 'udp=3'],
  )
  const port445 = report.listening.filter((entry) => entry.port === 445)
  assert.equal(port445.length, 2)
  assert.deepEqual(port445.map((entry) => `${entry.address}:${entry.pid}`), ['0.0.0.0:4', '127.0.0.1:4'])

  const duplicate = report.duplicate_binds.find((entry) => entry.port === 445)
  assert.ok(duplicate, 'the 0.0.0.0/127.0.0.1 pair on port 445 is a duplicate bind')
  assert.equal(duplicate.protocol, 'tcp')
  assert.equal(duplicate.wildcard_conflict, true)
  assert.equal(duplicate.multi_pid, false)
  assert.deepEqual(duplicate.bindings.map((binding) => `${binding.address}:${binding.pid}`), ['0.0.0.0:4', '127.0.0.1:4'])

  const port135 = report.duplicate_binds.find((entry) => entry.port === 135)
  assert.ok(port135, 'the IPv4 and IPv6 wildcard binds on port 135 are separate bindings of the same port')
  assert.equal(port135.wildcard_conflict, true)
  assert.equal(port135.bindings.length, 2)

  const udp3702 = report.duplicate_binds.find((entry) => entry.protocol === 'udp' && entry.port === 3702)
  assert.ok(udp3702, 'UDP 3702 is bound on both 0.0.0.0 and [::]')

  assert.equal(report.established[0]?.remote, '52.109.8.20:443')
  assert.equal(report.established[0]?.connections, 2)
  assert.deepEqual(report.established[0]?.pids, [4412])
  assert.deepEqual(report.established[0]?.states, ['ESTABLISHED'])
  assert.equal(report.established[1]?.remote, '13.107.42.16:443')
  assert.equal(report.established[1]?.connections, 1)
  assert.deepEqual(report.notes, [])
  assert.match(report.limitations.join('\n'), /cannot be determined from netstat text/)
})

test('parseNetstat attaches `netstat -b` executable names and detects the dialect', () => {
  assert.equal(detectDialect(NETSTAT_B_SAMPLE), 'netstat')
  const report = parseNetstat(NETSTAT_B_SAMPLE)
  const names = report.listening.map((entry) => `${entry.port}=${entry.process_name}`)
  assert.deepEqual(names, ['80=System', '5040=svchost.exe', '5939=TeamViewer.exe'])
  assert.equal(report.listening[0]?.pid, 4)
})

test('parseNetstat recognizes PowerShell Get-NetTCPConnection table output', () => {
  assert.equal(detectDialect(POWERSHELL_SAMPLE), 'powershell')
  const report = parseNetstat(POWERSHELL_SAMPLE)
  assert.equal(report.dialect, 'powershell')
  assert.equal(report.rows.length, 5)
  assert.deepEqual(report.summary, {
    tcp_rows: 5,
    udp_rows: 0,
    listening_tcp: 3,
    listening_udp: 0,
    established: 2,
    distinct_pids: 3,
    ports: 4,
  })
  const listener = report.listening.find((entry) => entry.address === '127.0.0.1')
  assert.ok(listener)
  assert.equal(listener.port, 445)
  assert.equal(listener.pid, 4)
  const established = report.established.find((entry) => entry.remote === '52.109.8.20:443')
  assert.equal(established?.connections, 2)
  assert.equal(established?.pids[0], 4412)
  const duplicate = report.duplicate_binds.find((entry) => entry.port === 445)
  assert.ok(duplicate)
  assert.equal(duplicate.wildcard_conflict, true)
})

test('findDuplicateBinds ignores established sockets that merely reuse a local port', () => {
  const report = parseNetstat(NETSTAT_SAMPLE)
  const port49670 = report.duplicate_binds.find((entry) => entry.port === 49670)
  assert.equal(port49670, undefined, 'a listener plus its own connections is not a duplicate bind')
})

test('parseNetstat never invents facts the text cannot carry', () => {
  const report = parseNetstat('  TCP    0.0.0.0:80     0.0.0.0:0     LISTENING    4\n')
  assert.equal(report.listening[0]?.pid, 4)
  assert.equal(report.listening[0]?.process_name, null)
  assert.match(report.limitations.join('\n'), /whether a listening PID still exists/)
  assert.match(report.limitations.join('\n'), /process names are only present/)
})

test('parseNetstat skips malformed lines and says so instead of guessing', () => {
  const report = parseNetstat('Proto Local Address Foreign Address State PID\n  TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 4\n  this is not a row\n  UDP 0.0.0.0:53 *:* 5353\n')
  assert.equal(report.rows.length, 2)
  assert.equal(report.notes.length, 1)
  assert.match(report.notes[0]!, /1 line\(s\) did not match the netstat row shape/)
})

test('netstat_parse returns the receipt envelope with complete counters and explicit limitations', async () => {
  const value = await run('netstat_parse', { text: NETSTAT_SAMPLE })
  const result = value.result as unknown as {
    dialect: string
    summary: { listening_tcp: number; established: number }
    state_counts: { state: string; count: number }[]
    listening: unknown[]
    established: unknown[]
    duplicate_binds: unknown[]
    rows: unknown[]
    limitations: string[]
  }
  assert.equal(result.dialect, 'netstat')
  assert.equal(result.summary.listening_tcp, 7)
  assert.equal(result.summary.established, 3)
  assert.equal(result.listening.length, 10)
  assert.equal(result.duplicate_binds.length, 3)
  assert.deepEqual(result.rows, [], 'rows are opt-in')
  assert.equal(value.meta.truncated, false)
  assert.ok(result.limitations.length >= 3)

  const withRows = await run('netstat_parse', { text: NETSTAT_SAMPLE, include_rows: true })
  assert.equal((withRows.result as unknown as { rows: unknown[] }).rows.length, 14)

  const bytesIn = value.meta.bytesIn
  assert.equal(bytesIn, Buffer.byteLength(NETSTAT_SAMPLE, 'utf8'))
})

test('netstat_parse clips long lists to maxEntries and marks the result bounded', async () => {
  const lines = ['  Proto  Local Address          Foreign Address        State           PID']
  for (let index = 0; index < 12; index++) {
    lines.push(`  TCP    0.0.0.0:${10_000 + index}       0.0.0.0:0              LISTENING       ${100 + index}`)
  }
  const clipped = createTools({ limits: resolveLimits({ maxEntries: 3 }) })
  const value = await run('netstat_parse', { text: lines.join('\n') }, clipped)
  const result = value.result as unknown as {
    listening: unknown[]
    summary: { listening_tcp: number }
  }
  assert.equal(result.listening.length, 3)
  assert.equal(result.summary.listening_tcp, 12, 'the counters stay complete even when the lists are clipped')
  assert.equal(value.meta.truncated, true)
  assert.match(value.meta.notes[0] ?? '', /maxEntries=3/)
})

test('netstat_parse reports an unrecognized dialect without failing', async () => {
  const value = await run('netstat_parse', { text: 'nothing here looks like a socket table' })
  const result = value.result as unknown as { dialect: string; rows: unknown[]; notes: string[] }
  assert.equal(result.dialect, 'unknown')
  assert.deepEqual(result.rows, [])
  assert.ok(result.notes.some((note) => /did not match the unknown row shape/.test(note)))
  assert.match(value.meta.notes.join('\n'), /no netstat or Get-NetTCPConnection header/)
})

test('netstat_parse refuses an over-budget paste instead of parsing half of it', async () => {
  const small = createTools({ limits: resolveLimits({ maxInputBytes: 64 }) })
  await assert.rejects(() => run('netstat_parse', { text: NETSTAT_SAMPLE }, small), /above the configured limit/)
})
