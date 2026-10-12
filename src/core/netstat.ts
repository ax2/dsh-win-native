/**
 * Interpretation of pasted Windows socket listings.
 *
 * The parser handles the two dialects an agent actually receives: classic
 * `netstat -ano`/`-anob` console output and PowerShell `Get-NetTCPConnection`
 * table output. It deliberately does not invent facts the text cannot carry —
 * there is no way to know from `netstat` text whether a listening PID is still
 * alive, so that question is reported as unanswerable instead of guessed.
 * @module dsh-win-native/core/netstat
 */

/** Which input format was recognized. */
export type NetstatDialect = 'netstat' | 'powershell' | 'unknown'

/** One parsed socket row. */
export interface SocketRow {
  /** `tcp` or `udp`, lower case. */
  protocol: 'tcp' | 'udp'
  /** Address as written, without the port. `*` and `[::]` are kept verbatim. */
  local_address: string
  /** Local port, or `null` when the text did not carry a numeric port. */
  local_port: number | null
  /** Remote address, empty for a listening or unconnected socket. */
  remote_address: string
  /** Remote port, or `null`. */
  remote_port: number | null
  /** TCP state as written (`LISTENING`, `ESTABLISHED`, ...); empty for UDP. */
  state: string
  /** Owning process id, or `null` when the row carried none. */
  pid: number | null
  /** Executable name from `netstat -b`, or `null`. */
  process_name: string | null
  /** 1-based line number in the input, so a human can find the row. */
  line: number
  /** Raw row text, trimmed. */
  raw: string
}

/** One duplicate bind: the same protocol and port claimed more than once. */
export interface DuplicateBind {
  /** `tcp` or `udp`. */
  protocol: 'tcp' | 'udp'
  /** The contested port. */
  port: number
  /** Every distinct binding of that port. */
  bindings: { address: string; pid: number | null; state: string; line: number }[]
  /** Whether one of the bindings is the wildcard address. */
  wildcard_conflict: boolean
  /** Whether more than one distinct PID claims the port. */
  multi_pid: boolean
}

/** Established connections rolled up by remote endpoint. */
export interface EndpointGroup {
  /** `host:port` (IPv6 in brackets exactly as written). */
  remote: string
  /** Number of rows in this group. */
  connections: number
  /** Distinct owning process ids. */
  pids: number[]
  /** Distinct local endpoints involved. */
  local_endpoints: string[]
  /** Distinct states seen in this group. */
  states: string[]
}

/** Parsed socket listing. */
export interface NetstatReport {
  /** Recognized input dialect. */
  dialect: NetstatDialect
  /** Rows parsed, in input order. */
  rows: SocketRow[]
  /** Row count per TCP state, upper-cased. */
  state_counts: { state: string; count: number }[]
  /** Row count per protocol. */
  protocol_counts: { protocol: string; count: number }[]
  /** Listening TCP endpoints (and UDP binds, which are always "listening"). */
  listening: {
    protocol: 'tcp' | 'udp'
    address: string
    port: number | null
    pid: number | null
    process_name: string | null
    line: number
  }[]
  /** Established connections grouped by remote endpoint. */
  established: EndpointGroup[]
  /** Ports bound more than once for the same protocol. */
  duplicate_binds: DuplicateBind[]
  /** Counters that are exact and useful at a glance. */
  summary: {
    tcp_rows: number
    udp_rows: number
    listening_tcp: number
    listening_udp: number
    established: number
    distinct_pids: number
    ports: number
  }
  /** What the text does not and cannot say. */
  limitations: string[]
  /** Non-fatal parse observations. */
  notes: string[]
}

/** Normalized header tokens recognized for the netstat dialect. */
const NETSTAT_HEADER = /^\s*Proto\s+Local\s+Address\s+Foreign\s+Address\s+State(\s+\S+)*\s*$/iu

/** Normalized header tokens recognized for `Get-NetTCPConnection` output. */
const POWERSHELL_HEADER = /^\s*LocalAddress\s+LocalPort\s+RemoteAddress\s+RemotePort\s+State(\s+\S+)*\s*$/iu

/** The `----` underline that PowerShell's formatting adds below a header. */
const POWERSELL_UNDERLINE = /^\s*-{3,}(\s+-{3,})*\s*$/u

/**
 * Split a `host:port` token. IPv6 arrives as `[::]:135` or `[fe80::1%12]:445`,
 * so the port is always the text after the last colon that follows a bracket.
 * @param token - address token from a socket row.
 * @returns address, port, and whether the port was numeric.
 */
export function splitEndpoint(token: string): { address: string; port: number | null; raw_port: string } {
  const bracket = /^(.*\]):([^:]*)$/u.exec(token)
  if (bracket !== null) {
    const port = parsePort(bracket[2]!)
    return { address: bracket[1]!, port, raw_port: bracket[2]! }
  }
  const index = token.lastIndexOf(':')
  if (index < 0) return { address: token, port: null, raw_port: '' }
  const port = parsePort(token.slice(index + 1))
  return { address: token.slice(0, index), port, raw_port: token.slice(index + 1) }
}

/** Parse a port token, tolerating `*` and service names. */
function parsePort(value: string): number | null {
  if (!/^\d{1,5}$/u.test(value)) return null
  const port = Number(value)
  return port >= 0 && port <= 65535 ? port : null
}

/** Join an address and port back into a display endpoint. */
function endpoint(address: string, port: number | null, raw: string): string {
  if (address.length === 0) return raw
  if (port === null && raw.length === 0) return address
  return `${address}:${port === null ? raw : port}`
}

/** Extract `[name.exe]` or `name.exe` out of a `netstat -b` continuation line. */
function processFromBracketLine(line: string): string | null {
  const match = /^\s*\[([^\]]+)\]\s*$/u.exec(line) ?? /^\[([^\]]+)\]$/u.exec(line.trim())
  return match === null ? null : match[1]!.trim()
}

/** Extract a `[name.exe]` or bare `name.exe` token embedded in a row. */
function processFromInline(text: string): string | null {
  const match = /\[([^\]]+)\]/u.exec(text)
  if (match !== null) return match[1]!.trim()
  return null
}

/**
 * Detect the dialect of a socket listing.
 * @param text - pasted output.
 */
export function detectDialect(text: string): NetstatDialect {
  const lines = text.split(/\r?\n/u)
  for (const line of lines) {
    if (NETSTAT_HEADER.test(line) && !/^\s*TCP\b/iu.test(line)) return 'netstat'
    if (POWERSHELL_HEADER.test(line) && /RemotePort/iu.test(line) && !/^\s*TCP\b/iu.test(line)) return 'powershell'
  }
  // Fall back to row shape so a headerless paste still parses. The PowerShell
  // shape is tested first because it is the stricter of the two: its third token
  // must be a bare port, while a netstat row's third token is an endpoint.
  for (const line of lines) {
    if (/^\s*(TCP|UDP)\s+\S+\s+\d+\s+\S+\s+\d+\s+\w+/iu.test(line)) return 'powershell'
    if (/^\s*(TCP|UDP)\s+\S+\s+\S+/iu.test(line)) return 'netstat'
  }
  return 'unknown'
}

/**
 * Parse a pasted `netstat -ano` / `-anob` or `Get-NetTCPConnection` listing.
 *
 * Rows whose shape is not understood are skipped and counted in `notes`; the
 * parser never throws on malformed text and never fills a field with a guess.
 * @param text - pasted listing.
 * @returns the parsed report.
 */
export function parseNetstat(text: string): NetstatReport {
  const notes: string[] = []
  const lines = text.split(/\r?\n/u)
  const dialect = detectDialect(text)
  const rows: SocketRow[] = []
  let skipped = 0
  lines.forEach((line, index) => {
    const lineNumber = index + 1
    const trimmed = line.trim()
    if (trimmed.length === 0) return
    if (POWERSELL_UNDERLINE.test(trimmed)) return
    if (POWERSHELL_HEADER.test(trimmed) || NETSTAT_HEADER.test(trimmed)) return
    if (/^(Active Connections|活动连接)/iu.test(trimmed)) return
    if (/^Proto\b/iu.test(trimmed) && !/^(TCP|UDP)\b/iu.test(trimmed)) return
    if (/^\[[^\]]+\]$/u.test(trimmed)) {
      // `netstat -b` prints the executable on its own line after the row it
      // belongs to; attach it to the most recent row that has no name yet,
      // which is the row it follows.
      const name = processFromBracketLine(trimmed)
      if (name !== null) {
        for (let i = rows.length - 1; i >= 0; i--) {
          if (rows[i]!.process_name === null) {
            rows[i]!.process_name = name
            break
          }
        }
      }
      return
    }
    const parsed = parseRow(trimmed, lineNumber, dialect)
    if (parsed === null) {
      skipped++
      return
    }
    rows.push(parsed)
  })
  if (skipped > 0) notes.push(`${skipped} line(s) did not match the ${dialect} row shape and were skipped`)

  const stateCounts = new Map<string, number>()
  const protocolCounts = new Map<string, number>()
  for (const row of rows) {
    protocolCounts.set(row.protocol, (protocolCounts.get(row.protocol) ?? 0) + 1)
    const state = row.protocol === 'udp' ? 'UDP' : row.state.length > 0 ? row.state.toUpperCase() : 'UNKNOWN'
    stateCounts.set(state, (stateCounts.get(state) ?? 0) + 1)
  }

  const listening = rows
    .filter((row) => {
      if (row.protocol === 'udp') {
        // A UDP row with a foreign address is a live flow; the ones that bind a
        // port carry `*:*` as the foreign endpoint, so that is the real test.
        return row.remote_address === '' || isWildcard(row.remote_address)
      }
      const state = row.state.toUpperCase()
      return state === 'LISTENING' || state === 'LISTEN' || state === 'BOUND'
    })
    .map((row) => ({
      protocol: row.protocol,
      address: row.local_address,
      port: row.local_port,
      pid: row.pid,
      process_name: row.process_name,
      line: row.line,
    }))

  const establishedRows = rows.filter((row) => row.state.toUpperCase() === 'ESTABLISHED')
  const groups = new Map<string, EndpointGroup>()
  for (const row of establishedRows) {
    const remote = endpoint(row.remote_address, row.remote_port, '')
    const existing = groups.get(remote)
    const local = endpoint(row.local_address, row.local_port, '')
    if (existing === undefined) {
      groups.set(remote, {
        remote,
        connections: 1,
        pids: row.pid === null ? [] : [row.pid],
        local_endpoints: [local],
        states: [row.state.toUpperCase()],
      })
      continue
    }
    existing.connections++
    if (row.pid !== null && !existing.pids.includes(row.pid)) existing.pids.push(row.pid)
    if (!existing.local_endpoints.includes(local)) existing.local_endpoints.push(local)
    if (!existing.states.includes(row.state.toUpperCase())) existing.states.push(row.state.toUpperCase())
  }
  const established = [...groups.values()].sort(
    (a, b) => b.connections - a.connections || a.remote.localeCompare(b.remote),
  )

  const duplicateBinds = findDuplicateBinds(rows)

  const limitations = [
    'whether a listening PID still exists cannot be determined from netstat text; resolve the pid separately',
    'process names are only present with `netstat -b` (often "Access denied") or from Get-NetTCPConnection -OwningProcess',
    'UDP has no connection state, so a UDP row without a foreign address is reported as a bind rather than a session',
  ]

  return {
    dialect,
    rows,
    state_counts: [...stateCounts.entries()]
      .map(([state, count]) => ({ state, count }))
      .sort((a, b) => b.count - a.count || a.state.localeCompare(b.state)),
    protocol_counts: [...protocolCounts.entries()]
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => a.protocol.localeCompare(b.protocol)),
    listening,
    established,
    duplicate_binds: duplicateBinds,
    summary: {
      tcp_rows: protocolCounts.get('tcp') ?? 0,
      udp_rows: protocolCounts.get('udp') ?? 0,
      // Both counters mean "endpoints awaiting traffic", so they count binds
      // rather than rows: a UDP row that carries a remote address is an active
      // flow, not a listener.
      listening_tcp: listening.filter((entry) => entry.protocol === 'tcp').length,
      listening_udp: listening.filter((entry) => entry.protocol === 'udp').length,
      established: establishedRows.length,
      distinct_pids: new Set(rows.map((row) => row.pid).filter((pid): pid is number => pid !== null)).size,
      ports: new Set(rows.map((row) => row.local_port).filter((port): port is number => port !== null)).size,
    },
    limitations,
    notes,
  }
}

/**
 * Parse one socket row in either dialect.
 * @param line - trimmed row text.
 * @param lineNumber - 1-based line number for reporting.
 * @param dialect - the detected dialect, used to prefer a field order.
 * @returns the row, or `null` when the line is not a socket row.
 */
function parseRow(line: string, lineNumber: number, dialect: NetstatDialect): SocketRow | null {
  const tokens = line.split(/\s+/u)
  const inlineName = processFromInline(line)
  if (dialect === 'powershell') {
    // LocalAddress LocalPort RemoteAddress RemotePort State [OwningProcess].
    // A trailing Protocol column exists in some projections, so the offset is
    // derived from the row instead of assumed.
    const offset = /^(TCP|UDP)$/iu.test(tokens[0] ?? '') ? 1 : 0
    const protocol = offset === 1 ? ((tokens[0] ?? '').toUpperCase() === 'UDP' ? 'udp' : 'tcp') : 'tcp'
    const local = tokens[offset] ?? ''
    const localPort = parsePort(tokens[offset + 1] ?? '')
    const remote = tokens[offset + 2] ?? ''
    const remotePort = parsePort(tokens[offset + 3] ?? '')
    const state = tokens[offset + 4] ?? ''
    // A PowerShell row is recognizable by a numeric local port and a state word;
    // every other line (headers, banners, footers) is not a socket row.
    if (localPort === null || !/^[A-Za-z]/u.test(state)) return null
    const numeric = tokens.filter((token) => /^\d+$/u.test(token))
    return {
      protocol,
      local_address: local,
      local_port: localPort,
      remote_address: remote,
      remote_port: remotePort,
      state,
      // The owning process is the last numeric column; columns 2 and 4 are
      // ports, so the last numeric token is the only safe rule here.
      pid: numeric.length > 0 ? Number(numeric[numeric.length - 1]) : null,
      process_name: inlineName,
      line: lineNumber,
      raw: line,
    }
  }
  const protoToken = tokens[0]?.toUpperCase() ?? ''
  if (protoToken !== 'TCP' && protoToken !== 'UDP') return null
  const protocol = protoToken === 'TCP' ? 'tcp' : 'udp'
  const numeric = tokens.filter((token) => /^\d+$/u.test(token))
  if (protocol === 'tcp') {
    // Proto Local Foreign State [Pid]
    const local = splitEndpoint(tokens[1] ?? '')
    const remote = splitEndpoint(tokens[2] ?? '')
    return {
      protocol,
      local_address: local.address,
      local_port: local.port,
      remote_address: remote.address,
      remote_port: remote.port,
      state: tokens[3] ?? '',
      pid: pidFromTokens(tokens.slice(4), numeric),
      process_name: inlineName,
      line: lineNumber,
      raw: line,
    }
  }
  // UDP rows have no state and no foreign address: Proto Local [Pid]
  const local = splitEndpoint(tokens[1] ?? '')
  return {
    protocol,
    local_address: local.address,
    local_port: local.port,
    remote_address: '',
    remote_port: null,
    state: '',
    pid: pidFromTokens(tokens.slice(2), numeric),
    process_name: inlineName,
    line: lineNumber,
    raw: line,
  }
}

/** Take the PID from a row's trailing tokens, ignoring bracketed names. */
function pidFromTokens(tokens: string[], numeric: string[]): number | null {
  for (const token of tokens) {
    if (/^\d+$/u.test(token)) return Number(token)
  }
  if (numeric.length > 0) return Number(numeric[0])
  return null
}

/**
 * Find ports bound more than once for the same protocol.
 *
 * A wildcard bind (`0.0.0.0` or `[::]`) plus a specific-address bind on the same
 * port is the classic Windows "port already in use but something still answers"
 * shape, and it is invisible unless the two rows are compared.
 * @param rows - every parsed row.
 */
export function findDuplicateBinds(rows: readonly SocketRow[]): DuplicateBind[] {
  const byKey = new Map<string, SocketRow[]>()
  for (const row of rows) {
    if (row.local_port === null) continue
    // Only binds contend for a port: a TCP row in ESTABLISHED state owns the
    // local port too, so a listener plus its own connections are not a conflict.
    const isBind = row.protocol === 'udp' || row.state.toUpperCase() === 'LISTENING' || row.state.toUpperCase() === 'LISTEN'
    if (!isBind) continue
    const key = `${row.protocol}:${row.local_port}`
    const bucket = byKey.get(key)
    if (bucket === undefined) byKey.set(key, [row])
    else bucket.push(row)
  }
  const duplicates: DuplicateBind[] = []
  for (const [key, bucket] of byKey) {
    const distinctAddresses = new Set(bucket.map((row) => row.local_address))
    if (bucket.length < 2 || distinctAddresses.size < 2) continue
    const [protocol, portText] = key.split(':')
    const pids = new Set(bucket.map((row) => row.pid).filter((pid): pid is number => pid !== null))
    duplicates.push({
      protocol: protocol as 'tcp' | 'udp',
      port: Number(portText),
      bindings: bucket.map((row) => ({
        address: row.local_address,
        pid: row.pid,
        state: row.state,
        line: row.line,
      })),
      wildcard_conflict: bucket.some((row) => isWildcard(row.local_address)),
      multi_pid: pids.size > 1,
    })
  }
  return duplicates.sort((a, b) => a.protocol.localeCompare(b.protocol) || a.port - b.port)
}

/** Whether an address is a wildcard bind. */
export function isWildcard(address: string): boolean {
  return address === '0.0.0.0' || address === '*' || address === '[::]' || address === '::' || address === '[::]%0'
}
