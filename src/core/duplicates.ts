/**
 * Read-only duplicate detection with an explicit hashing budget.
 *
 * The algorithm is the standard three-stage one — group by size, drop singleton
 * sizes, hash only what remains — because size grouping is what makes the byte
 * budget affordable: on a typical tree it removes the vast majority of files
 * before a single byte is read. Every file that could not be read is reported,
 * never dropped, because "no duplicates found" over a half-readable tree is a
 * dangerously wrong answer.
 * @module dsh-win-native/core/duplicates
 */
import { createHash } from 'node:crypto'
import { createReadStream, lstat, opendir, type Dirent, type Stats } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'

const openDir = promisify(opendir)
const lstatAsync = promisify(lstat)

/** Budgets for one duplicate scan. */
export interface DuplicateOptions {
  /** Maximum files collected by the walk. */
  maxFiles: number
  /** Maximum directory depth below the root. */
  maxDepth: number
  /** Maximum total bytes fed through the hash function. */
  maxBytesHashed: number
  /** Cancellation signal, checked between files. */
  signal: AbortSignal
  /** How many unreadable paths to report. */
  maxErrors: number
}

/** One candidate file, before hashing. */
export interface CandidateFile {
  /** Absolute path. */
  path: string
  /** Size in bytes, used for the initial grouping. */
  size: number
}

/** One group of byte-identical files. */
export interface DuplicateGroup {
  /** SHA-256 of the shared content, hex encoded. */
  hash: string
  /** Size of every file in the group, in bytes. */
  size: number
  /** How many copies exist. */
  count: number
  /** Bytes reclaimable by keeping one copy. */
  reclaimable: number
  /** Every path in the group, sorted. */
  paths: string[]
}

/** A path that could not be read during the scan. */
export interface UnreadableFile {
  /** The path. */
  path: string
  /** Node error code, for example `EACCES`, `EBUSY`, `EPERM`. */
  code: string
  /** Node error message. */
  message: string
  /** Stage that failed: `stat`, `read`, or `list`. */
  stage: 'stat' | 'read' | 'list'
}

/** Result of a duplicate scan. */
export interface DuplicateReport {
  /** Directory that was scanned. */
  root: string
  /** Duplicate groups, largest reclaimable first. */
  groups: DuplicateGroup[]
  /** Total bytes reclaimable across every group. */
  reclaimable_bytes: number
  /** Number of files that had at least one same-size sibling. */
  candidates_hashed: number
  /** Number of files read and hashed. */
  files_hashed: number
  /** Bytes fed through SHA-256. */
  bytes_hashed: number
  /** Files collected before stage one. */
  files_seen: number
  /** Paths that could not be read, with the error code. */
  unreadable: UnreadableFile[]
  /** Whether a budget stopped the scan early. */
  truncated: boolean
  /** Budget and coverage notes. */
  notes: string[]
}

/** Normalize any thrown value into an unreadable record. */
function toUnreadable(path: string, stage: UnreadableFile['stage'], error: unknown): UnreadableFile {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code: unknown }).code) : 'UNKNOWN'
  const message = error instanceof Error ? error.message : String(error)
  return { path, code, message, stage }
}

/** Yield to the event loop so a long scan cannot stall the host. */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve)
  })
}

/** Open a directory without a synchronous full-tree scan. */
function openDirectory(path: string): ReturnType<typeof openDir> {
  return openDir(path)
}

/** Stat a path without following a symlink, so a link is never counted as its target. */
function lstatPath(path: string): Promise<Stats> {
  return lstatAsync(path)
}

/**
 * Stream one file through SHA-256 without buffering it.
 *
 * Streaming is what keeps the tool inside a sane memory footprint on a tree with
 * multi-gigabyte files; the read stream is destroyed as soon as it emits an
 * error so a broken file cannot leak a descriptor.
 * @param path - file to hash.
 * @param signal - cancellation signal.
 * @returns hex digest and bytes consumed, or the error that stopped it.
 */
export function hashFile(
  path: string,
  signal: AbortSignal,
): Promise<{ ok: true; digest: string; bytes: number } | { ok: false; error: unknown }> {
  return new Promise((resolve) => {
    const hash = createHash('sha256')
    let bytes = 0
    const stream = createReadStream(path)
    const onAbort = (): void => {
      stream.destroy()
    }
    signal.addEventListener('abort', onAbort, { once: true })
    stream.on('data', (chunk) => {
      bytes += chunk.length
      hash.update(chunk)
    })
    stream.on('error', (error) => {
      signal.removeEventListener('abort', onAbort)
      stream.destroy()
      resolve({ ok: false, error })
    })
    stream.on('end', () => {
      signal.removeEventListener('abort', onAbort)
      resolve({ ok: true, digest: hash.digest('hex'), bytes })
    })
  })
}

/**
 * Collect every regular file below a root, read-only.
 * @param root - absolute directory.
 * @param options - budgets and cancellation.
 * @returns candidates, unreadable paths, and coverage notes.
 */
export async function collectFiles(
  root: string,
  options: { maxFiles: number; maxDepth: number; signal: AbortSignal; maxErrors: number },
): Promise<{ files: CandidateFile[]; unreadable: UnreadableFile[]; truncated: boolean; notes: string[] }> {
  const files: CandidateFile[] = []
  const unreadable: UnreadableFile[] = []
  const notes: string[] = []
  let truncated = false
  const queue: { path: string; depth: number }[] = [{ path: root, depth: 0 }]
  let processed = 0
  while (queue.length > 0) {
    const current = queue.shift()!
    let directory: Awaited<ReturnType<typeof openDir>>
    try {
      directory = await openDirectory(current.path)
    } catch (error) {
      unreadable.push(toUnreadable(current.path, 'list', error))
      continue
    }
    try {
      for await (const entry of directory as AsyncIterable<Dirent>) {
        options.signal.throwIfAborted()
        if (truncated) break
        processed++
        if (processed % 64 === 0) await yieldToEventLoop()
        const childPath = join(current.path, entry.name)
        if (entry.isSymbolicLink()) {
          notes.push(`skipped reparse point ${childPath}; duplicates behind a junction are not counted`)
          continue
        }
        if (entry.isDirectory()) {
          if (current.depth + 1 > options.maxDepth) {
            truncated = true
            notes.push(`depth budget maxDepth=${options.maxDepth} reached; deeper directories were not scanned`)
            continue
          }
          queue.push({ path: childPath, depth: current.depth + 1 })
          continue
        }
        if (!entry.isFile()) continue
        if (files.length >= options.maxFiles) {
          truncated = true
          notes.push(`file budget maxFiles=${options.maxFiles} reached; the duplicate list is a lower bound`)
          break
        }
        try {
          const stats = await lstatPath(childPath)
          files.push({ path: childPath, size: stats.size })
        } catch (error) {
          if (unreadable.length < options.maxErrors) unreadable.push(toUnreadable(childPath, 'stat', error))
        }
      }
    } catch (error) {
      unreadable.push(toUnreadable(current.path, 'list', error))
    }
    if (truncated) break
  }
  return { files, unreadable, truncated, notes }
}

/**
 * Find byte-identical files below a root.
 *
 * Only files that share a size are hashed, and hashing stops at
 * `maxBytesHashed`. A file that is skipped because of the byte budget is not
 * silently dropped: it is counted in `notes` and reflected in `truncated`, so
 * the caller can tell "no duplicates" from "no duplicates among what I read".
 * @param root - absolute directory.
 * @param options - budgets and cancellation.
 * @returns duplicate groups, reclaimable bytes, and full coverage accounting.
 */
export async function findDuplicates(root: string, options: DuplicateOptions): Promise<DuplicateReport> {
  const collected = await collectFiles(root, {
    maxFiles: options.maxFiles,
    maxDepth: options.maxDepth,
    signal: options.signal,
    maxErrors: options.maxErrors,
  })
  const notes = [...collected.notes]
  const unreadable = [...collected.unreadable]
  let truncated = collected.truncated

  const bySize = new Map<number, CandidateFile[]>()
  for (const file of collected.files) {
    const bucket = bySize.get(file.size)
    if (bucket === undefined) bySize.set(file.size, [file])
    else bucket.push(file)
  }
  // Empty files are all "identical"; grouping them is technically correct but
  // useless, so they are reported as a note instead of a group.
  const emptyCount = bySize.get(0)?.length ?? 0
  if (emptyCount > 1) notes.push(`${emptyCount} zero-byte files share a size but carry no content; not reported as duplicates`)

  const candidates: CandidateFile[] = []
  for (const [size, bucket] of bySize) {
    if (size === 0) continue
    if (bucket.length < 2) continue
    candidates.push(...bucket)
  }

  const byHash = new Map<string, CandidateFile[]>()
  let bytesHashed = 0
  let filesHashed = 0
  let byteBudgetHit = false
  for (const file of candidates) {
    options.signal.throwIfAborted()
    if (bytesHashed + file.size > options.maxBytesHashed) {
      byteBudgetHit = true
      continue
    }
    const result = await hashFile(file.path, options.signal)
    if (!result.ok) {
      if (unreadable.length < options.maxErrors) unreadable.push(toUnreadable(file.path, 'read', result.error))
      continue
    }
    bytesHashed += result.bytes
    filesHashed++
    const bucket = byHash.get(result.digest)
    if (bucket === undefined) byHash.set(result.digest, [file])
    else bucket.push(file)
  }
  if (byteBudgetHit) {
    truncated = true
    notes.push(
      `hashing byte budget maxBytesHashed=${options.maxBytesHashed} reached; same-size files that were not hashed may or may not be duplicates`,
    )
  }

  const groups: DuplicateGroup[] = []
  for (const [hash, bucket] of byHash) {
    if (bucket.length < 2) continue
    const size = bucket[0]!.size
    groups.push({
      hash,
      size,
      count: bucket.length,
      reclaimable: size * (bucket.length - 1),
      paths: bucket.map((file) => file.path).sort(),
    })
  }
  groups.sort((a, b) => b.reclaimable - a.reclaimable || a.hash.localeCompare(b.hash))

  const reclaimable = groups.reduce((sum, group) => sum + group.reclaimable, 0)
  if (collected.files.length > candidates.length) {
    notes.push(`${collected.files.length - candidates.length} file(s) had a unique size and needed no hashing`)
  }
  if (unreadable.length > 0) notes.push(`${unreadable.length} path(s) could not be read and are reported in \`unreadable\``)
  if (unreadable.length >= options.maxErrors) notes.push(`unreadable list clipped to ${options.maxErrors} entries`)
  return {
    root,
    groups,
    reclaimable_bytes: reclaimable,
    candidates_hashed: candidates.length,
    files_hashed: filesHashed,
    bytes_hashed: bytesHashed,
    files_seen: collected.files.length,
    unreadable,
    truncated,
    notes,
  }
}
