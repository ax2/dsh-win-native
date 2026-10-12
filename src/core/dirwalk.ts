/**
 * Bounded, read-only directory accounting.
 *
 * Two rules shape this module. First, it never writes: no temp files, no
 * indexes, no caches. Second, it never lies about what it skipped — a reparse
 * point that was not followed, a budget that stopped the walk, and a file that
 * could not be stat'ed are all reported as data, because a directory total that
 * silently omits an entire junction target is worse than no total at all.
 * @module dsh-win-native/core/dirwalk
 */
import { lstat, opendir, type Dirent, type Stats } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'

const openDir = promisify(opendir)
const lstatAsync = promisify(lstat)

/** Budgets and safety knobs for one walk. */
export interface WalkOptions {
  /** Maximum files accounted before the walk stops early. */
  maxFiles: number
  /** Maximum directory depth below the root; the root's own children are depth 1, so `1` accounts only the root's files. */
  maxDepth: number
  /** Maximum total bytes accounted before the walk stops early. */
  maxBytes: number
  /** How many of the largest files to return. */
  topN: number
  /** How many unreadable entries to report. */
  maxErrors: number
  /** Cancellation signal, checked between entries. */
  signal: AbortSignal
}

/** One file accounted during a walk. */
export interface WalkFile {
  /** Path as walked. */
  path: string
  /** Size in bytes. */
  size: number
  /** Depth below the root, the root's own children being 1. */
  depth: number
}

/** A path that was deliberately not followed. */
export interface SkippedLink {
  /** Path of the reparse point. */
  path: string
  /** Depth below the root. */
  depth: number
  /** Why it was skipped. */
  reason: string
}

/** An entry that could not be inspected. */
export interface WalkError {
  /** Path that failed. */
  path: string
  /** Node error code, for example `EACCES` or `ENOENT`. */
  code: string
  /** Node error message. */
  message: string
}

/** Result of one bounded walk. */
export interface WalkResult {
  /** Root that was walked. */
  root: string
  /** Total bytes of the files that were accounted. */
  total_bytes: number
  /** Files accounted. */
  files: number
  /** Directories entered. */
  directories: number
  /** Largest files, descending by size. */
  largest: WalkFile[]
  /** File count and byte total per extension, descending by bytes. */
  extensions: { extension: string; files: number; bytes: number }[]
  /** Reparse points that were not followed. */
  skipped_links: SkippedLink[]
  /** Entries that could not be inspected. */
  unreadable: WalkError[]
  /** Whether a budget stopped the walk before it finished. */
  truncated: boolean
  /** Budget notes, in the order the budgets were hit. */
  notes: string[]
}

/** Whether a directory entry is a symlink, junction, or other reparse point. */
export function isReparsePoint(entry: Dirent | Stats): boolean {
  return entry.isSymbolicLink()
}

/** Lower-cased extension including the dot, or `(none)`. */
export function extensionOf(path: string): string {
  const base = path.slice(Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/')) + 1)
  const dot = base.lastIndexOf('.')
  // `dot <= 0` covers both an extensionless name and a leading dot (a hidden-file
  // marker on POSIX); `dot === base.length - 1` rejects a name that merely ends
  // in a dot, which Win32 strips anyway.
  if (dot <= 0 || dot === base.length - 1) return '(none)'
  return base.slice(dot).toLowerCase()
}

/** Normalize any thrown value into a reported error. */
function toWalkError(path: string, error: unknown): WalkError {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code: unknown }).code) : 'UNKNOWN'
  const message = error instanceof Error ? error.message : String(error)
  return { path, code, message }
}

/** Open a directory without blocking on a synchronous scan of a huge tree. */
function openDirectory(path: string): ReturnType<typeof openDir> {
  return openDir(path)
}

/**
 * Stat a path without following a symlink.
 *
 * `lstat` rather than `stat` is load-bearing here: the size of a link is not the
 * size of its target, and following one would silently double-count a tree.
 */
function lstatPath(path: string): Promise<Stats> {
  return lstatAsync(path)
}

/** Yield to the event loop so a long walk cannot stall the host. */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve)
  })
}

/**
 * Walk a directory tree, read-only, within explicit budgets.
 *
 * The loop yields to the event loop every `yieldEvery` entries and checks the
 * abort signal every entry, so a caller can cancel a walk over a large tree
 * instead of waiting for it to finish.
 * @param root - absolute directory to walk.
 * @param options - budgets, top-N size, and cancellation.
 * @returns totals, largest files, extension histogram, and everything skipped.
 */
export async function walkDirectory(root: string, options: WalkOptions): Promise<WalkResult> {
  // Check before doing any work: a walk that was cancelled before it started must
  // not open the root at all.
  options.signal.throwIfAborted()
  const notes: string[] = []
  const largest: WalkFile[] = []
  const extensionTotals = new Map<string, { files: number; bytes: number }>()
  const skippedLinks: SkippedLink[] = []
  const unreadable: WalkError[] = []
  let totalBytes = 0
  let files = 0
  let directories = 1
  let truncated = false
  let processed = 0
  const yieldEvery = 64

  /** Insert into the bounded top-N list. */
  const track = (file: WalkFile): void => {
    largest.push(file)
    largest.sort((a, b) => b.size - a.size || a.path.localeCompare(b.path))
    if (largest.length > options.topN) largest.length = options.topN
  }

  /** Report a reason the walk stopped. */
  const stop = (reason: string): void => {
    truncated = true
    notes.push(reason)
  }

  const queue: { path: string; depth: number }[] = [{ path: root, depth: 0 }]
  while (queue.length > 0) {
    const current = queue.shift()!
    let directory: Awaited<ReturnType<typeof openDir>>
    try {
      directory = await openDirectory(current.path)
    } catch (error) {
      unreadable.push(toWalkError(current.path, error))
      if (current.depth === 0) {
        notes.push(`the root directory itself could not be opened; the totals describe nothing`)
        truncated = true
        break
      }
      continue
    }
    try {
      for await (const entry of directory as AsyncIterable<Dirent>) {
        options.signal.throwIfAborted()
        if (truncated) break
        processed++
        if (processed % yieldEvery === 0) await yieldToEventLoop()
        const childPath = join(current.path, entry.name)
        const childDepth = current.depth + 1
        if (entry.isSymbolicLink()) {
          // Following a junction can leave the requested tree entirely (and on
          // Windows can loop), so it is always skipped and always reported.
          skippedLinks.push({ path: childPath, depth: childDepth, reason: 'symbolic link or reparse point; not followed' })
          continue
        }
        if (entry.isDirectory()) {
          if (childDepth >= options.maxDepth) {
            // Entering this directory would put its files one level past the
            // budget, so the walk stops at the directory instead of descending
            // into children that could never be accounted.
            stop(`depth budget maxDepth=${options.maxDepth} reached; deeper directories were not entered`)
            continue
          }
          directories++
          queue.push({ path: childPath, depth: childDepth })
          continue
        }
        if (!entry.isFile()) {
          skippedLinks.push({ path: childPath, depth: childDepth, reason: 'not a regular file (device, socket or fifo)' })
          continue
        }
        if (files >= options.maxFiles) {
          stop(`file budget maxFiles=${options.maxFiles} reached; the totals are a lower bound`)
          break
        }
        let stats: Stats
        try {
          stats = await lstatPath(childPath)
        } catch (error) {
          if (unreadable.length < options.maxErrors) unreadable.push(toWalkError(childPath, error))
          continue
        }
        const size = stats.size
        if (totalBytes + size > options.maxBytes) {
          stop(`byte budget maxBytes=${options.maxBytes} reached; the totals are a lower bound`)
          break
        }
        totalBytes += size
        files++
        const file: WalkFile = { path: childPath, size, depth: childDepth }
        track(file)
        const extension = extensionOf(childPath)
        const bucket = extensionTotals.get(extension) ?? { files: 0, bytes: 0 }
        bucket.files++
        bucket.bytes += size
        extensionTotals.set(extension, bucket)
      }
    } catch (error) {
      // A directory can fail mid-iteration (permissions revoked, drive removed).
      unreadable.push(toWalkError(current.path, error))
    }
    if (truncated) break
  }
  if (unreadable.length >= options.maxErrors) {
    notes.push(`unreadable list clipped to ${options.maxErrors} entries`)
  }
  if (skippedLinks.length > 0) notes.push(`${skippedLinks.length} reparse point(s) or special files were skipped, never followed`)
  return {
    root,
    total_bytes: totalBytes,
    files,
    directories,
    largest,
    extensions: [...extensionTotals.entries()]
      .map(([extension, totals]) => ({ extension, files: totals.files, bytes: totals.bytes }))
      .sort((a, b) => b.bytes - a.bytes || a.extension.localeCompare(b.extension)),
    skipped_links: skippedLinks,
    unreadable,
    truncated,
    notes,
  }
}
