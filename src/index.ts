/**
 * dsh-win-native — the Windows correctness layer for DeepSeek Harness.
 *
 * Registers encoding detection and conversion, Windows path legality analysis,
 * `netstat` interpretation, and bounded read-only directory inspection. Every
 * tool is local: no network, no telemetry, no credential access. The filesystem
 * tools read and never write; every budget refusal and every skipped or
 * unreadable entry is reported rather than hidden.
 * @module dsh-win-native
 */
import type { Context } from '@deepseek-ai/cordis'
import { Config, resolveLimits } from './limits.ts'
import { createTools } from './tools.ts'

export const name = 'win-native'

/** Requires the tool registry before `apply` runs. */
export const inject = ['tools']

export { Config }
export type { Config as WinNativeConfig } from './limits.ts'
export { resolveLimits, DEFAULT_LIMITS } from './limits.ts'
export type { Limits } from './limits.ts'
export { createTools, defineReceiptTool, compileParameters } from './tools.ts'
export type { ToolBody, ToolFactoryOptions, ToolGroup } from './tools.ts'

/**
 * Register every enabled tool. Registration is effect-based, so unloading the
 * plugin unregisters the tools.
 * @param ctx - plugin context.
 * @param config - user configuration.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const limits = resolveLimits(config)
  const only = config.only ?? []
  const prefix = config.toolPrefix ?? ''
  for (const definition of createTools({ limits, prefix, only })) {
    ctx.tools.register(definition)
  }
}
