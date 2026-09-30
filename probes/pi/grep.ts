// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
//
// Pi's grep, with the search in the guest. Unlike the other six, `createGrepTool(cwd, { operations })`
// only uses its operations for `isDirectory` on the root and `readFile` for context lines: the search
// itself is `ensureTool('rg')` — which downloads ripgrep from GitHub if it is missing — spawned on
// the host (0.85.1, `dist/core/tools/grep.js`). Supplying operations therefore cannot move it, so
// this keeps grep's identity (name, description, schema) and replaces its `execute`, the way Pi's
// Gondolin example does. The executor runs the search in the guest; this only formats, matching the
// output of Pi's own grep line for line.

import {
  createGrepToolDefinition,
  DEFAULT_MAX_BYTES,
  formatSize,
  type GrepToolDetails,
  type GrepToolInput,
  truncateHead,
  truncateLine,
} from '@earendil-works/pi-coding-agent';
import { resolve } from 'node:path';
import { type FileOpStats, request } from './fs-ops.ts';

const DEFAULT_LIMIT = 100;
// Pi's `GREP_MAX_LINE_LENGTH`: declared in its types, absent from its runtime exports.
const GREP_MAX_LINE_LENGTH = 500;

type GuestMatch = { path: string; block: [line: number, text: string, isMatch: boolean][] };

export function createSeamGrepToolDefinition(workspace: string, socketPath: string, stats?: FileOpStats) {
  const definition = createGrepToolDefinition(workspace);
  return {
    ...definition,
    async execute(_toolCallId: string, params: GrepToolInput, signal: AbortSignal | undefined) {
      if (signal?.aborted) throw new Error('Operation aborted');
      const limit = Math.max(1, params.limit ?? DEFAULT_LIMIT);
      const { matches, limitReached } = (await request(
        socketPath,
        {
          op: 'grep',
          path: resolve(workspace, params.path || '.'),
          pattern: params.pattern,
          glob: params.glob,
          ignoreCase: params.ignoreCase ?? false,
          literal: params.literal ?? false,
          context: params.context && params.context > 0 ? params.context : 0,
          limit,
        },
        stats,
      )) as { matches: GuestMatch[]; limitReached: boolean };
      if (signal?.aborted) throw new Error('Operation aborted');
      if (matches.length === 0) return { content: [{ type: 'text' as const, text: 'No matches found' }], details: undefined };

      let linesTruncated = false;
      const outputLines: string[] = [];
      for (const { path, block } of matches) {
        for (const [line, text, isMatch] of block) {
          const { text: shown, wasTruncated } = truncateLine(text);
          linesTruncated ||= wasTruncated;
          outputLines.push(isMatch ? `${path}:${line}: ${shown}` : `${path}-${line}- ${shown}`);
        }
      }

      // From here on, Pi's own grep verbatim: byte truncation, then the notices.
      const truncation = truncateHead(outputLines.join('\n'), { maxLines: Number.MAX_SAFE_INTEGER });
      let output = truncation.content;
      const details: GrepToolDetails = {};
      const notices: string[] = [];
      if (limitReached) {
        notices.push(`${limit} matches limit reached. Use limit=${limit * 2} for more, or refine pattern`);
        details.matchLimitReached = limit;
      }
      if (truncation.truncated) {
        notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
        details.truncation = truncation;
      }
      if (linesTruncated) {
        notices.push(`Some lines truncated to ${GREP_MAX_LINE_LENGTH} chars. Use read tool to see full lines`);
        details.linesTruncated = true;
      }
      if (notices.length > 0) output += `\n\n[${notices.join('. ')}]`;
      return {
        content: [{ type: 'text' as const, text: output }],
        details: Object.keys(details).length > 0 ? details : undefined,
      };
    },
  };
}
