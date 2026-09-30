// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
//
// Refuse a path outside the workspace before Pi's own code sees it. Our operations are not the only
// thing a file tool does with its path: in 0.85.1 `read` stat-probes it locally for macOS filename
// variants (`resolveReadPathAsync`), and `write`/`edit` `realpath` it locally to key their mutation
// queue. Pi's `/workspace` is an empty directory (`entrypoint.sh`), so for a path inside it those
// probes find nothing. For `/etc/hosts` they would find the host's, so this refuses first.
//
// The executor refuses the same paths anyway; this is so Pi never touches them, not the boundary.

import { homedir } from 'node:os';
import { resolve } from 'node:path';

/** Pi's own resolution (`resolveToCwd`), conservatively: strip a leading `@`, expand `~`, resolve. */
export function confine(workspace: string, path: string | undefined): void {
  let named = (path || '.').replace(/^@/, '');
  if (named === '~' || named.startsWith('~/')) named = homedir() + named.slice(1);
  const absolute = resolve(workspace, named);
  if (absolute !== workspace && !absolute.startsWith(`${workspace}/`)) {
    throw new Error(`ConfinedError: ${path} resolves to ${absolute}, outside the workspace ${workspace}`);
  }
}

type Executes = { execute: (toolCallId: string, params: any, ...rest: any[]) => any };

/** `tool`, refusing before it runs any call whose `path` leaves the workspace. */
export function confined<T extends Executes>(workspace: string, tool: T): T {
  return {
    ...tool,
    execute: (toolCallId: string, params: { path?: string }, ...rest: unknown[]) => {
      confine(workspace, params?.path);
      return tool.execute(toolCallId, params, ...rest);
    },
  };
}
