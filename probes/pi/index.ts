// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
// Ported from themis-internal `proto/pi-vm` (`prototypes/pi_vm/extension/index.ts`), minus the
// Analysis-specific system prompt.
//
// The extension that puts Pi's built-in tools inside the postern guest. Pi runs outside, holding the
// model credential; every tool it calls crosses a Unix socket to `executor.py`, which runs it in a
// guest with an empty network namespace.
//
// Shaped after Pi's own Gondolin example (`examples/extensions/gondolin`), which routes the same
// seven tools into a micro-VM. Registering a tool under a built-in's name replaces it, and each
// factory already yields the built-in's name, description and schema — so what the model sees is
// Pi's own tool set, ours only in where the work lands.
//
// Pi resolves a tool's path and hands it over without confining it to the workspace. The check that
// matters is the executor's, on the trusted side; `confined` only keeps Pi's own local probes of a
// path (see `confine.ts`) off anything outside the workspace.

import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import {
  createBashTool,
  createEditTool,
  createFindTool,
  createLsTool,
  createReadTool,
  createWriteTool,
} from '@earendil-works/pi-coding-agent';
import { createSeamBashOperations } from './bash-ops.ts';
import { confined } from './confine.ts';
import { createSeamFileOperations } from './fs-ops.ts';
import { createSeamGrepToolDefinition } from './grep.ts';

/** Set by `entrypoint.sh`; there is no default, because a default would be a tool running on the host. */
function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is unset: refusing to run tools outside the sandbox`);
  return value;
}

export default function activate(pi: ExtensionAPI): void {
  const socket = required('PI_POSTERN_SOCKET');
  const workspace = required('PI_POSTERN_WORKSPACE');
  const files = createSeamFileOperations(socket);
  const bash = createSeamBashOperations(socket);

  // Every built-in that touches the filesystem or runs a command. A tool left off this list keeps
  // Pi's default operations and runs on the host, beside the model credential — so the list is the
  // whole boundary. Registered one by one rather than over a list: each factory's parameter schema is
  // its own type, and a list of them unifies to something `registerTool` will not take.
  pi.registerTool(confined(workspace, createReadTool(workspace, { operations: files.read })));
  pi.registerTool(confined(workspace, createWriteTool(workspace, { operations: files.write })));
  pi.registerTool(confined(workspace, createEditTool(workspace, { operations: files.edit })));
  pi.registerTool(confined(workspace, createSeamGrepToolDefinition(workspace, socket)));
  pi.registerTool(confined(workspace, createFindTool(workspace, { operations: files.find })));
  pi.registerTool(confined(workspace, createLsTool(workspace, { operations: files.ls })));
  pi.registerTool(createBashTool(workspace, { operations: bash }));

  // `!command` in the TUI is the user's own shell, and it goes to the same place the agent's does.
  pi.on('user_bash', async () => ({ operations: bash }));

  pi.on('before_agent_start', async (event) => ({
    systemPrompt: `${event.systemPrompt}\n\nYour tools run inside a postern sandbox. Its working directory is ${workspace}; it has no network.`,
  }));

  pi.registerCommand('sandbox', {
    description: 'Where this session’s tools actually run',
    handler: async (_args, ctx) => {
      ctx.ui.notify(`postern guest\nworkspace: ${workspace}\nexecutor:  ${socket}`, 'info');
    },
  });
}
