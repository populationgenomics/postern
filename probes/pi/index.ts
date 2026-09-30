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
  createBashToolDefinition,
  createEditToolDefinition,
  createFindToolDefinition,
  createLsToolDefinition,
  createReadToolDefinition,
  createWriteToolDefinition,
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

type EditDefinition = ReturnType<typeof createEditToolDefinition>;

/**
 * The edit tool, without the preview its renderer computes before the call runs.
 *
 * That preview (`computeEditsDiff`) reads the target file *locally*, ignoring the operations, and
 * with any path the model named. Rendering the call as though its arguments were still streaming
 * skips it; the diff Pi shows once the call returns is the result's, computed in the guest.
 */
function withoutLocalPreview(edit: EditDefinition): EditDefinition {
  const renderCall = edit.renderCall;
  if (!renderCall) return edit;
  return { ...edit, renderCall: (args, theme, context) => renderCall(args, theme, { ...context, argsComplete: false }) };
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
  //
  // The `…ToolDefinition` factories, not `createReadTool` and friends: those wrap the definition
  // into an `AgentTool`, which drops `promptSnippet`, `promptGuidelines` and the renderers, so a
  // tool registered from one reaches the model with less guidance than Pi's built-in of the same name.
  pi.registerTool(confined(workspace, createReadToolDefinition(workspace, { operations: files.read })));
  pi.registerTool(confined(workspace, createWriteToolDefinition(workspace, { operations: files.write })));
  pi.registerTool(confined(workspace, withoutLocalPreview(createEditToolDefinition(workspace, { operations: files.edit }))));
  pi.registerTool(confined(workspace, createSeamGrepToolDefinition(workspace, socket)));
  pi.registerTool(confined(workspace, createFindToolDefinition(workspace, { operations: files.find })));
  pi.registerTool(confined(workspace, createLsToolDefinition(workspace, { operations: files.ls })));
  pi.registerTool(createBashToolDefinition(workspace, { operations: bash }));

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
