// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
// Ported from themis-internal `proto/pi-loop-outside` (`tools.ts`), against the real guest.
//
// Pi's seven built-in tools, each built with our operations, exercised through the seam with no
// model involved. Run inside the container: `probes/pi/run.sh tools`.

import {
  createBashToolDefinition,
  createEditToolDefinition,
  createFindToolDefinition,
  createLsToolDefinition,
  createReadToolDefinition,
  createWriteToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createSeamBashOperations } from './bash-ops.ts';
import { confined } from './confine.ts';
import { createSeamFileOperations, type FileOpStats } from './fs-ops.ts';
import { createSeamGrepToolDefinition } from './grep.ts';

const SOCKET = process.env.PI_POSTERN_SOCKET!;
const WORKSPACE = process.env.PI_POSTERN_WORKSPACE!;

type ToolLike = {
  name: string;
  execute: (id: string, params: unknown, signal: AbortSignal, onUpdate?: (u: unknown) => void) => Promise<unknown>;
};

const stats: FileOpStats = { calls: 0, backendMs: 0 };
const files = createSeamFileOperations(SOCKET, stats);
const bash = createSeamBashOperations(SOCKET);

// Seeded from inside the guest: Pi's /workspace is an empty decoy, and the real one is not on its
// side at all. `planted` is what a guest could leave behind — a symlink out of the workspace, which
// must be refused, not followed.
await bash.exec(
  "printf '# Working document\\n\\nseeded by the probe\\n' > working_document.md" +
    " && printf 'alpha\\nbeta CANARY gamma\\n' > notes.txt && ln -s /etc/hostname planted",
  WORKSPACE,
  { onData: () => {} },
);

// Pi's own tools; ours only in where the work lands.
const tools: ToolLike[] = [
  confined(WORKSPACE, createReadToolDefinition(WORKSPACE, { operations: files.read })),
  confined(WORKSPACE, createWriteToolDefinition(WORKSPACE, { operations: files.write })),
  confined(WORKSPACE, createEditToolDefinition(WORKSPACE, { operations: files.edit })),
  confined(WORKSPACE, createSeamGrepToolDefinition(WORKSPACE, SOCKET, stats)),
  confined(WORKSPACE, createFindToolDefinition(WORKSPACE, { operations: files.find })),
  confined(WORKSPACE, createLsToolDefinition(WORKSPACE, { operations: files.ls })),
  createBashToolDefinition(WORKSPACE, { operations: bash }),
] as unknown as ToolLike[];

console.log(`\nworkspace: ${WORKSPACE}`);
console.log(`tools built through the seam: ${tools.map((t) => t.name).join(', ')}\n`);

const signal = new AbortController().signal;
const call = async (name: string, params: unknown): Promise<string> => {
  const tool = tools.find((t) => t.name === name);
  if (!tool) return `NO SUCH TOOL ${name}`;
  try {
    // Pi's tool ABI is positional: (toolCallId, params, signal, onUpdate, ctx).
    const result = (await tool.execute(`call-${name}`, params, signal, () => {})) as {
      content?: { text?: string }[];
    };
    return (result.content?.[0]?.text ?? JSON.stringify(result)).trim().split('\n').slice(0, 3).join(' | ');
  } catch (error) {
    return `refused: ${(error as Error).message.trim().split('\n')[0]}`;
  }
};

const started = performance.now();
console.log('exercising each tool through the socket:');
console.log(`  read    ${await call('read', { path: 'working_document.md' })}`);
console.log(`  write   ${await call('write', { path: 'new.md', content: 'written through the seam\n' })}`);
const edits = [{ oldText: 'alpha', newText: 'ALPHA' }];
console.log(`  edit    ${await call('edit', { path: 'notes.txt', edits })}`);
console.log(`  grep    ${await call('grep', { pattern: 'CANARY' })}`);
console.log(`  grep -C ${await call('grep', { pattern: 'beta', context: 1, glob: '*.txt' })}`);
console.log(`  find    ${await call('find', { pattern: '*.md' })}`);
console.log(`  ls      ${await call('ls', { path: '.' })}`);
console.log(`  bash    ${await call('bash', { command: 'echo from-the-guest; id -u; pwd' })}`);
// The guest's userland is its own rootfs: its tools are there, the trusted side's are not.
const userland = 'for c in python3 git rg node pi; do command -v $c >/dev/null && echo -n "$c " || echo -n "!$c "; done;' +
  ' python3 -c "import postern" 2>/dev/null && echo postern || echo !postern';
console.log(`  bash    ${await call('bash', { command: userland })}`);
const elapsed = performance.now() - started;

// Pi's own grep would have spawned rg on this side; there must be none here to spawn.
const hostRg = [process.env.PATH ?? '', join(process.env.PI_AGENT_DIR ?? '', 'bin')]
  .flatMap((dirs) => dirs.split(':'))
  .some((dir) => dir && existsSync(join(dir, 'rg')));
console.log(`\nrg on Pi's side: ${hostRg ? 'PRESENT' : 'absent'} — grep ran in the guest`);
const decoy = readdirSync(WORKSPACE);
console.log(`Pi's ${WORKSPACE}: ${decoy.length ? `NOT EMPTY (${decoy.join(', ')})` : 'empty'} — the files above are the guest's alone`);

console.log('\ndoes anything confine a path to the workspace?');
for (const escape of ['../escaped.txt', '/etc/hosts', 'planted']) {
  console.log(`  read ${escape.padEnd(16)} ${await call('read', { path: escape })}`);
}
console.log(`  grep /etc            ${await call('grep', { pattern: 'root', path: '/etc' })}`);
// `planted` points at /etc/hostname: a walk that followed it would match the container's hostname.
console.log(`  grep . (via planted) ${await call('grep', { pattern: '.', glob: 'planted' })}`);

console.log(`\nseven tool calls in ${elapsed.toFixed(0)} ms; ` +
  `${stats.calls} file primitives served, ${stats.backendMs.toFixed(1)} ms of that in the guest`);
// Pi's bash tool, called the way its loop calls it: an onUpdate callback for partial output, an
// AbortSignal for the user's interrupt, and the model's own `timeout`. What the model is told comes
// from how our operations settle, so this is where a contract mismatch would show.
console.log("\nPi's bash tool, as its loop drives it:");
const bashTool = tools.find((t) => t.name === 'bash')!;
const drive = async (params: unknown, abortAfterMs?: number) => {
  const controller = new AbortController();
  if (abortAfterMs !== undefined) setTimeout(() => controller.abort(), abortAfterMs);
  const updates: number[] = [];
  const started = performance.now();
  let text: string;
  try {
    const result = (await bashTool.execute('drive', params, controller.signal, () => {
      updates.push(performance.now() - started);
    })) as { content?: { text?: string }[] };
    text = result.content?.[0]?.text ?? '';
  } catch (error) {
    text = (error as Error).message;
  }
  const said = text.trim().split('\n').filter(Boolean).slice(-2).join(' | ');
  return { ms: performance.now() - started, updates, said };
};
const streamed = await drive({ command: 'for i in 1 2 3 4 5; do echo $i; sleep 0.2; done' });
// The first onUpdate is Pi clearing the pane before anything runs; the rest carry output.
const partial = streamed.updates.slice(1);
console.log(`  streaming  ${partial.length} partial update(s) during a ${streamed.ms.toFixed(0)} ms command, ` +
  `first at ${partial[0]?.toFixed(0) ?? '-'} ms`);
const aborted = await drive({ command: 'trap "echo cleaning-up; exit 3" TERM; echo started; sleep 5 & wait' }, 300);
console.log(`  abort      returned in ${aborted.ms.toFixed(0)} ms: ${aborted.said}`);
const timedOut = await drive({ command: 'echo started; sleep 5', timeout: 1 });
console.log(`  timeout=1  returned in ${timedOut.ms.toFixed(0)} ms: ${timedOut.said}`);

console.log('\nnot provided here, and not provided by Pi at all:');
console.log('  web_search, web_fetch — would be first-party tools over an HttpHatch\n');
