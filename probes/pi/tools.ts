// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
// Ported from themis-internal `proto/pi-loop-outside` (`tools.ts`), against the real guest.
//
// Pi's seven built-in tools, each built with our operations, exercised through the seam with no
// model involved. Run inside the container: `probes/pi/run.sh tools`.

import {
  createBashTool,
  createEditTool,
  createFindTool,
  createLsTool,
  createReadTool,
  createWriteTool,
} from '@earendil-works/pi-coding-agent';
import { existsSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createSeamBashOperations } from './bash-ops.ts';
import { createSeamFileOperations, type FileOpStats } from './fs-ops.ts';
import { createSeamGrepToolDefinition } from './grep.ts';

const SOCKET = process.env.PI_POSTERN_SOCKET!;
const WORKSPACE = process.env.PI_POSTERN_WORKSPACE!;

type ToolLike = {
  name: string;
  execute: (id: string, params: unknown, signal: AbortSignal, onUpdate?: (u: unknown) => void) => Promise<unknown>;
};

// Seeded from the host side, as a caller restoring a workspace would.
writeFileSync(join(WORKSPACE, 'working_document.md'), '# Working document\n\nseeded by the probe\n');
writeFileSync(join(WORKSPACE, 'notes.txt'), 'alpha\nbeta CANARY gamma\n');
// What a guest could plant: a symlink out of the workspace. It must be refused, not followed.
symlinkSync('/etc/hostname', join(WORKSPACE, 'planted'));

const stats: FileOpStats = { calls: 0, backendMs: 0 };
const files = createSeamFileOperations(SOCKET, stats);
const bash = createSeamBashOperations(SOCKET);

// Pi's own tools; ours only in where the work lands.
const tools: ToolLike[] = [
  createReadTool(WORKSPACE, { operations: files.read }),
  createWriteTool(WORKSPACE, { operations: files.write }),
  createEditTool(WORKSPACE, { operations: files.edit }),
  createSeamGrepToolDefinition(WORKSPACE, SOCKET, stats),
  createFindTool(WORKSPACE, { operations: files.find }),
  createLsTool(WORKSPACE, { operations: files.ls }),
  createBashTool(WORKSPACE, { operations: bash }),
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
const elapsed = performance.now() - started;

// Pi's own grep would have spawned rg on this side; there must be none here to spawn.
const hostRg = [process.env.PATH ?? '', join(process.env.PI_AGENT_DIR ?? '', 'bin')]
  .flatMap((dirs) => dirs.split(':'))
  .some((dir) => dir && existsSync(join(dir, 'rg')));
console.log(`\nrg on Pi's side: ${hostRg ? 'PRESENT' : 'absent'} — grep ran in the guest`);

console.log('\ndoes anything confine a path to the workspace?');
for (const escape of ['../escaped.txt', '/etc/hosts', 'planted']) {
  console.log(`  read ${escape.padEnd(16)} ${await call('read', { path: escape })}`);
}
console.log(`  grep /etc            ${await call('grep', { pattern: 'root', path: '/etc' })}`);
// `planted` points at /etc/hostname: a walk that followed it would match the container's hostname.
console.log(`  grep . (via planted) ${await call('grep', { pattern: '.', glob: 'planted' })}`);

console.log(`\nseven tool calls in ${elapsed.toFixed(0)} ms; ` +
  `${stats.calls} file primitives served, ${stats.backendMs.toFixed(1)} ms of that in the guest`);
console.log('\nnot provided here, and not provided by Pi at all:');
console.log('  web_search, web_fetch — would be first-party tools over an HttpHatch\n');
