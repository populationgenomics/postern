// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
// Ported from themis-internal `proto/pi-loop-outside` (`seam.ts`), against the real guest.
//
// Drives the seam without a model in the way, and prints what it found. Run inside the container:
// `probes/pi/run.sh seam`.
//
// `pi-loop-outside` measured this against a host subprocess, because bubblewrap does not exist on
// macOS, and left the guest's own cost as its open question. This is that measurement:
//   1. What does a tool call cost end to end against a postern guest, and how much is the socket?
//   2. Does the guest meet the two things Pi's bash contract asks for — streaming output, and abort?

import { createSeamBashOperations, type SeamCall } from './bash-ops.ts';

const SOCKET = process.env.PI_POSTERN_SOCKET!;
const WORKSPACE = process.env.PI_POSTERN_WORKSPACE!;

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;

type Case = { label: string; wallMs: number; call: SeamCall; exitCode: number | null; output: string };

let last: SeamCall | undefined;
const ops = createSeamBashOperations(SOCKET, (call) => {
  last = call;
});

const run = async (label: string, command: string, signal?: AbortSignal): Promise<Case> => {
  let output = '';
  const started = performance.now();
  const { exitCode } = await ops.exec(command, WORKSPACE, {
    onData: (data) => {
      output += data.toString('utf8');
    },
    signal,
  });
  return { label, wallMs: performance.now() - started, call: last!, exitCode, output };
};

// 1. Cost: a command that does nothing, many times over.
const trivial: Case[] = [];
for (let i = 0; i < 11; i += 1) trivial.push(await run('echo', 'echo hello'));

// 2. Streaming: five lines a fifth of a second apart. One frame means the backend buffered.
const streamed = await run('stream', 'for i in 1 2 3 4 5; do echo $i; sleep 0.2; done');

// 3. Abort: a long sleep, cancelled almost immediately.
const controller = new AbortController();
setTimeout(() => controller.abort(), 300);
const aborted = await run('abort', 'sleep 5', controller.signal);

const seamCosts = trivial.map((c) => c.wallMs - c.call.backendMs);
const backendCosts = trivial.map((c) => c.call.backendMs);

console.log(`\n${'='.repeat(78)}`);
console.log(`backend in use: ${trivial[0]!.call.backend}`);
console.log(`${'='.repeat(78)}`);
console.log('case      wall ms   backend ms   seam ms   frames   exit');
for (const c of [...trivial.slice(0, 3), streamed, aborted]) {
  const seam = (c.wallMs - c.call.backendMs).toFixed(1).padStart(7);
  console.log(
    `${c.label.padEnd(9)} ${c.wallMs.toFixed(1).padStart(7)}   ` +
      `${c.call.backendMs.toFixed(1).padStart(10)}   ${seam}   ` +
      `${String(c.call.frames).padStart(6)}   ${String(c.exitCode).padStart(4)}`,
  );
}

console.log(`\nover ${trivial.length} trivial calls:`);
console.log(`  guest (bwrap launch + bash): median ${median(backendCosts).toFixed(1)} ms, ` +
  `min ${Math.min(...backendCosts).toFixed(1)} ms, max ${Math.max(...backendCosts).toFixed(1)} ms`);
console.log(`  socket seam:                 median ${median(seamCosts).toFixed(1)} ms, ` +
  `min ${Math.min(...seamCosts).toFixed(1)} ms, max ${Math.max(...seamCosts).toFixed(1)} ms`);

console.log('\nagainst the two things Pi\'s bash contract asks for:');
console.log(`  streaming: ${streamed.call.frames} output frame(s) for 5 lines emitted 200ms apart ` +
  `— ${streamed.call.frames > 1 ? 'incremental' : 'BUFFERED, all at the end'}`);
console.log(`  abort:     sleep 5 cancelled at 300ms returned after ${aborted.wallMs.toFixed(0)} ms ` +
  `— ${aborted.wallMs < 1000 ? 'the command was killed' : 'IGNORED, it ran to completion'}`);
for (const note of new Set([...streamed.call.notes, ...aborted.call.notes])) {
  console.log(`  executor said: ${note}`);
}
console.log();
