// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
// Ported verbatim from themis-internal `proto/pi-vm` (`prototypes/pi_vm/extension/`), which copied it
// from `proto/pi-loop-outside`, where the seam question was answered.
//
// Pi's `BashOperations`, implemented over the Unix socket `executor.py` serves. This is the seam the
// spike exists to test: the loop runs here, outside the sandbox; every command it wants to run
// crosses this socket and executes inside the guest. Nothing in this file can reach the guest or
// anything the guest can — it can only ask.
//
// The type import is the point of the exercise: if this object stops satisfying Pi's published
// contract, `npm run typecheck` fails.

import type { BashOperations } from '@earendil-works/pi-coding-agent';
import { connect } from 'node:net';

export type SeamCall = {
  /** Output frames the executor sent — 1 means the backend buffered, >1 means it streamed. */
  frames: number;
  /** Milliseconds the executor spent in its backend, excluding the socket round trip. */
  backendMs: number;
  /** Which backend served the call. */
  backend: string;
  /** Notes the executor sent, e.g. that it cannot abort. */
  notes: string[];
};

export function createSeamBashOperations(
  socketPath: string,
  onCall?: (call: SeamCall) => void,
): BashOperations {
  return {
    exec(command, cwd, options) {
      return new Promise((resolve, reject) => {
        const socket = connect(socketPath);
        let pending = '';
        let frames = 0;
        let backend = 'unknown';
        const notes: string[] = [];

        const requestCancel = () => {
          socket.write(`${JSON.stringify({ cancel: true })}\n`);
        };
        options.signal?.addEventListener('abort', requestCancel, { once: true });

        socket.on('connect', () => {
          // Seconds, both sides: Pi's bash schema documents `timeout` as "Timeout in seconds".
          socket.write(`${JSON.stringify({ command, cwd, timeout: options.timeout })}\n`);
        });

        socket.on('data', (chunk) => {
          pending += chunk.toString('utf8');
          for (;;) {
            const newline = pending.indexOf('\n');
            if (newline < 0) break;
            const line = pending.slice(0, newline);
            pending = pending.slice(newline + 1);
            if (!line) continue;
            const message = JSON.parse(line) as Record<string, never>;
            switch (message.t as unknown as string) {
              case 'hello':
                backend = message.backend as unknown as string;
                break;
              case 'out':
                frames += 1;
                options.onData(Buffer.from(message.d as unknown as string, 'utf8'));
                break;
              case 'note': {
                const note = message.d as unknown as string;
                notes.push(note);
                options.onData(Buffer.from(`[seam] ${note}\n`, 'utf8'));
                break;
              }
              case 'exit': {
                options.signal?.removeEventListener('abort', requestCancel);
                onCall?.({ frames, backend, notes, backendMs: message.backend_ms as unknown as number });
                socket.end();
                resolve({ exitCode: (message.code as unknown as number | null) ?? null });
                break;
              }
            }
          }
        });

        socket.on('error', reject);
      });
    },
  };
}
