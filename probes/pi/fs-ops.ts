// PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.
// Ported verbatim from themis-internal `proto/pi-vm` (`prototypes/pi_vm/extension/`), which copied it
// from `proto/pi-loop-outside`, where the seam question was answered.
//
// The rest of Pi's tool operations over the same socket `bash-ops.ts` uses. Pi's read, write, edit,
// find and ls tools all reduce to a handful of primitives — readFile, writeFile, mkdir, access,
// exists, stat, readdir, glob — so one request type serves all five. grep does not: see `grep.ts`.
//
// Confinement is the executor's, not ours: a path that escapes the workspace comes back as an error
// frame. Doing it here would put the check on the untrusted side of the seam.

import type {
  EditOperations,
  FindOperations,
  LsOperations,
  ReadOperations,
  WriteOperations,
} from '@earendil-works/pi-coding-agent';
import { connect } from 'node:net';

export type FileOpStats = { calls: number; backendMs: number };

/** One request, one response, one connection — the shape the executor serves. */
export function request(socketPath: string, payload: Record<string, unknown>, stats?: FileOpStats): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let pending = '';
    socket.on('connect', () => socket.write(`${JSON.stringify(payload)}\n`));
    socket.on('data', (chunk) => {
      pending += chunk.toString('utf8');
      for (;;) {
        const newline = pending.indexOf('\n');
        if (newline < 0) break;
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (!line) continue;
        const message = JSON.parse(line) as { t: string; value?: unknown; message?: string; backend_ms?: number };
        if (message.t === 'result') {
          if (stats) {
            stats.calls += 1;
            stats.backendMs += message.backend_ms ?? 0;
          }
          socket.end();
          resolve(message.value);
        } else if (message.t === 'error') {
          socket.end();
          reject(new Error(message.message ?? 'executor error'));
        }
      }
    });
    socket.on('error', reject);
  });
}

export function createSeamFileOperations(socketPath: string, stats?: FileOpStats) {
  const call = (payload: Record<string, unknown>) => request(socketPath, payload, stats);

  const readFile = async (absolutePath: string): Promise<Buffer> =>
    Buffer.from((await call({ op: 'readFile', path: absolutePath })) as string, 'base64');

  const read: ReadOperations = {
    readFile,
    access: async (absolutePath) => {
      await call({ op: 'access', path: absolutePath });
    },
  };

  const write: WriteOperations = {
    writeFile: async (absolutePath, content) => {
      await call({ op: 'writeFile', path: absolutePath, content });
    },
    mkdir: async (dir) => {
      await call({ op: 'mkdir', path: dir });
    },
  };

  const edit: EditOperations = { readFile, writeFile: write.writeFile, access: read.access };

  const find: FindOperations = {
    exists: async (absolutePath) => (await call({ op: 'exists', path: absolutePath })) as boolean,
    glob: async (pattern, cwd, options) =>
      (await call({ op: 'glob', pattern, cwd, limit: options.limit })) as string[],
  };

  const ls: LsOperations = {
    exists: find.exists,
    stat: async (absolutePath) => {
      const isDirectory = (await call({ op: 'isDirectory', path: absolutePath })) as boolean;
      return { isDirectory: () => isDirectory };
    },
    readdir: async (absolutePath) => (await call({ op: 'readdir', path: absolutePath })) as string[],
  };

  return { read, write, edit, find, ls };
}
