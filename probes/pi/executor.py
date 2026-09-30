"""PROBE — throwaway, lives on `pi-probe`. Not part of the postern package.

The trusted half of the seam between Pi's loop and a postern guest: a Unix-socket server that Pi's
tool operations (`bash-ops.ts`, `fs-ops.ts`) call, and that does every piece of work inside the
guest. Pi holds the model credential and never sees the guest; the guest never sees Pi.

Ported from themis-internal's `proto/pi-vm` (`prototypes/pi_vm/executor.py`), itself the serving
successor to `proto/pi-loop-outside`'s comparison executor. What it kept from each:

- **No host backend.** `pi-loop-outside` fell back to a host subprocess where bubblewrap was absent;
  `pi-vm` dropped that, because a fallback is model-chosen commands running unsandboxed beside the
  credential. This refuses to start unless `Sandbox.verify()` passes.
- **A timeout ceiling.** Pi's bash tool takes `timeout` from the model and `Sandbox.run` cannot be
  interrupted, so an unclamped value is a command nothing can stop.
- **Confinement on the trusted side.** Pi resolves a tool's path and hands it over without a
  workdir check, so `read ../../etc/shadow` arrives here as an absolute path outside the workspace.
  It is refused here, because this is the only place the check can go.

What it adds: host paths are translated to guest paths rather than assumed equal, so the probe does
not depend on the host workspace happening to live at `/workspace`.

Protocol, newline-delimited JSON, one request per connection:

    in   {"command": str, "cwd": str, "timeout": float}
    in   {"cancel": true}                                  (during a command)
    out  {"t": "hello", "backend": str, "streams": bool, "aborts": bool}
    out  {"t": "out", "d": str}                            (zero or more)
    out  {"t": "note", "d": str}                           (zero or more)
    out  {"t": "exit", "code": int | None, "backend_ms": float}

    in   {"op": "readFile" | "writeFile" | ..., "path": str, ...}
    out  {"t": "hello", ...}
    out  {"t": "result", "value": <json>, "backend_ms": float}
    out  {"t": "error", "message": str}

Run: `python executor.py <socket-path> <workspace>`; `entrypoint.sh` does this for you.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import pathlib
import shlex
import sys
import time
from collections.abc import Awaitable, Callable

import postern

Emit = Callable[[dict[str, object]], Awaitable[None]]

# `Sandbox.run` has no cancellation, so a command runs to completion regardless; this bounds it. The
# ceiling, not just the default: the model picks the number, and an unclamped one is unstoppable.
_DEFAULT_TIMEOUT_S = 120.0
_MAX_TIMEOUT_S = 120.0
_FILE_OP_TIMEOUT_S = 60.0
# Where postern binds the workspace inside the guest.
_GUEST_WORKSPACE = pathlib.PurePosixPath('/workspace')
_logger = logging.getLogger(__name__)


class ConfinedError(Exception):
    """A path that resolved outside the workspace."""


def _to_guest(workspace: pathlib.Path, path: str) -> str:
    """The guest path for host `path`, or raise if it leaves the workspace.

    Resolved on the host before the check, so `..` and a symlink both land where they really point.
    A guest-planted symlink that escapes is therefore refused here rather than followed in the guest.

    Raises:
        ConfinedError: If the resolved path is not under the workspace.
    """
    root = workspace.resolve()
    candidate = pathlib.Path(path)
    absolute = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if absolute != root and root not in absolute.parents:
        raise ConfinedError(f'{path} resolves to {absolute}, outside the workspace {root}')
    return str(_GUEST_WORKSPACE / absolute.relative_to(root))


# The file primitives Pi's read/write/edit/grep/find/ls tools reduce to, run inside the guest.
# `readFile` answers base64 so a Buffer survives the hop; everything else is JSON-native.
_GUEST_FILE_OPS = """
import base64, glob, json, pathlib
request = json.loads({payload!r})
op, path = request['op'], request.get('path')
target = pathlib.Path(path) if path else None
if op == 'readFile':
    print(json.dumps(base64.b64encode(target.read_bytes()).decode()))
elif op == 'writeFile':
    target.write_text(request['content'], 'utf-8'); print('null')
elif op == 'mkdir':
    target.mkdir(parents=True, exist_ok=True); print('null')
elif op == 'access':
    target.stat(); print('null')
elif op == 'exists':
    print(json.dumps(target.exists()))
elif op == 'isDirectory':
    print(json.dumps(target.is_dir()))
elif op == 'readdir':
    print(json.dumps(sorted(entry.name for entry in target.iterdir())))
elif op == 'glob':
    matches = glob.glob(request['pattern'], root_dir=request['cwd'], recursive=True)
    print(json.dumps(sorted(matches)[: request['limit']]))
else:
    raise SystemExit(f'unknown op {{op}}')
"""


async def _run_command(
    sandbox: postern.Sandbox, command: str, cwd: str, timeout: float, emit: Emit, cancelled: asyncio.Event
) -> int | None:
    """Run `command` in the guest, reporting the two places `Sandbox.run` falls short of Pi's contract.

    Pi's `BashOperations.exec` promises incremental output through `onData` and a kill on abort.
    `Sandbox.run` buffers and cannot be interrupted, so output arrives in one frame at the end and a
    cancel is acknowledged rather than honoured. Both are reported as notes instead of papered over.
    """

    async def acknowledge_cancel() -> None:
        await cancelled.wait()
        await emit({'t': 'note', 'd': 'Sandbox.run cannot be aborted; the command runs to completion'})

    # Not `bash -l`: the guest has no /etc, so a login shell has no profile to read.
    argv = ['bash', '-c', f'cd {shlex.quote(cwd)} && {command}']
    watching = asyncio.create_task(acknowledge_cancel())
    try:
        result = await asyncio.to_thread(sandbox.run, argv, timeout=timeout)
    finally:
        watching.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watching

    for stream in (result.stdout, result.stderr):
        if stream:
            await emit({'t': 'out', 'd': stream})
    return result.returncode


async def _file_op(sandbox: postern.Sandbox, workspace: pathlib.Path, request: dict[str, object]) -> object:
    """Serve one file primitive inside the guest.

    Raises:
        ConfinedError: If a path in the request escapes the workspace.
        RuntimeError: If the guest could not run the primitive.
    """
    resolved = dict(request)
    if 'path' in resolved:
        resolved['path'] = _to_guest(workspace, str(resolved['path']))
    if 'cwd' in resolved:
        resolved['cwd'] = _to_guest(workspace, str(resolved['cwd'] or '.'))
    code = _GUEST_FILE_OPS.format(payload=json.dumps(resolved))
    result = await asyncio.to_thread(sandbox.run_python, code, timeout=_FILE_OP_TIMEOUT_S)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f'guest file op {request["op"]} failed')
    return json.loads(result.stdout)


async def _handle(
    sandbox: postern.Sandbox,
    workspace: pathlib.Path,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Serve one connection: one request, its frames, and the connection's close."""

    async def emit(message: dict[str, object]) -> None:
        writer.write(f'{json.dumps(message)}\n'.encode())
        await writer.drain()

    line = await reader.readline()
    if not line:
        return
    request = json.loads(line)
    await emit({'t': 'hello', 'backend': 'postern-guest', 'streams': False, 'aborts': False})
    started = time.monotonic()

    if 'op' in request:
        try:
            value = await _file_op(sandbox, workspace, request)
        except (ConfinedError, OSError, RuntimeError, ValueError) as exc:
            _logger.warning('file op %s refused: %s', request.get('op'), exc)
            await emit({'t': 'error', 'message': f'{type(exc).__name__}: {exc}'})
            return
        await emit({'t': 'result', 'value': value, 'backend_ms': (time.monotonic() - started) * 1000})
        return

    cancelled = asyncio.Event()

    async def watch_for_cancel() -> None:
        while await reader.readline():
            cancelled.set()

    watching = asyncio.create_task(watch_for_cancel())
    try:
        cwd = _to_guest(workspace, str(request.get('cwd') or workspace))
        timeout = min(float(request.get('timeout') or _DEFAULT_TIMEOUT_S), _MAX_TIMEOUT_S)
        code = await _run_command(sandbox, str(request['command']), cwd, timeout, emit, cancelled)
    except Exception as exc:  # a guest failure is the model's to see, not the executor's to die on
        _logger.exception('guest command failed')
        await emit({'t': 'note', 'd': f'{type(exc).__name__}: {exc}'})
        code = None
    finally:
        watching.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watching
    await emit({'t': 'exit', 'code': code, 'backend_ms': (time.monotonic() - started) * 1000})


async def serve(sandbox: postern.Sandbox, workspace: pathlib.Path, socket_path: pathlib.Path) -> asyncio.Server:
    """Start serving Pi's tool operations for `sandbox` on `socket_path`.

    The caller owns the sandbox, which it must already have verified, and the returned server.
    """

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await _handle(sandbox, workspace, reader, writer)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    socket_path.unlink(missing_ok=True)
    server = await asyncio.start_unix_server(handle, path=str(socket_path))
    # Only Pi, running as this user, should reach it; the guest is never bound to it.
    socket_path.chmod(0o600)
    _logger.info('executor serving %s for workspace %s', socket_path, workspace)
    return server


async def main(socket_path: pathlib.Path, workspace: pathlib.Path) -> None:
    """Verify a guest over `workspace`, then serve on `socket_path` until killed."""
    workspace.mkdir(parents=True, exist_ok=True)
    sandbox = postern.Sandbox(postern.SandboxProfile(workspace=workspace))
    sandbox.verify()  # raises IsolationError: there is no host path to fall back to
    _logger.info('isolation verified')
    server = await serve(sandbox, workspace, socket_path)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='executor: %(message)s')
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])))
