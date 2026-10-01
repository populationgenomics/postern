"""PROBE — throwaway, lives on `pi-probe`. Drive a real Pi session through its RPC mode, and abort it.

Print mode (`pi -p`) cannot interrupt a tool call; RPC mode can, with the same `abort` the TUI's
Esc sends. This asks the model to run a long streaming command, aborts it mid-run, and then asks
the model to check the command really stopped: the guest appends a tick a second, so a count
that does not move proves the sandboxed process is gone, not merely detached from.

Run: `ANTHROPIC_API_KEY=... python3 probes/pi/drive_rpc.py` (needs the image `run.sh` builds).
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
import typing
from collections.abc import Iterator

RUN = pathlib.Path(__file__).with_name('run.sh')
LONG = 'for i in $(seq 1 30); do echo tick $i | tee -a ticks.txt; sleep 1; done'


class Session:
    """A Pi RPC session in the probe container: JSON commands in, JSON events out."""

    def __init__(self) -> None:
        argv = [
            str(RUN),
            'pi',
            '--mode',
            'rpc',
            '--no-session',
            '--provider',
            'anthropic',
            '--model',
            'claude-sonnet-5',
        ]
        self.pi = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)  # noqa: S603 — our own script
        if self.pi.stdin is None or self.pi.stdout is None:
            raise RuntimeError('no pipes to the Pi session')
        self.stdin, self.stdout = self.pi.stdin, self.pi.stdout
        self.started = time.monotonic()

    def send(self, command: dict[str, object]) -> None:
        self.stdin.write(json.dumps(command) + '\n')
        self.stdin.flush()

    def events(self) -> Iterator[dict[str, typing.Any]]:
        for line in self.stdout:
            if line.strip():
                yield json.loads(line)

    def say(self, what: str) -> None:
        print(f'{time.monotonic() - self.started:6.1f}s  {what}')

    def close(self) -> None:
        self.stdin.close()
        self.pi.wait(timeout=30)


def run_and_abort(session: Session) -> None:
    """Start the long command, abort it after a few streamed updates, and time the tool's end."""
    session.send({'type': 'prompt', 'message': f'Use bash to run exactly this, with no timeout: {LONG}'})
    updates, aborted_at = 0, None
    for event in session.events():
        kind = event.get('type')
        if kind == 'tool_execution_start':
            session.say(f'tool start: {event.get("toolName")} {event.get("args")}')
        elif kind == 'tool_execution_update':
            updates += 1
            if updates == 3 and aborted_at is None:
                aborted_at = time.monotonic()
                session.say(f'{updates} streamed updates so far: sending abort')
                session.send({'type': 'abort'})
        elif kind == 'tool_execution_end':
            took = time.monotonic() - (aborted_at or session.started)
            text = ''.join(part.get('text', '') for part in (event.get('result') or {}).get('content', []))
            session.say(f'tool end, {took * 1000:.0f} ms after abort: {" | ".join(text.strip().splitlines()[-2:])}')
        elif kind == 'response' and event.get('command') == 'abort':
            session.say('abort acknowledged; session idle')
            return


def check_it_stopped(session: Session) -> None:
    """Ask the model whether the aborted loop is still appending ticks."""
    session.send(
        {
            'type': 'prompt',
            'message': (
                'Your last command was interrupted. Use bash to run `wc -l < ticks.txt`, then `sleep 3`, then '
                '`wc -l < ticks.txt` again, as one command. Reply with the two numbers and whether the interrupted '
                'loop is still running.'
            ),
        }
    )
    for event in session.events():
        if event.get('type') == 'agent_end':
            for message in reversed(event.get('messages') or []):
                if message.get('role') == 'assistant':
                    parts = message.get('content', [])
                    session.say(
                        'model: ' + ' '.join(p.get('text', '') for p in parts if p.get('type') == 'text').strip()
                    )
                    return
            return


def main() -> int:
    session = Session()
    try:
        run_and_abort(session)
        time.sleep(3)
        check_it_stopped(session)
    finally:
        session.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
