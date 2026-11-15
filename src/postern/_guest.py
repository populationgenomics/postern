"""In-sandbox runner for `Sandbox.run_python`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. The guest init execs
it as its child, and it runs ``POSTERN_CODE`` in this process. Reaching a hatch is
the guest's own business: the socket is a file at
``$POSTERN_HATCH``/``$POSTERN_HATCH_<NAME>``, dialled with whatever client library
the guest's environment carries.

The host↔shim contract is two environment variables: ``POSTERN_CODE`` and
``POSTERN_AS``. The ``POSTERN_HATCH``/``POSTERN_HATCH_<NAME>`` variables are set
alongside them for the *guest* to read, not for this module.
"""

import os
import resource
import sys
import traceback


def _apply_address_space_limit() -> None:
    """Set ``RLIMIT_AS`` from ``POSTERN_AS``, now that the interpreter is up.

    The init leaves it to this shim: a bare CPython's *virtual* size at startup can
    far exceed its resident use, so capping before the exec can abort the
    interpreter's startup outright. Per-process, so this bounds one allocation
    spree rather than the guest's total memory; a cgroup ``memory.max`` at the
    deploy layer is the real bound.
    """
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))


def _run_code() -> int:
    """Execute ``POSTERN_CODE`` in *this* process and return its exit status.

    Mirrors ``sys.exit(main())``'s handling of the guest's own ``SystemExit`` and
    of an uncaught exception.
    """
    _apply_address_space_limit()
    code = os.environ.get('POSTERN_CODE', '')
    try:
        exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        if exc.code is None:
            return 0
        print(exc.code, file=sys.stderr)  # CPython prints a non-int sys.exit() arg
        return 1
    except BaseException:
        traceback.print_exc()
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(_run_code())
