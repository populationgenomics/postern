r"""Log-safety helper: render a guest-controlled value so it cannot forge a record.

Guest bytes reach the host as method names, socket paths, header values and
exception text. Interpolated raw into a log record they land in an aggregated
stream (Cloud Logging, journald) where a newline starts what reads like a new
entry from the host — so a guest that names its RPC
``/x\nseverity=ERROR breach detected`` writes host-attributed lines.

:func:`safe` is the only way a guest-derived value should enter a log call.
"""

from __future__ import annotations

_LIMIT = 200


def safe(value: object, limit: int = _LIMIT) -> str:
    """Render ``value`` as a single-line, escaped, length-capped literal.

    ``repr`` is what does the work: it quotes the result and escapes every
    control character, so no newline, carriage return or NUL survives into the
    record. The cap is applied to the *input*, so a guest cannot spend the
    record's budget on padding.

    Args:
        value: Any guest-derived value. Non-``str``/``bytes`` values are
            ``repr``'d as they are, since the guest cannot control their shape.
        limit: Characters of ``value`` to keep before truncating.

    Returns:
        A literal safe to interpolate into a log message. Truncation is marked
        with a trailing ``…`` inside the literal, so a capped value is never
        mistaken for a complete one.
    """
    if isinstance(value, (str, bytes)):
        clipped = value[:limit]
        text = repr(clipped)
        if len(value) > limit:
            return f'{text}…({len(value)} total)'
        return text
    return repr(value)
