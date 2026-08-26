r"""Log-safety helper: render a guest-derived value so it cannot forge a record.

Guest bytes reach the host as gRPC method names and as the text and traceback of
an exception a handler raised on guest input. Interpolated raw into a log record
they land in an aggregated stream (Cloud Logging, journald) where a newline
starts what reads like a new entry from the host — so a guest whose RPC is named
``/x\nseverity=ERROR breach detected`` writes host-attributed lines.

:func:`safe` is the only way a guest-derived value enters a log call, tracebacks
included: nothing on a guest-reachable path is handed to ``exc_info``.
"""

from __future__ import annotations

_LIMIT = 200


def safe(value: object, limit: int = _LIMIT) -> str:
    r"""Render ``value`` as a single-line, escaped, length-capped literal.

    ``repr`` is what does the work: it quotes the result and escapes every
    character `str.isprintable` rejects, which covers ``\n``, ``\r``, NUL, NEL
    (U+0085), the Unicode line separators (U+2028/U+2029), bidi controls and lone
    surrogates. Nothing that survives it can start a line.

    Args:
        value: Any guest-derived value. A non-``str``/``bytes`` value is
            ``repr``'d as it is, then capped like any other.
        limit: Cap, applied to the input *and* to the rendered output. Capping
            only the input would leave the record's size guest-controlled, since
            an escape-heavy value renders up to ten times its own length.

    Returns:
        A literal safe to interpolate into a log message. A truncated result
        carries a trailing ``…`` after the closing quote — outside the literal,
        so a guest cannot forge it — naming the input's full length when the
        input was sized.
    """
    sized = isinstance(value, (str, bytes))
    text = repr(value[:limit] if sized else value)
    clipped = sized and len(value) > limit
    if len(text) > limit:
        text = text[:limit]
        clipped = True
    if not clipped:
        return text
    return f'{text}…({len(value)} total)' if sized else f'{text}…'
