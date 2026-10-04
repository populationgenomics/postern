"""`Guest`: how a guest-derived value enters a log call.

Raw, a newline in such a value starts what reads as a new host-attributed entry
in an aggregated log stream. Wrap every one: ``log.warning('denied %s', Guest(method))``.
"""

from __future__ import annotations

import functools

_LIMIT = 200


class Guest:
    """A guest-derived value, rendered for a log record as one escaped, length-capped line.

    Rendered only when the record is formatted, so a disabled level costs nothing.
    How a value renders depends on its type; see :func:`_render`.
    """

    __slots__ = ('_limit', '_value')

    def __init__(self, value: object, *, limit: int = _LIMIT) -> None:
        self._value = value
        self._limit = limit

    def __str__(self) -> str:
        return _render(self._value, self._limit)

    __repr__ = __str__


@functools.singledispatch
def _render(value: object, limit: int) -> str:
    """``value`` as one escaped line of about ``limit`` characters."""
    text = repr(value)
    return text if len(text) <= limit else f'{text[:limit]}…'


@_render.register(str)
@_render.register(bytes)
def _(value: str | bytes, limit: int) -> str:
    # repr escapes everything str.isprintable rejects: newlines, NUL, NEL, U+2028/9,
    # bidi controls, lone surrogates. Escaping can multiply the length, so the
    # output is capped as well as the input. The marker sits outside the quotes,
    # where a guest cannot forge it.
    text = repr(value[:limit])
    if len(value) <= limit and len(text) <= limit:
        return text
    return f'{text[:limit]}…({len(value)} total)'


@_render.register
def _(value: BaseException, limit: int) -> str:
    return _render(f'{type(value).__name__}: {value}', limit)
