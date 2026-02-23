from __future__ import annotations

import re
from typing import Optional


def parse_filter_expr(expr: str) -> tuple:
    """
    Parse a filter expression like '<500', '>500', '=500', or bare '500'.
    Returns (operator, value) where operator is one of '<', '>', '='.
    A bare integer is treated as '='.
    Raises ValueError on invalid input.
    """
    match = re.fullmatch(r'([<>=]?)(\d+)', expr.strip())
    if not match:
        raise ValueError(
            f"Invalid filter expression: {expr!r}. "
            "Use formats like '=500', '<500', '>500', or '500'."
        )
    op = match.group(1) or '='
    val = int(match.group(2))
    return op, val


def _matches(expr: str, actual: int) -> bool:
    """Return True if the actual value matches the filter expression."""
    op, threshold = parse_filter_expr(expr)
    if op == '=' and actual == threshold:
        return True
    if op == '<' and actual < threshold:
        return True
    if op == '>' and actual > threshold:
        return True
    return False


def should_exclude(
    page,
    exclude_bytes: list,
    exclude_words: list,
    exclude_lines: list,
) -> bool:
    """
    Return True if the page should be excluded from output.

    Each list contains filter expressions (e.g. ['=200', '>5000']).
    Conditions within and across lists are OR'd: if ANY expression in
    ANY list matches, the page is excluded.
    """
    for expr in (exclude_bytes or []):
        if _matches(expr, page.byte_count):
            return True
    for expr in (exclude_words or []):
        if _matches(expr, page.word_count):
            return True
    for expr in (exclude_lines or []):
        if _matches(expr, page.line_count):
            return True
    return False
