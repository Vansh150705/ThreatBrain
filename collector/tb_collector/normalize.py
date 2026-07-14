from __future__ import annotations

import re
from urllib.parse import unquote_plus

# Deobfuscation before signature matching: defeats URL-encoding, double-encoding,
# SQL comment insertion, whitespace tricks, null bytes, and case juggling.

_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Return a decoded, comment-stripped, whitespace-collapsed, lower-cased form."""
    prev = None
    cur = text
    # Recursively URL-decode a few times to unwrap single AND double encoding.
    for _ in range(3):
        if cur == prev:
            break
        prev = cur
        cur = unquote_plus(cur)
    cur = cur.replace("\x00", "")          # strip null bytes
    cur = _SQL_COMMENT.sub(" ", cur)       # collapse /* ... */ SQL comments
    cur = cur.replace("/**/", " ")
    cur = _WS.sub(" ", cur)                 # collapse whitespace (tabs, %09, +)
    return cur.lower()
