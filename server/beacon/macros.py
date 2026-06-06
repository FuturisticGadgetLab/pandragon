"""
Macro Expansion for Malleable C2

Expands macros in wrapper patterns for beacon obfuscation.
"""

import re
import random
import string
import time
import logging
from typing import Optional


logger = logging.getLogger('pandragon.beacon.macros')


# Pre-compiled regex patterns for macro expansion
_MACRO_EXPAND_PATTERNS = {
    'timestamp': re.compile(r'\$\{TIMESTAMP\}'),
    'rand_b64': re.compile(r'\$\{RAND_B64:(\d+)\}'),
    'junk': re.compile(r'\$\{JUNK:(\d+)\}'),
    'pad_b64': re.compile(r'\$\{PAD_BASE64\}'),
}


def expand_macros(text: str, beacon_session: Optional[dict] = None) -> str:
    """
    Expand macros in a string for malleable C2.

    Supported macros:
        ${TIMESTAMP}   - Unix timestamp (seconds)
        ${RAND_B64:N}  - Random base64 (N characters)
        ${JUNK:N}      - Random junk (N characters, alphanumeric)
        ${PAD_BASE64}  - Base64 padding (== or =X)

    Args:
        text: Input string potentially containing macros
        beacon_session: Optional beacon session (reserved for future use)

    Returns:
        String with macros expanded to runtime values

    Example:
        >>> expand_macros("REQ_${RAND_B64:4}_")
        'REQ_abcd_'  # Random 4-char base64
    """
    if not text:
        return text

    result = text

    # ${TIMESTAMP} - current Unix timestamp
    result = _MACRO_EXPAND_PATTERNS['timestamp'].sub(
        str(int(time.time())), result
    )

    # ${RAND_B64:N} - random base64 of N characters
    def _rand_b64(match: re.Match) -> str:
        n = int(match.group(1))
        return ''.join(random.choices(
            string.ascii_letters + string.digits + '+/', k=n
        ))
    result = _MACRO_EXPAND_PATTERNS['rand_b64'].sub(_rand_b64, result)

    # ${JUNK:N} - random junk of N characters (printable ASCII, URL-safe)
    def _rand_junk(match: re.Match) -> str:
        n = int(match.group(1))
        return ''.join(random.choices(
            string.ascii_letters + string.digits, k=n
        ))
    result = _MACRO_EXPAND_PATTERNS['junk'].sub(_rand_junk, result)

    # ${PAD_BASE64} - base64-like padding
    def _pad_b64(_: re.Match) -> str:
        if random.random() < 0.5:
            return '=='
        return '=' + random.choice(string.ascii_letters + string.digits)
    result = _MACRO_EXPAND_PATTERNS['pad_b64'].sub(_pad_b64, result)

    return result
