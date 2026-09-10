"""TrustGate text normalizer.

Strips invisible/zero-width Unicode format characters (Unicode category 'Cf')
and folds homoglyphs/lookalike letters to defeat evasion and obfuscation
attacks before any downstream scanner (regex, LLM) inspects the content.
"""

from typing import Any
import unicodedata

# Common Cyrillic and Greek homoglyphs visually identical to Latin characters
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u04ae": "Y",
    # Greek lookalikes
    "\u03bf": "o", "\u03bd": "v", "\u0391": "A", "\u0392": "B", "\u0395": "E",
    "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y",
    "\u03a7": "X",
}

TRANS_TABLE = str.maketrans(HOMOGLYPH_MAP)

# Explicit zero-width/invisible code points
ZERO_WIDTH_CHARS = frozenset([
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u2060",  # Word joiner
    "\u00ad",  # Soft hyphen
    "\u202a",  # Left-to-right embedding
    "\u202b",  # Right-to-left embedding
    "\u202c",  # Pop directional formatting
    "\u202d",  # Left-to-right override
    "\u202e",  # Right-to-left override
])


def normalize_text(text: str) -> str:
    """Normalize text by stripping zero-width format chars, applying NFKC, and folding homoglyphs.

    Guarantees:
    1. Removes all invisible and zero-width characters (category 'Cf' and explicit list).
    2. Normalizes full-width and mathematical bold/script styling via Unicode NFKC.
    3. Translates visually confusable Cyrillic/Greek homoglyphs into their Latin equivalents.
    """
    if not text:
        return ""

    # 1. Unicode NFKC normalization (folds full-width chars, font variants, ligatures)
    nfkc = unicodedata.normalize("NFKC", text)

    # 2. Strip format characters and zero-width code points
    stripped = "".join(
        c for c in nfkc
        if unicodedata.category(c) != "Cf" and c not in ZERO_WIDTH_CHARS
    )

    # 3. Translate lookalike homoglyphs to standard ASCII
    return stripped.translate(TRANS_TABLE)


def normalize_tool_manifest(tool: dict[str, Any]) -> dict[str, Any]:
    """Recursively normalize all string keys and values in a tool manifest dictionary."""
    if not isinstance(tool, dict):
        return tool

    normalized: dict[str, Any] = {}
    for key, value in tool.items():
        norm_key = normalize_text(key) if isinstance(key, str) else key
        if isinstance(value, str):
            normalized[norm_key] = normalize_text(value)
        elif isinstance(value, dict):
            normalized[norm_key] = normalize_tool_manifest(value)
        elif isinstance(value, list):
            normalized[norm_key] = [
                normalize_text(item) if isinstance(item, str)
                else normalize_tool_manifest(item) if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            normalized[norm_key] = value

    return normalized
