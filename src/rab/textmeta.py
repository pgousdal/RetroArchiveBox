from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TextExtraction:
    text: str
    encoding: str
    status: str


def extract_text(data: bytes) -> TextExtraction:
    if data.startswith(b"\xef\xbb\xbf"):
        return TextExtraction(data[3:].decode("utf-8", "replace"), "utf-8-sig", "PASS")
    candidates = ("utf-8", "ascii", "iso-8859-1", "cp437")
    for encoding in candidates:
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if encoding in {"utf-8", "ascii"} or sum(ch == "�" for ch in text) == 0:
            return TextExtraction(text, encoding, "PASS")
    return TextExtraction(data.decode("iso-8859-1", "replace"), "iso-8859-1", "REPLACED")
