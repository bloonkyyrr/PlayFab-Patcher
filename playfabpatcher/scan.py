"""Detection: find a Unity game's backend and every patchable PlayFab setting.

The scanner never trusts a single heuristic.  A *site* is only reported when a
value is anchored by at least one of:

* the ``PlayFabSharedSettings`` object a player build still carries (title id,
  developer secret key and environment URL sit in the string slots behind it),
* another ``PlayFab*`` object name followed directly by a title id
  (``PlayFabBackend``, ``PlayFabConfig``, ...),
* a Unity length-prefixed string that directly follows a PlayFab key name
  (``TitleId``, ``DeveloperSecretKey``, ``ProductionEnvironmentUrl``),
* a ``key: value`` / ``key=value`` pair in a text based config,
* a ``#US`` / IL2CPP string literal that is named by the literal next to it,
* a ``*.playfabapi.com`` endpoint - the title id is the sub domain there.
"""

from __future__ import annotations

import mmap
import os
import re
import struct
import time
from dataclasses import dataclass, field

from . import dnmeta, il2cpp
from .pe import PEImage, PEError

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
TITLE_ID = "TitleId"
SECRET_KEY = "DeveloperSecretKey"
API_URL = "ApiUrl"
UNCLASSIFIED = "Unknown"

ID_ROLES = (TITLE_ID, SECRET_KEY, API_URL)

# PlayFab field names, longest first so ``playfabtitleid`` wins over ``titleid``.
PLAYFAB_KEYS = (
    "playfabtitleid",
    "playfabtitle_id",
    "playfab_title_id",
    "playfabsecretkey",
    "playfabsecret_key",
    "developersecretkey",
    "developer_secret_key",
    "developer_secretkey",
    "productionenvironmenturl",
    "production_environment_url",
    "playfabapiurl",
    "environmenturl",
    "titleid",
    "title_id",
    "secretkey",
    "secret_key",
)

MARKERS = (
    "playfab",
    "playfabapi.com",
    "playfabsharedsettings",
    "playfabsettings",
    "titleid",
    "developersecretkey",
    "playfabparty",
    "playfabmultiplayer",
    "playfabeconomy",
    "playfabauth",
)

SERVER_HINTS = (
    "playfabapi.com",
    "developer.playfab.com",
    "api.playfab.com",
    "playfab.com",
    "playfabcloudscript.com",
)

ASSET_EXTENSIONS = (".assets", ".asset", ".bundle", ".unity3d", ".ress", ".bytes", ".resource")
TEXT_EXTENSIONS = (".json", ".txt", ".xml", ".cfg", ".ini", ".yaml", ".yml", ".config", ".properties")

MAX_BLOB = 512 * 1024 * 1024

# Assets above MAX_BLOB are never loaded: they are mapped and only the regions
# around PlayFab looking text are parsed.  One mapped pass finds those regions,
# everything after that touches a few kilobytes at a time.
WINDOW_LOOKBACK = 2048  # bytes kept before a hit (Unity length prefixes)
WINDOW_BYTES = 48 * 1024  # bytes parsed from a hit on (settings objects)
WINDOW_MAX = 512 * 1024  # two hits closer than this share one window
WINDOW_CHUNK = 8 * 1024 * 1024
WINDOW_OVERLAP = 64
WINDOW_MAX_HITS = 8192

# Lower case on purpose: the mapped pass is case blind, and a player build
# spells the same object PlayFabSharedSettings and playfabsharedsettings.
WINDOW_NEEDLES = tuple(
    dict.fromkeys([key.encode("ascii") for key in PLAYFAB_KEYS] + [b"playfab", b"titleid"])
)

# The SDK keeps its settings in this object; a player build still contains it.
SETTINGS_NAME = "playfabsharedsettings"

PLAYFAB_OBJECT_RE = re.compile(rb"PlayFab[A-Za-z0-9_]*", re.IGNORECASE)
SETTINGS_MAX_SLOTS = 4

# A title id is a short upper case id: PlayFab issues 5 character hex ids
# ("A89CF"), legacy titles have 4, a few have 6.
TITLE_ANY_RE = re.compile(r"[A-Za-z0-9]{4,6}")
TITLE_HEX_RE = re.compile(r"[0-9A-F]{4,6}")
SECRET_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,100}")
SECRET_ANCHORED_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,100}")
URL_TEXT_RE = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d{2,5})?(?:/[^\s\"'<>]*)?")

TITLE_BARE_RE = re.compile(rb"(?<![A-Za-z0-9])[A-F0-9]{4,6}(?![A-Za-z0-9])")
SECRET_BARE_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,100}(?![A-Za-z0-9+/=])")
URL_BLOB_RE = re.compile(
    rb"(?i)https?://[A-Za-z0-9._-]*(?:playfab|playfabapi)[A-Za-z0-9._:-]*(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
)

TITLE_IN_HOST_RE = re.compile(
    r"^(?P<scheme>https?://)?(?P<tid>[0-9A-Fa-f]{4,6})\.playfabapi\.com(?::\d{2,5})?(?P<path>/.*)?$"
)

# Settings folded into one literal by the compiler ("titleid=A89CF;...").
LITERAL_TITLE_RE = re.compile(r"(?i)(?:playfab)?title_?id\s*[=:]\s*([A-Za-z0-9]{4,6})(?![A-Za-z0-9])")
LITERAL_SECRET_RE = re.compile(
    r"(?i)(?:developer_?)?secret_?key\s*[=:]\s*([A-Za-z0-9+/=_-]{20,100})"
)
LITERAL_URL_RE = re.compile(
    r"(?i)https?://[A-Za-z0-9._-]*playfab[A-Za-z0-9._-]*(?::\d{2,5})?/"
)

# Field names that prove a neighbouring literal is a PlayFab setting.
TITLE_KEY_HINT_RE = re.compile(r"title_?id")
SECRET_KEY_HINT_RE = re.compile(r"(?:developer_?)?secret_?key")

KV_RE = re.compile(
    rb"(?i)\b(playfabtitle_?id|title_?id|playfabsecret_?key|developer_?secret_?key"
    rb"|secret_?key|production_?environment_?url|playfabapiurl|environment_?url)"
    rb"[\"']?\s*[:=]\s*[\"']?([^\s\"',;}\r\n\x00]{2,120})"
)

UNITY_VERSION_RE = re.compile(rb"20\d\d\.\d+\.\d+[abfp]\d+")


# --------------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------------- #
@dataclass
class Site:
    path: str
    kind: str  # us | il2cpp | unity_str | text | raw
    offset: int  # absolute file offset of the value payload
    encoding: str  # utf-16-le | utf-8
    value: str
    role: str
    confidence: float
    context: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return f"{self.path}|{self.kind}|{self.offset}"

    @property
    def filename(self) -> str:
        return os.path.basename(self.path)

    @property
    def can_change_length(self) -> bool:
        return self.kind in ("us", "il2cpp", "unity_str", "text")


@dataclass
class ScanResult:
    root: str = ""
    backend: str = "Unknown"
    unity_version: str = ""
    game_name: str = ""
    evidence: list[str] = field(default_factory=list)
    server_hints: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    sites: list[Site] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0
    elapsed: float = 0.0
    il2cpp_version: str = ""
    managed_assemblies: int = 0
    blob_files: int = 0

    def by_role(self) -> dict[str, list[Site]]:
        groups: dict[str, list[Site]] = {}
        for site in self.sites:
            groups.setdefault(site.role, []).append(site)
        return groups

    @property
    def title_ids(self) -> list[str]:
        seen: list[str] = []
        for site in self.sites:
            if site.role in (TITLE_ID, UNCLASSIFIED) and site.value not in seen:
                seen.append(site.value)
        return seen

    @property
    def secret_keys(self) -> list[Site]:
        return [site for site in self.sites if site.role == SECRET_KEY]


# --------------------------------------------------------------------------- #
# environment detection
# --------------------------------------------------------------------------- #
def _iter_children(root: str, depth: int = 2):
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name.lower())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                if depth > 1:
                    yield from _iter_children(entry.path, depth - 1)
            else:
                yield entry.path
        except OSError:
            continue


def read_unity_version(root: str) -> str:
    for path in _iter_children(root, depth=2):
        base = os.path.basename(path)
        if base not in ("globalgamemanagers", "data.unity3d") and not base.endswith("_Data"):
            continue
        try:
            with open(path, "rb") as handle:
                head = handle.read(8192)
        except OSError:
            continue
        match = UNITY_VERSION_RE.search(head)
        if match:
            return match.group().decode("latin-1", "replace")
    return ""


def detect_environment(root: str) -> dict:
    info = {
        "backend": "Unknown",
        "unity_version": read_unity_version(root),
        "game_name": os.path.basename(os.path.normpath(root)),
        "managed_dirs": [],
        "il2cpp_metadata": [],
    }
    mono = 0
    il2cpp_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".playfabpatcher", "__pycache__", ".git")]
        lowered = {name.lower(): name for name in filenames}
        if os.path.basename(dirpath).lower() == "managed":
            dlls = [os.path.join(dirpath, name) for name in filenames if name.lower().endswith(".dll")]
            if dlls:
                info["managed_dirs"].append(dirpath)
                mono += len(dlls)
        if "global-metadata.dat" in lowered:
            il2cpp_files.append(os.path.join(dirpath, lowered["global-metadata.dat"]))
        if "gameassembly.dll" in lowered:
            il2cpp_files.append(os.path.join(dirpath, lowered["gameassembly.dll"]))
    info["il2cpp_metadata"] = il2cpp_files
    has_il2cpp_metadata = [p for p in il2cpp_files if p.lower().endswith("global-metadata.dat")]
    if mono and not has_il2cpp_metadata:
        info["backend"] = "Mono"
    elif has_il2cpp_metadata and not mono:
        info["backend"] = "IL2CPP"
    elif mono and has_il2cpp_metadata:
        info["backend"] = "Mixed"
    return info


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _read_file(path: str, warnings: list[str]) -> bytes | None:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        warnings.append(f"cannot stat {path}: {exc}")
        return None
    if size > MAX_BLOB:
        warnings.append(f"skipped {os.path.basename(path)} (larger than {MAX_BLOB // (1024 * 1024)} MB)")
        return None
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        warnings.append(f"cannot read {path}: {exc}")
        return None


def _evidence(text: str) -> list[str]:
    lowered = text.lower()
    return [marker for marker in MARKERS if marker in lowered]


def _role_from_key(key: str) -> str:
    """Map a PlayFab field name (TitleId, DeveloperSecretKey, ...) to its role."""
    lowered = key.lower().replace(" ", "")
    if "secret" in lowered:
        return SECRET_KEY
    if "url" in lowered or "endpoint" in lowered:
        return API_URL
    if "title" in lowered:
        return TITLE_ID
    return UNCLASSIFIED


def looks_like_title_id(value: str, strict: bool = False) -> bool:
    """A PlayFab title id: 4-6 characters, upper case hex in practice."""
    if not 4 <= len(value) <= 6:
        return False
    pattern = TITLE_HEX_RE if strict else TITLE_ANY_RE
    if pattern.fullmatch(value) is None:
        return False
    # "0000" and friends are counters, not titles.
    return any(ch.isalpha() for ch in value)


def looks_like_secret(value: str, anchored: bool = False) -> bool:
    """A developer secret key is a long base64-ish blob, never a short token.

    ``anchored`` relaxes the shape test when a ``DeveloperSecretKey`` field name
    proves what the value is; a free floating 32+ character token still has to
    contain a digit so that class names and paths do not qualify.
    """
    if anchored:
        return bool(SECRET_ANCHORED_RE.fullmatch(value))
    return bool(SECRET_RE.fullmatch(value)) and any(ch.isdigit() for ch in value)


def _literal_title(value: str, strict: bool = False) -> bool:
    """A title id literal is upper case; mixed case words are field names."""
    if value.upper() != value:
        return False
    return looks_like_title_id(value, strict=strict)


def _literal_secret(value: str) -> bool:
    """A key literal is base64-ish; API paths and sentences do not qualify."""
    if value.startswith(("/", ".", "\\")) or " " in value:
        return False
    return looks_like_secret(value, anchored=True) and any(ch.isdigit() for ch in value)


def looks_like_endpoint(value: str) -> bool:
    lowered = value.lower()
    if "playfab" not in lowered:
        return False
    if lowered.startswith(("http://", "https://")):
        return True
    return lowered.startswith(".") and lowered.endswith((".com", ".com/"))


def looks_like_url(value: str) -> bool:
    return bool(URL_TEXT_RE.fullmatch(value))


def role_for_value(value: str) -> str | None:
    """Classify a config value purely by its shape."""
    if looks_like_endpoint(value):
        return API_URL
    if looks_like_secret(value):
        return SECRET_KEY
    if looks_like_title_id(value):
        return TITLE_ID
    return None


def title_in_endpoint(value: str) -> tuple[int, int, str] | None:
    """Return ``(start, end, title_id)`` of the sub domain title id, if any."""
    match = TITLE_IN_HOST_RE.match(value)
    if match is None:
        return None
    return match.start("tid"), match.end("tid"), match.group("tid")


def _read_unity_string(data: bytes, position: int) -> tuple[str, int] | None:
    """Read a length-prefixed Unity string at ``position``."""
    if position < 0 or position + 4 > len(data):
        return None
    length = struct.unpack_from("<i", data, position)[0]
    if length < 0 or length > 4096:
        return None
    start = position + 4
    end = start + length
    if end > len(data):
        return None
    raw = data[start:end]
    if any(byte < 9 or 13 < byte < 32 for byte in raw):
        return None
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not value.isprintable():
        return None
    return value, end


def _slot_end(data: bytes, prefix: int, length: int) -> int:
    """End of a Unity string slot: the text plus its 4 byte alignment padding."""
    return prefix + 4 + length + ((4 - length % 4) % 4)


def _unity_string_prefix(data: bytes, offset: int) -> int:
    """Length of the Unity serialized string starting at ``offset``, or -1."""
    if offset < 4:
        return -1
    try:
        length = struct.unpack_from("<i", data, offset - 4)[0]
    except struct.error:
        return -1
    return length if 0 < length <= 4096 else -1


def _context_around(data: bytes, offset: int, length: int, radius: int = 40) -> str:
    start = max(0, offset - radius)
    end = min(len(data), offset + length + radius)
    text = data[start:end].decode("latin-1", "replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return cleaned.strip(".")


def _short_context(values: list[str], limit: int = 70) -> str:
    parts: list[str] = []
    for value in values:
        text = value.replace("\n", " ").strip()
        if text:
            parts.append(text)
    joined = " | ".join(parts)
    if len(joined) > limit:
        joined = joined[:limit] + "..."
    return joined


# --------------------------------------------------------------------------- #
# .NET assemblies
# --------------------------------------------------------------------------- #
def _scan_assembly(path: str, result: ScanResult) -> None:
    data = _read_file(path, result.warnings)
    if data is None:
        return
    try:
        pe = PEImage(data)
        meta = dnmeta.Metadata(data)
        entries = meta.user_strings()
    except (PEError, dnmeta.MetadataError):
        return
    except Exception as exc:  # noqa: BLE001 - never let one file kill a scan
        result.warnings.append(f"{os.path.basename(path)}: metadata parse failed ({exc})")
        return

    result.managed_assemblies += 1
    names = meta.strings_heap_peek()
    values = [entry.value for entry in entries]
    joined_values = "\n".join(values)
    evidence = _evidence(names + "\n" + joined_values + "\n" + os.path.basename(path))
    for marker in evidence:
        if marker not in result.evidence:
            result.evidence.append(marker)
    _collect_endpoints(values, result)
    if not evidence:
        return

    _scan_literals(
        path=path,
        kind="us",
        values=values,
        result=result,
        offset_of=lambda index: entries[index].data_offset - entries[index].prefix_len,
        extra_of=lambda index: {
            "heap_offset": entries[index].heap_offset,
            "capacity": entries[index].capacity,
            "prefix_len": entries[index].prefix_len,
            "byte_len": entries[index].byte_len,
        },
        encoding="utf-16-le",
    )

    # ``const string`` values live in the #Blob heap (not #US), so scan the raw
    # image as well; those can only be replaced with a same-length value.
    classified = {
        site.value: (site.role, site.confidence)
        for site in result.sites
        if site.path == path and site.kind == "us"
    }
    covered = [
        (entry.data_offset - entry.prefix_len, entry.data_offset - entry.prefix_len + entry.capacity)
        for entry in entries
    ]

    for match in TITLE_BARE_RE.finditer(data):
        offset = match.start()
        if any(start <= offset < end for start, end in covered):
            continue
        value = match.group().decode("ascii")
        near = data[max(0, offset - 96) : offset + 96].lower()
        if not any(token in near for token in (b"titleid", b"playfab")):
            continue
        if value in classified:
            role, confidence = classified[value]
        else:
            role, confidence = TITLE_ID, 0.55
        result.sites.append(
            Site(
                path=path,
                kind="raw",
                offset=offset,
                encoding="utf-8",
                value=value,
                role=role,
                confidence=confidence,
                context=_context_around(data, offset, len(value)),
                extra={"length": len(value), "blob": True},
            )
        )
        covered.append((offset, offset + len(value)))


def _scan_literals(
    path: str,
    kind: str,
    values: list[str],
    result: ScanResult,
    offset_of,
    extra_of,
    encoding: str,
) -> None:
    """Classify every string literal of an assembly / metadata blob.

    A literal only counts when its own text or the literals around it name a
    PlayFab field: assemblies are full of short upper case tokens (enum names,
    log levels) that would otherwise look like title ids.
    """
    def add(
        index: int,
        shown: str,
        role: str,
        span: list[int],
        confidence: float,
        extra: dict | None = None,
    ) -> None:
        """Record one setting; ``span`` is where it sits inside the literal."""
        result.sites.append(
            Site(
                path=path,
                kind=kind,
                offset=offset_of(index) + (2 * span[0] if encoding == "utf-16-le" else span[0]),
                encoding=encoding,
                value=shown,
                role=role,
                confidence=confidence,
                context=_short_context(values[max(0, index - 3) : index + 4]),
                extra={
                    **extra_of(index),
                    **(extra or {}),
                    "span": span,
                    "full_value": values[index],
                },
            )
        )

    for index, value in enumerate(values):
        # Only the literal's immediate neighbours describe it.  Both heaps are
        # sorted, so a wide window drags in every PlayFab SDK method name and
        # turns ordinary tokens ("Bundle", "/Client/RegisterPlayFabUser") into
        # settings that do not exist.
        near = " | ".join(
            values[max(0, index - 3) : index] + values[index + 1 : index + 4]
        ).lower()

        # 1) The whole literal is the setting.
        if looks_like_endpoint(value):
            extra: dict = {}
            found = title_in_endpoint(value)
            if found is not None:
                extra["title_span"] = [found[0], found[1]]
                extra["title_id"] = found[2]
            add(index, value, API_URL, [0, len(value)], 0.85, extra)
            continue
        if SECRET_KEY_HINT_RE.search(near) and _literal_secret(value):
            add(index, value, SECRET_KEY, [0, len(value)], 0.9)
            continue
        if TITLE_KEY_HINT_RE.search(near) and _literal_title(value):
            add(index, value, TITLE_ID, [0, len(value)], 0.9)
            continue
        if "playfab" in near and _literal_title(value, strict=True):
            add(index, value, TITLE_ID, [0, len(value)], 0.7)
            continue

        # 2) The literal carries the setting inside a folded string
        #    ("titleid=A89CF;secret=..."), which is what a C# const becomes.
        for match in LITERAL_TITLE_RE.finditer(value):
            add(index, match.group(1), TITLE_ID, [match.start(1), match.end(1)], 0.9)
        for match in LITERAL_SECRET_RE.finditer(value):
            add(index, match.group(1), SECRET_KEY, [match.start(1), match.end(1)], 0.85)
        for match in LITERAL_URL_RE.finditer(value):
            extra = {}
            found = title_in_endpoint(match.group())
            if found is not None:
                extra["title_span"] = [found[0], found[1]]
                extra["title_id"] = found[2]
            add(index, match.group(), API_URL, [match.start(), match.end()], 0.85, extra)


# --------------------------------------------------------------------------- #
# IL2CPP
# --------------------------------------------------------------------------- #
def _scan_global_metadata(path: str, result: ScanResult) -> None:
    data = _read_file(path, result.warnings)
    if data is None:
        return
    try:
        meta = il2cpp.GlobalMetadata(data)
    except il2cpp.Il2CppError as exc:
        result.warnings.append(f"global-metadata.dat: {exc}")
        return
    except Exception as exc:  # noqa: BLE001
        result.warnings.append(f"global-metadata.dat: parse failed ({exc})")
        return

    result.il2cpp_version = meta.version
    values = [literal.value for literal in meta.literals]
    joined = "\n".join(values)
    evidence = _evidence(joined)
    for marker in evidence:
        if marker not in result.evidence:
            result.evidence.append(marker)
    _collect_endpoints(values, result)
    if not evidence:
        return

    _scan_literals(
        path=path,
        kind="il2cpp",
        values=values,
        result=result,
        offset_of=lambda index: meta.literals[index].offset,
        extra_of=lambda index: {
            "literal_index": meta.literals[index].index,
            "length": meta.literals[index].length,
            "data_index": meta.literals[index].data_index,
        },
        encoding="utf-8",
    )


def _collect_endpoints(values: list[str], result: ScanResult) -> None:
    for value in values:
        lowered = value.lower()
        for hint in SERVER_HINTS:
            if hint in lowered and hint not in result.server_hints:
                result.server_hints.append(hint)
        match = URL_TEXT_RE.search(value)
        if match and "playfab" in match.group().lower():
            endpoint = match.group()
            if endpoint not in result.endpoints:
                result.endpoints.append(endpoint)


# --------------------------------------------------------------------------- #
# asset / bundle / text blobs
# --------------------------------------------------------------------------- #
def _scan_blob(path: str, result: ScanResult, textual: bool, progress=None) -> None:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result.warnings.append(f"cannot stat {path}: {exc}")
        return
    if size > MAX_BLOB:
        _scan_blob_windowed(path, size, result, textual, progress)
        return
    data = _read_file(path, result.warnings)
    if data is None:
        return
    result.blob_files += 1
    _scan_blob_data(path, data, result, textual)


def _scan_blob_data(path: str, data: bytes, result: ScanResult, textual: bool) -> None:
    _scan_playfab_objects(path, data, result)
    # Player builds strip the type tree, so PlayFab names can sit anywhere in a
    # large asset; sample the whole file instead of only its head.
    samples = [data[: 1024 * 1024]]
    if len(data) > 1024 * 1024:
        samples.append(data[-1024 * 1024 :])
        step = 8 * 1024 * 1024
        for start in range(step, len(data) - 1024 * 1024, step):
            samples.append(data[start : start + 1024 * 1024])
    scanned = b"\n".join(samples).lower()
    blob_evidence = _evidence(
        scanned.decode("latin-1", "replace") + " " + os.path.basename(path).lower()
    )
    for marker in blob_evidence:
        if marker not in result.evidence:
            result.evidence.append(marker)
    if not blob_evidence and not any(site.path == path for site in result.sites):
        return

    seen_offsets: set[int] = {site.offset for site in result.sites if site.path == path}

    # 1) Unity length-prefixed key/value pairs (works for resources.assets).
    for key in PLAYFAB_KEYS:
        needle = key.encode("ascii")
        start = 0
        while True:
            position = data.find(needle, start)
            if position < 0:
                break
            start = position + 1
            if position < 4:
                continue
            # Skip when this is only part of a longer identifier.
            if position > 0 and (data[position - 1 : position].isalnum() or data[position - 1] == 95):
                continue
            # Only when the key itself is stored as a Unity string.
            key_prefix = position - 4
            key_len = struct.unpack_from("<i", data, key_prefix)[0]
            if key_len != len(needle):
                continue
            value_position = _slot_end(data, key_prefix, key_len)
            parsed = _read_unity_string(data, value_position)
            if parsed is None:
                continue
            value, value_end = parsed
            role = _role_from_key(key)
            if not _value_fits_role(role, value):
                continue
            slot_end = _slot_end(data, value_position, len(value.encode("utf-8")))
            if value_position + 4 in seen_offsets:
                continue
            result.sites.append(
                Site(
                    path=path,
                    kind="unity_str",
                    offset=value_position + 4,
                    encoding="utf-8",
                    value=value,
                    role=role,
                    confidence=0.97,
                    context=f'{key}: "{value}"',
                    extra={
                        "len_field": value_position,
                        "slot": slot_end - value_position,
                        "key": key,
                    },
                )
            )
            seen_offsets.add(value_position + 4)

    # 2) Text style key: value pairs.
    if textual:
        for match in KV_RE.finditer(data):
            key = match.group(1).decode("latin-1")
            value = match.group(2).decode("latin-1").strip("\"'")
            role = _role_from_key(key)
            if not _value_fits_role(role, value):
                continue
            offset = match.start(2)
            if offset in seen_offsets:
                continue
            result.sites.append(
                Site(
                    path=path,
                    kind="text",
                    offset=offset,
                    encoding="utf-8",
                    value=value,
                    role=role,
                    confidence=0.95,
                    context=f"{key}: {value}",
                    extra={"length": len(value), "key": key},
                )
            )
            seen_offsets.add(offset)

    # 3) PlayFab endpoints, which also carry the title id in the sub domain.
    endpoints = 0
    for match in URL_BLOB_RE.finditer(data):
        if endpoints >= 8:
            break
        offset = match.start()
        value = match.group().decode("latin-1")
        value = value.rstrip(".,;)").rstrip(chr(34) + chr(39))
        if offset in seen_offsets:
            continue
        extra = {"length": len(value), "blob": True}
        found = title_in_endpoint(value)
        if found is not None:
            extra["title_span"] = [found[0], found[1]]
            extra["title_id"] = found[2]
        if _unity_string_prefix(data, offset) == len(value):
            length_field = offset - 4
            slot = _slot_end(data, length_field, len(value)) - length_field
            kind = "unity_str"
            extra.update({"len_field": length_field, "slot": slot})
            confidence = 0.95
        else:
            kind = "raw"
            confidence = 0.8
        result.sites.append(
            Site(
                path=path,
                kind=kind,
                offset=offset,
                encoding="utf-8",
                value=value,
                role=API_URL,
                confidence=confidence,
                context=_context_around(data, offset, len(value), radius=50),
                extra=extra,
            )
        )
        seen_offsets.add(offset)
        result.endpoints.append(value)
        endpoints += 1

    # 4) Bare title ids framed as a Unity string, named by nearby PlayFab text.
    for match in TITLE_BARE_RE.finditer(data):
        offset = match.start()
        if offset in seen_offsets:
            continue
        value = match.group().decode("ascii")
        if _unity_string_prefix(data, offset) != len(value):
            continue
        window = data[max(0, offset - 256) : offset + 256].decode("latin-1", "replace").lower()
        if "playfab" not in window and "titleid" not in window:
            continue
        length_field = offset - 4
        slot = _slot_end(data, length_field, len(value)) - length_field
        confidence = 0.9 if ("playfabsharedsettings" in window or "titleid" in window) else 0.75
        result.sites.append(
            Site(
                path=path,
                kind="unity_str",
                offset=offset,
                encoding="utf-8",
                value=value,
                role=TITLE_ID,
                confidence=confidence,
                context=_context_around(data, offset, len(value), radius=70),
                extra={"len_field": length_field, "slot": slot, "key": "titleid"},
            )
        )
        seen_offsets.add(offset)

    # 5) Bare secret keys framed as a Unity string, named by nearby text.
    for match in SECRET_BARE_RE.finditer(data):
        offset = match.start()
        if offset in seen_offsets:
            continue
        value = match.group().decode("latin-1")
        if _unity_string_prefix(data, offset) != len(value):
            continue
        if not looks_like_secret(value, anchored=True):
            continue
        window = data[max(0, offset - 256) : offset + 256].decode("latin-1", "replace").lower()
        if "secretkey" not in window and "developersecret" not in window:
            continue
        length_field = offset - 4
        slot = _slot_end(data, length_field, len(value)) - length_field
        result.sites.append(
            Site(
                path=path,
                kind="unity_str",
                offset=offset,
                encoding="utf-8",
                value=value,
                role=SECRET_KEY,
                confidence=0.8,
                context="developer secret key embedded in the build",
                extra={"len_field": length_field, "slot": slot, "key": "secretkey"},
            )
        )
        seen_offsets.add(offset)


def _value_fits_role(role: str, value: str) -> bool:
    if role == TITLE_ID:
        return looks_like_title_id(value)
    if role == SECRET_KEY:
        return looks_like_secret(value)
    if role == API_URL:
        return looks_like_endpoint(value) or looks_like_url(value)
    return False


def _scan_blob_windowed(
    path: str, size: int, result: ScanResult, textual: bool, progress=None
) -> None:
    """Scan an asset too large to load by mapping it and parsing windows.

    The settings of a player build live in one object buried in a multi-gigabyte
    bundle, so reading the file is pointless - it is mapped and one sequential
    pass locates every region that can hold a PlayFab setting.  Each region is
    then parsed with the same code the small-file path uses, and the offsets are
    moved back to file coordinates.
    """
    result.blob_files += 1
    name = os.path.basename(path)
    try:
        handle = open(path, "rb")
    except OSError as exc:
        result.warnings.append(f"cannot read {path}: {exc}")
        return
    with handle:
        try:
            mapping = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as exc:
            result.warnings.append(f"cannot map {name}: {exc}")
            return
        with mapping:
            hits, truncated = _window_hits(mapping, size, progress)
            if truncated:
                result.warnings.append(
                    f"{name}: PlayFab text occurs more than {WINDOW_MAX_HITS} times; "
                    "some regions were not parsed"
                )
            for start, end in _merge_windows(hits, size):
                window = mapping[start:end]
                local = ScanResult(root=result.root)
                _scan_playfab_objects(path, window, local)
                _scan_blob_data(path, window, local, textual)
                for marker in local.evidence:
                    if marker not in result.evidence:
                        result.evidence.append(marker)
                for endpoint in local.endpoints:
                    if endpoint not in result.endpoints:
                        result.endpoints.append(endpoint)
                for site in local.sites:
                    site.offset += start
                    if "len_field" in site.extra:
                        site.extra["len_field"] += start
                    result.sites.append(site)
    _dedupe_sites(result, path)


def _window_hits(mapping, size: int, progress=None) -> tuple[list[int], bool]:
    """One sequential pass over the mapping, collecting needle offsets."""
    hits: set[int] = set()
    truncated = False
    position = 0
    while position < size:
        if len(hits) >= WINDOW_MAX_HITS:
            # Keep walking so the caller knows the file was not fully covered;
            # the windows that were found are still parsed.
            truncated = True
            break
        # Lowering the chunk keeps the needles few and the match case blind:
        # the same bundle spells them PlayFabSharedSettings and titleid.
        chunk = mapping[position : position + WINDOW_CHUNK + WINDOW_OVERLAP].lower()
        for needle in WINDOW_NEEDLES:
            start = 0
            while True:
                found = chunk.find(needle, start)
                if found < 0:
                    break
                hits.add(position + found)
                start = found + 1
            if len(hits) >= WINDOW_MAX_HITS:
                break
        position += WINDOW_CHUNK
        if progress:
            progress(min(1.0, position / size if size else 1.0))
    return sorted(hits), truncated


def _merge_windows(hits: list[int], size: int) -> list[tuple[int, int]]:
    """Turn hit offsets into non overlapping [start, end) windows."""
    windows: list[tuple[int, int]] = []
    for hit in hits:
        start = max(0, hit - WINDOW_LOOKBACK)
        end = min(size, start + WINDOW_BYTES)
        if windows:
            previous_start, previous_end = windows[-1]
            if end <= previous_end:
                continue
            if start < previous_end and end - previous_start <= WINDOW_MAX:
                windows[-1] = (previous_start, end)
                continue
        windows.append((start, end))
    return windows


def _dedupe_sites(result: ScanResult, path: str) -> None:
    """Windows can overlap, so keep the best site per file offset."""
    keep: list[Site] = []
    best: dict[tuple[str, int], Site] = {}
    for site in result.sites:
        if site.path != path:
            keep.append(site)
            continue
        key = (site.kind, site.offset)
        existing = best.get(key)
        if existing is None or site.confidence > existing.confidence:
            best[key] = site
    keep.extend(best.values())
    result.sites = keep


def _scan_playfab_objects(path: str, data: bytes, result: ScanResult) -> None:
    """Find ``PlayFabSharedSettings`` and other PlayFab objects by their name.

    Player builds have no type tree, so the object name is the only anchor that
    still exists.  The SDK writes ``TitleId``, ``DeveloperSecretKey`` and
    ``ProductionEnvironmentUrl`` into the three string slots right behind the
    name, in that order, so they can be read without the field names.
    """
    if PLAYFAB_OBJECT_RE.search(data) is None:
        return
    known = {site.offset for site in result.sites if site.path == path}
    for match in PLAYFAB_OBJECT_RE.finditer(data):
        name_length = len(match.group())
        if _unity_string_prefix(data, match.start()) != name_length:
            continue
        name = match.group().decode("latin-1")
        position = _slot_end(data, match.start() - 4, name_length)
        is_settings = name.lower() == SETTINGS_NAME
        limit = min(len(data), position + 8192)
        found: dict[str, bool] = {}

        for slot in range(SETTINGS_MAX_SLOTS if is_settings else 1):
            prefix = position
            parsed = _read_unity_string(data, prefix)
            if parsed is None:
                break
            value, value_end = parsed
            encoded_length = len(value.encode("utf-8"))
            slot_end = _slot_end(data, prefix, encoded_length)
            position = max(slot_end, value_end)
            if position > limit:
                break
            if not value:
                continue
            role = role_for_value(value)
            if role is None or role in found:
                continue
            if role == TITLE_ID and not looks_like_title_id(value):
                continue
            if role == SECRET_KEY and not looks_like_secret(value):
                continue
            if role == API_URL and not (looks_like_endpoint(value) or looks_like_url(value)):
                continue
            found[role] = True
            offset = value_end - encoded_length
            if offset in known:
                continue
            extra = {
                "length": len(value),
                "blob": True,
                "len_field": prefix,
                "slot": slot_end - prefix,
                "slot_index": slot,
                "object": name,
            }
            if role == API_URL:
                endpoint_title = title_in_endpoint(value)
                if endpoint_title is not None:
                    extra["title_span"] = [endpoint_title[0], endpoint_title[1]]
                    extra["title_id"] = endpoint_title[2]
                    result.endpoints.append(value)
            confidence = 0.97 if is_settings else 0.7
            if role == SECRET_KEY:
                confidence = 0.98
            result.sites.append(
                Site(
                    path=path,
                    kind="unity_str",
                    offset=offset,
                    encoding="utf-8",
                    value=value,
                    role=role,
                    confidence=confidence,
                    context=f"{name} slot {slot + 1}",
                    extra=extra,
                )
            )
            known.add(offset)


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #
def _collect(root: str, deep: bool) -> tuple[list[str], list[str], list[str], list[str]]:
    assemblies: list[str] = []
    metadata: list[str] = []
    assets: list[str] = []
    texts: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".playfabpatcher", "__pycache__", ".git")]
        in_managed = os.path.basename(dirpath).lower() == "managed"
        for name in filenames:
            lowered = name.lower()
            path = os.path.join(dirpath, name)
            if lowered.endswith(".pfbak"):
                continue
            if lowered == "global-metadata.dat":
                metadata.append(path)
            elif lowered.endswith(".dll") and (in_managed or deep):
                assemblies.append(path)
            elif lowered.endswith(ASSET_EXTENSIONS) or lowered in ("globalgamemanagers", "resources.assets"):
                assets.append(path)
            elif lowered.endswith(TEXT_EXTENSIONS):
                texts.append(path)
            elif deep and not lowered.endswith((".exe", ".so", ".dylib", ".dat", ".pak")):
                assets.append(path)
    return assemblies, metadata, assets, texts


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def scan(root: str, deep: bool = False, progress=None) -> ScanResult:
    started = time.time()
    root = os.path.abspath(root)
    env = detect_environment(root)
    result = ScanResult(
        root=root,
        backend=env["backend"],
        unity_version=env["unity_version"],
        game_name=env["game_name"],
    )
    if not os.path.isdir(root):
        result.warnings.append(f"{root} is not a directory")
        return result

    assemblies, metadata, assets, texts = _collect(root, deep)
    jobs: list[tuple[str, str]] = []
    jobs += [(path, "assembly") for path in assemblies]
    jobs += [(path, "il2cpp") for path in metadata]
    jobs += [(path, "asset") for path in assets]
    jobs += [(path, "text") for path in texts]

    for done, (path, job) in enumerate(jobs, start=1):
        relative = os.path.relpath(path, root)
        if progress:
            progress(done, len(jobs), relative)

        def file_progress(fraction, _done=done, _relative=relative):
            if progress:
                progress(_done, len(jobs), f"{_relative} {int(fraction * 100)}%")

        try:
            if job == "assembly":
                _scan_assembly(path, result)
            elif job == "il2cpp":
                _scan_global_metadata(path, result)
            elif job == "asset":
                _scan_blob(path, result, textual=False, progress=file_progress)
            else:
                _scan_blob(path, result, textual=True, progress=file_progress)
        except Exception as exc:  # noqa: BLE001
            result.warnings.append(f"{os.path.basename(path)}: {exc}")
        result.files_scanned += 1

    result.sites.sort(key=lambda site: (site.path.lower(), site.offset))
    result.elapsed = time.time() - started
    for site in result.secret_keys:
        result.warnings.append(
            f"a developer secret key is stored in {os.path.basename(site.path)}; "
            "clients must not ship one - treat it as leaked and rotate it"
        )
        break
    if not result.sites:
        result.warnings.append(
            "no PlayFab settings detected - the game may be protected, packed, "
            "or simply not use PlayFab"
        )
    return result
