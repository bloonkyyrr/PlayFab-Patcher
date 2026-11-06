# PlayFab Patcher

Repoint a Unity game's **PlayFab** title at another title, with backups and
verification. Standalone tool, standard library only (Python 3.10+), Tkinter GUI
plus a full CLI.

Two things are found and rewritten:

* **Title id** – `A89CF`, `BDFF1`, … (4–6 characters, `TitleId`).
* **Developer secret key** – `DeveloperSecretKey` (server builds only).
* **Environment endpoint** – `ApiUrl` / `ProductionEnvironmentUrl`, e.g.
  `https://A89CF.playfabapi.com/`.

Endpoints follow the new title id automatically: change `A89CF` into `C0FFE` and
`https://A89CF.playfabapi.com/` becomes `https://C0FFE.playfabapi.com/`. Pass
`--api-url` to point at a proxy instead and the literal endpoint is used as is.

## Quick start

```bat
run.bat                                         :: GUI
```

```bash
python -m playfabpatcher scan   "<game folder>"              # what is patchable
python -m playfabpatcher patch  "<game folder>" --title-id C0FFE
python -m playfabpatcher verify "<game folder>" --title-id C0FFE
python -m playfabpatcher restore "<game folder>"
```

`<game folder>` is the folder that holds `<Game>_Data` (the one with the `.exe`).
Always run `scan` first; `patch` without `--yes` prints the plan and asks.

Useful flags:

| flag | meaning |
| --- | --- |
| `--title-id` | new title id (required to change it) |
| `--secret-key` | new developer secret key |
| `--api-url` | fixed endpoint instead of following the title id |
| `--dry-run` | plan and write nothing |
| `--only-old A89CF,BDFF1` | restrict to specific current values |
| `--file data.unity3d` | restrict to files whose path contains this text |
| `--role BDFF1=title` | label a value the scanner could not classify |
| `--skip-unclassified` | only touch values proven to be PlayFab settings |
| `--no-fill` | do not reuse the title id for unclassified ids in PlayFab objects |
| `--deep` | also scan non-standard files (`scan`, `verify`) |
| `--json report.json` | machine readable scan report |

## What gets detected

Detection is anchored: a short token only counts when something names it as a
PlayFab setting, so class names, log levels and enum values are not reported.

* **Unity settings object** – `PlayFabSharedSettings` (and other `PlayFab*`
  objects) in `*.unity3d` / `*.assets` / `resources.assets`. The object, its
  field names and the length-prefixed value slots are located, so `TitleId`,
  `DeveloperSecretKey` and `ProductionEnvironmentUrl` are found even when the
  type tree has been stripped from a player build.
* **Key-anchored Unity strings** – a `TitleId` / `DeveloperSecretKey` /
  `ProductionEnvironmentUrl` key stored as a Unity string, with the value in the
  next slot. Reported at 0.97 confidence.
* **Text configs** – `.json`, `.xml`, `.txt`, `.cfg`, `.ini`, `.yaml`:
  `"titleId": "A89CF"`, `titleId=A89CF`, `developerSecretKey: ...`.
* **Compiled literals** – `#US` heap literals in Mono assemblies and IL2CPP
  string literals in `global-metadata.dat`, including compiler-folded strings
  such as `"titleid=A89CF;secret=...;url=https://A89CF.playfabapi.com/"`.
* **Endpoints** – any `*.playfabapi.com` URL; the title id is read from the
  sub-domain.

Rules that keep it honest:

* Title ids are 4–6 upper case characters containing at least one letter;
  unanchored candidates must be pure hex (`A89CF`, `BDFF1`) so words like
  `GZIP` or `Bundle` never match.
* A secret key is 20–100 base64-ish characters (32+ when nothing anchors it)
  and must contain a digit; field names and URLs are rejected.
* The token must sit next to its field name (or inside a folded literal); a
  sorted heap is not allowed to imply a setting from far-away neighbours.

## Safety

* **Backups** – every file is copied to `<game>/.playfabpatcher/backups/...`
  before it is written, together with `manifest.json`.
* **Large bundles** – files over 512 MB are not copied. They are memory-mapped,
  scanned in windows, patched in place and the exact original bytes are
  journaled in the manifest, so restore is still byte-exact.
* **All or nothing per value** – a value is only rewritten when the bytes on
  disk still equal what the scan saw; otherwise it is reported as failed
  ("file on disk differs from the scan") instead of being guessed at.
* **Restore is verified** – `restore` writes the backed-up or journaled bytes
  back and `verify` re-scans to confirm the result.
* Same-length updates (title id for title id) are written in place; longer
  values are moved inside the heap when the space allows it.

A full patch → verify → restore round-trip on a real 4.6 GB IL2CPP bundle
(Secret Neighbor 01.04) reproduced the original file byte for byte (identical
MD5).

## Limitations

* Values inside compressed containers (LZ4/LZMA blocks of an AssetBundle) are
  not rewritten; PlayFab settings in those builds are only found when they sit
  in an uncompressed part of the file.
* Raw byte patching can only change a value to one of the same length outside a
  parsed heap; shorter values are padded, so a 6-character id cannot become a
  4-character one in a blob.
* Values obfuscated or encrypted by the game cannot be detected.
* The developer secret key is a server credential. In a client build it is
  already leaked – rotate it in PlayFab Game Manager instead of relying on this
  tool.

## Tests

```bash
python -m unittest discover -s tests
```

20 tests cover the settings object, key-anchored strings, folded literals
(compiled with `csc` when available), text configs, the windowed large-bundle
path, patch/restore round-trips and the value-shape rules.
