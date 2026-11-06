"""Tkinter front end for the PlayFab patcher.

The window is deliberately plain: pick a game folder, scan it, tick the settings
you want to change, type your own values and press Patch.  Everything runs on a
worker thread so the window keeps repainting while large assets are scanned.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from . import patch as patch_mod
from . import scan as scan_mod

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".playfab_patcher.json")
ROLE_ORDER = (
    scan_mod.TITLE_ID,
    scan_mod.SECRET_KEY,
    scan_mod.API_URL,
    scan_mod.UNCLASSIFIED,
)
CHECKED, UNCHECKED = "\u2611", "\u2610"
KIND_LABELS = {
    "us": "assembly literal",
    "il2cpp": "il2cpp literal",
    "unity_str": "unity asset",
    "text": "text config",
    "raw": "binary blob",
}


class PatcherApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"PlayFab Patcher {__version__}")
        self.geometry("1180x760")
        self.minsize(940, 600)

        self.events: queue.Queue = queue.Queue()
        self.sites: dict[str, scan_mod.Site] = {}
        self.checked: set[str] = set()
        self.roles: dict[str, str] = {}
        self.result: scan_mod.ScanResult | None = None
        self.busy = False

        self.folder_var = tk.StringVar()
        self.title_id_var = tk.StringVar()
        self.secret_key_var = tk.StringVar()
        self.api_url_var = tk.StringVar()
        self.follow_var = tk.BooleanVar(value=True)
        self.unclassified_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Pick a game folder and press Scan")
        self.info_var = tk.StringVar(value="")

        self._build_widgets()
        self._load_settings()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._drain_events)

    # ------------------------------------------------------------------ ui --
    def _build_widgets(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Mono.TLabel", font=("Consolas", 9))

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(4, weight=1)
        outer.rowconfigure(6, weight=1)

        folder_row = ttk.Frame(outer)
        folder_row.grid(row=0, column=0, sticky="ew")
        folder_row.columnconfigure(1, weight=1)
        ttk.Label(folder_row, text="Game folder").grid(row=0, column=0, padx=(0, 6))
        ttk.Entry(folder_row, textvariable=self.folder_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(folder_row, text="Browse...", command=self._browse, width=10).grid(
            row=0, column=2, padx=6
        )
        self.scan_button = ttk.Button(folder_row, text="Scan", command=self._start_scan, width=10)
        self.scan_button.grid(row=0, column=3)

        self.info_label = ttk.Label(outer, textvariable=self.info_var, style="Mono.TLabel")
        self.info_label.grid(row=1, column=0, sticky="w", pady=(6, 8))

        settings = ttk.LabelFrame(outer, text="Your PlayFab settings", padding=8)
        settings.grid(row=3, column=0, sticky="ew")
        settings.columnconfigure(1, weight=1)

        ttk.Label(settings, text="Title id").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(settings, textvariable=self.title_id_var, width=14).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Label(
            settings,
            text="4-6 characters, e.g. A89CF (copied from the game when you scan)",
            foreground="#666666",
        ).grid(row=0, column=2, sticky="w", padx=(10, 0))

        ttk.Label(settings, text="Environment URL").grid(
            row=1, column=0, sticky="w", padx=(0, 6), pady=(6, 0)
        )
        ttk.Entry(settings, textvariable=self.api_url_var).grid(
            row=1, column=1, columnspan=2, sticky="ew", pady=(6, 0)
        )

        ttk.Label(settings, text="Secret key").grid(
            row=2, column=0, sticky="w", padx=(0, 6), pady=(6, 0)
        )
        self.secret_entry = ttk.Entry(settings, textvariable=self.secret_key_var, show="*")
        self.secret_entry.grid(row=2, column=1, columnspan=2, sticky="ew", pady=(6, 0))
        self.show_secret = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            settings,
            text="show",
            variable=self.show_secret,
            command=self._toggle_secret,
        ).grid(row=2, column=3, sticky="w", padx=(8, 0), pady=(6, 0))

        checks = ttk.Frame(settings)
        checks.grid(row=3, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Checkbutton(
            checks,
            text="Follow the title id inside *.playfabapi.com endpoints",
            variable=self.follow_var,
        ).pack(anchor="w")
        ttk.Checkbutton(
            checks,
            text="Also patch short ids found in other PlayFab objects",
            variable=self.unclassified_var,
        ).pack(anchor="w", pady=(4, 0))

        ttk.Label(
            settings,
            text="Leave a field empty to keep what the game already has. "
            "Clients never need a developer secret key.",
            foreground="#666666",
        ).grid(row=4, column=0, columnspan=4, sticky="w", pady=(8, 0))

        actions = ttk.Frame(outer)
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.patch_button = ttk.Button(actions, text="Patch", command=self._start_patch, width=12)
        self.patch_button.pack(side="left")
        self.restore_button = ttk.Button(
            actions, text="Restore backups", command=self._start_restore, width=16
        )
        self.restore_button.pack(side="left", padx=6)
        self.verify_button = ttk.Button(actions, text="Verify", command=self._start_verify, width=10)
        self.verify_button.pack(side="left")
        ttk.Button(actions, text="All", command=lambda: self._check_all(True), width=6).pack(
            side="left", padx=(18, 2)
        )
        ttk.Button(actions, text="None", command=lambda: self._check_all(False), width=6).pack(
            side="left", padx=2
        )
        ttk.Button(actions, text="Suggested", command=self._select_suggested, width=10).pack(
            side="left", padx=2
        )
        self.progress = ttk.Progressbar(actions, mode="determinate", length=180)
        self.progress.pack(side="right")

        table = ttk.Frame(outer)
        table.grid(row=4, column=0, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)

        columns = ("pick", "role", "file", "kind", "old", "conf", "status")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", selectmode="browse")
        headings = {
            "pick": "",
            "role": "Role",
            "file": "File",
            "kind": "Found in",
            "old": "Current value",
            "conf": "Conf",
            "status": "Result",
        }
        widths = {
            "pick": 34,
            "role": 140,
            "file": 280,
            "kind": 112,
            "old": 300,
            "conf": 50,
            "status": 190,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w", stretch=column in ("file", "old"))
        self.tree.column("pick", anchor="center", stretch=False)
        self.tree.column("conf", anchor="center", stretch=False)
        self.tree.tag_configure("low", foreground="#888888")
        self.tree.tag_configure("done", foreground="#0a7d28")
        self.tree.tag_configure("failed", foreground="#b00020")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        log_frame = ttk.LabelFrame(outer, text="Log", padding=6)
        log_frame.grid(row=6, column=0, sticky="nsew", pady=(8, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = tk.Text(log_frame, height=8, wrap="word", font=("Consolas", 9))
        self.log.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=log_scroll.set, state="disabled")

        ttk.Label(outer, textvariable=self.status_var, anchor="w").grid(
            row=7, column=0, sticky="ew", pady=(8, 0)
        )

    def _toggle_secret(self) -> None:
        self.secret_entry.configure(show="" if self.show_secret.get() else "*")

    # -------------------------------------------------------------- helpers --
    def _log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.scan_button, self.patch_button, self.restore_button, self.verify_button):
            button.configure(state=state)
        if message:
            self.status_var.set(message)
        if not busy:
            self.progress.configure(value=0)

    def _browse(self) -> None:
        initial = self.folder_var.get() or os.path.expanduser("~")
        chosen = filedialog.askdirectory(title="Select the folder that contains the game", initialdir=initial)
        if chosen:
            self.folder_var.set(os.path.normpath(chosen))
            self._start_scan()

    def _folder(self) -> str | None:
        folder = self.folder_var.get().strip().strip('"')
        if not folder:
            messagebox.showinfo("PlayFab Patcher", "Pick the game folder first.")
            return None
        if not os.path.isdir(folder):
            messagebox.showerror("PlayFab Patcher", f"{folder}\nis not a folder.")
            return None
        return folder

    # --------------------------------------------------------------- events --
    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self._log(event[1])
                elif kind == "progress":
                    _, done, total, name = event
                    if total:
                        self.progress.configure(maximum=total, value=done)
                    self.status_var.set(f"{name}  ({done}/{total})")
                elif kind == "scan_done":
                    self._show_scan(event[1])
                elif kind == "patch_done":
                    self._show_report(event[1], event[2])
                elif kind == "restore_done":
                    self._show_restore(event[1])
                elif kind == "verify_done":
                    self._show_verify(event[1], event[2], event[3])
                elif kind == "error":
                    self._log(f"ERROR: {event[1]}")
                    self.status_var.set("Failed - see the log")
                    self._set_busy(False)
                    messagebox.showerror("PlayFab Patcher", event[1])
        except queue.Empty:
            pass
        self.after(80, self._drain_events)

    # ---------------------------------------------------------------- scan --
    def _start_scan(self) -> None:
        if self.busy:
            return
        folder = self._folder()
        if folder is None:
            return
        self._set_busy(True, "Scanning...")
        self._log(f"Scanning {folder}")
        threading.Thread(target=self._scan_worker, args=(folder,), daemon=True).start()

    def _scan_worker(self, folder: str) -> None:
        try:
            result = scan_mod.scan(
                folder,
                deep=False,
                progress=lambda done, total, name: self.events.put(("progress", done, total, name)),
            )
        except Exception as exc:  # noqa: BLE001 - surfaced in the window
            self.events.put(("error", f"scan failed: {exc}"))
            return
        self.events.put(("scan_done", result))

    def _show_scan(self, result: scan_mod.ScanResult) -> None:
        self.result = result
        self.tree.delete(*self.tree.get_children())
        self.sites.clear()
        self.checked.clear()
        self.roles.clear()

        summary = f"{result.backend}"
        if result.unity_version:
            summary += f" | Unity {result.unity_version}"
        summary += f" | {result.files_scanned} files scanned"
        if result.endpoints:
            summary += f" | endpoints: {', '.join(result.endpoints[:2])}"
        self.info_var.set(summary)

        for site in result.sites:
            iid = site.uid
            self.sites[iid] = site
            self.roles[iid] = site.role
            if site.confidence >= 0.8:
                self.checked.add(iid)
            self.tree.insert("", "end", iid=iid, values=self._row_values(site, iid), tags=self._row_tags(site))

        for warning in result.warnings[:10]:
            self._log(f"warning: {warning}")
        if result.evidence:
            self._log(f"PlayFab evidence: {', '.join(result.evidence[:8])}")
        if not result.sites:
            self._log("No patchable PlayFab settings found in this folder.")
            messagebox.showwarning(
                "PlayFab Patcher",
                "No PlayFab settings were found.\n\n"
                "The game may be packed, may not use PlayFab, or the title id may live "
                "in an unusual file. On IL2CPP builds make sure GlobalMetadata is present.",
            )
        else:
            self._log(f"{len(result.sites)} candidate(s) found in {result.elapsed:.2f}s.")
            if result.title_ids:
                self._log(f"title ids: {', '.join(result.title_ids[:6])}")
            self._prefill_from_scan(result)
        self._set_busy(False, f"{len(result.sites)} candidate(s) - tick the ones to change, then Patch")

    def _prefill_from_scan(self, result: scan_mod.ScanResult) -> None:
        fields = {
            scan_mod.TITLE_ID: self.title_id_var,
            scan_mod.SECRET_KEY: self.secret_key_var,
            scan_mod.API_URL: self.api_url_var,
        }
        for role, variable in fields.items():
            if variable.get().strip():
                continue
            for site in result.sites:
                if site.role == role:
                    variable.set(site.value)
                    break

    def _row_values(self, site: scan_mod.Site, iid: str) -> tuple[str, ...]:
        return (
            CHECKED if iid in self.checked else UNCHECKED,
            self.roles.get(iid, site.role),
            self._short_path(site.path),
            KIND_LABELS.get(site.kind, site.kind),
            self._short_value(site.value),
            f"{site.confidence:.2f}",
            "",
        )

    def _row_tags(self, site: scan_mod.Site) -> tuple[str, ...]:
        return ("low",) if site.confidence < 0.8 else ()

    def _refresh_row(self, iid: str) -> None:
        site = self.sites.get(iid)
        if site is not None:
            self.tree.item(iid, values=self._row_values(site, iid), tags=self._row_tags(site))

    def _short_path(self, path: str) -> str:
        root = (self.result.root if self.result else "") or ""
        if root and path.startswith(root):
            path = os.path.relpath(path, root)
        return path if len(path) <= 58 else "..." + path[-55:]

    def _short_value(self, value: str) -> str:
        text = value.replace("\n", " ")
        return text if len(text) <= 44 else text[:41] + "..."

    # ----------------------------------------------------------- selection --
    def _on_tree_click(self, event) -> None:
        if self.busy:
            return
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#1":
            return
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.sites:
            return
        if iid in self.checked:
            self.checked.discard(iid)
        else:
            self.checked.add(iid)
        self._refresh_row(iid)
        return "break"

    def _on_tree_double_click(self, event) -> None:
        if self.busy:
            return
        if self.tree.identify_column(event.x) != "#2":
            return
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.sites:
            return
        current = self.roles.get(iid, self.sites[iid].role)
        try:
            index = ROLE_ORDER.index(current)
        except ValueError:
            index = -1
        self.roles[iid] = ROLE_ORDER[(index + 1) % len(ROLE_ORDER)]
        self._refresh_row(iid)
        self._log(f"{self.sites[iid].filename}: role is now {self.roles[iid]}")
        return "break"

    def _check_all(self, checked: bool) -> None:
        for iid in self.sites:
            if checked:
                self.checked.add(iid)
            else:
                self.checked.discard(iid)
            self._refresh_row(iid)

    def _select_suggested(self) -> None:
        for iid, site in self.sites.items():
            if site.confidence >= 0.8:
                self.checked.add(iid)
            else:
                self.checked.discard(iid)
            self._refresh_row(iid)

    # --------------------------------------------------------------- patch --
    def _target(self) -> patch_mod.Target | None:
        values = {
            "Title id": (self.title_id_var.get().strip(), scan_mod.TITLE_ID),
            "Environment URL": (self.api_url_var.get().strip(), scan_mod.API_URL),
            "Secret key": (self.secret_key_var.get().strip(), scan_mod.SECRET_KEY),
        }
        if not any(value for value, _role in values.values()):
            messagebox.showinfo("PlayFab Patcher", "Type at least one value to write into the game.")
            return None
        for label, (value, role) in values.items():
            if value:
                problem = patch_mod.validate_value(value, role)
                if problem:
                    messagebox.showerror("PlayFab Patcher", f"{label}: {problem}")
                    return None
        return patch_mod.Target(
            title_id=values["Title id"][0] or None,
            api_url=values["Environment URL"][0] or None,
            secret_key=values["Secret key"][0] or None,
            patch_unclassified=self.unclassified_var.get(),
            fill_from_title_id=self.follow_var.get(),
        )

    def _selected_sites(self) -> list[scan_mod.Site]:
        selected = []
        for iid in self.checked:
            site = self.sites.get(iid)
            if site is None:
                continue
            role = self.roles.get(iid, site.role)
            if role != site.role:
                site = scan_mod.Site(
                    path=site.path,
                    kind=site.kind,
                    offset=site.offset,
                    encoding=site.encoding,
                    value=site.value,
                    role=role,
                    confidence=site.confidence,
                    context=site.context,
                    extra=dict(site.extra),
                )
            selected.append(site)
        return selected

    def _start_patch(self) -> None:
        if self.busy:
            return
        folder = self._folder()
        if folder is None:
            return
        if not self.sites:
            messagebox.showinfo("PlayFab Patcher", "Scan the game first.")
            return
        target = self._target()
        if target is None:
            return
        sites = self._selected_sites()
        if not sites:
            messagebox.showinfo("PlayFab Patcher", "Tick at least one setting to patch.")
            return
        planned = patch_mod.plan(sites, target)
        todo = [change for change in planned if change.status == "pending"]
        if not todo:
            messagebox.showinfo("PlayFab Patcher", "Nothing selected has a value to write.")
            return
        detail = "\n".join(
            f"  {change.site.filename}: {self._short_value(change.site.value)} -> "
            f"{self._short_value(change.new_value)}"
            for change in todo[:12]
        )
        if len(todo) > 12:
            detail += f"\n  ... and {len(todo) - 12} more"
        if not messagebox.askyesno(
            "Apply patch",
            f"Write {len(todo)} new value(s) into:\n{folder}\n\n{detail}\n\n"
            "Backups are written to .playfabpatcher so you can restore.",
        ):
            return
        self._set_busy(True, "Patching...")
        self._log(f"Patching {len(todo)} setting(s)")
        threading.Thread(target=self._patch_worker, args=(folder, planned), daemon=True).start()

    def _patch_worker(self, folder: str, changes: list[patch_mod.Change]) -> None:
        try:
            report = patch_mod.apply(
                folder,
                changes,
                progress=lambda done, total, name: self.events.put(("progress", done, total, name)),
            )
        except Exception as exc:  # noqa: BLE001
            self.events.put(("error", f"patch failed: {exc}"))
            return
        self.events.put(("patch_done", report, changes))

    def _show_report(self, report: patch_mod.PatchReport, changes: list[patch_mod.Change]) -> None:
        for change in changes:
            iid = change.site.uid
            if iid in self.tree.get_children():
                status = {
                    "patched": "patched",
                    "failed": f"failed: {change.message}",
                    "skipped": f"skipped: {change.message}",
                }.get(change.status, change.status)
                self.tree.set(iid, "status", status)
                tags = ("done",) if change.status == "patched" else ("failed",)
                if change.status == "skipped":
                    tags = ()
                self.tree.item(iid, tags=tags)
        for warning in report.warnings:
            self._log(f"warning: {warning}")
        for error in report.errors:
            self._log(f"error: {error}")
        root = self.result.root if self.result else folder_or_none(changes)
        for path in report.written_files:
            self._log(f"written: {os.path.relpath(path, root) if root else path}")
        self._log(f"Done: {report.summary()} in {report.elapsed:.2f}s")
        self._set_busy(False, report.summary())
        if report.failed:
            messagebox.showwarning(
                "PlayFab Patcher",
                f"{len(report.failed)} setting(s) could not be patched.\nSee the log for the reason.",
            )
        else:
            messagebox.showinfo(
                "PlayFab Patcher",
                f"{len(report.patched)} setting(s) patched.\n\n"
                "Start the game. If it does not connect, use Restore backups.",
            )

    # ------------------------------------------------------------- restore --
    def _start_restore(self) -> None:
        if self.busy:
            return
        folder = self._folder()
        if folder is None:
            return
        if not messagebox.askyesno(
            "Restore backups", "Put every backed up file back to its original state?"
        ):
            return
        self._set_busy(True, "Restoring...")
        threading.Thread(target=self._restore_worker, args=(folder,), daemon=True).start()

    def _restore_worker(self, folder: str) -> None:
        try:
            restored = patch_mod.restore(
                folder,
                progress=lambda done, total, name: self.events.put(("progress", done, total, name)),
            )
        except Exception as exc:  # noqa: BLE001
            self.events.put(("error", f"restore failed: {exc}"))
            return
        self.events.put(("restore_done", restored))

    def _show_restore(self, restored: list[str]) -> None:
        if not restored:
            self._log("No backups found for this folder.")
            self._set_busy(False, "Nothing to restore")
            messagebox.showinfo("PlayFab Patcher", "There are no backups for this folder.")
            return
        for path in restored:
            self._log(f"restored: {path}")
        self._set_busy(False, f"{len(restored)} file(s) restored")
        messagebox.showinfo("PlayFab Patcher", f"{len(restored)} file(s) restored.")
        self._start_scan()

    # -------------------------------------------------------------- verify --
    def _start_verify(self) -> None:
        if self.busy:
            return
        folder = self._folder()
        if folder is None:
            return
        title_id = self.title_id_var.get().strip()
        if not title_id:
            messagebox.showinfo("PlayFab Patcher", "Type the title id you expect to find.")
            return
        self._set_busy(True, "Verifying...")
        threading.Thread(target=self._verify_worker, args=(folder, title_id), daemon=True).start()

    def _verify_worker(self, folder: str, title_id: str) -> None:
        try:
            result = scan_mod.scan(folder, deep=False)
        except Exception as exc:  # noqa: BLE001
            self.events.put(("error", f"verify failed: {exc}"))
            return
        self.events.put(("verify_done", result, title_id, ""))

    def _show_verify(self, result: scan_mod.ScanResult, title_id: str, _extra: str) -> None:
        found = title_id in result.title_ids
        self._log(f"title id {title_id}: {'present' if found else 'NOT present'}")
        self._set_busy(False, "verified" if found else "not found")
        messagebox.showinfo(
            "PlayFab Patcher",
            "The title id you typed is in the game." if found else "That title id was not found - run Scan again.",
        )

    # ------------------------------------------------------------ settings --
    def _load_settings(self) -> None:
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        self.folder_var.set(data.get("folder", ""))
        self.title_id_var.set(data.get("title_id", ""))
        self.secret_key_var.set(data.get("secret_key", ""))
        self.api_url_var.set(data.get("api_url", ""))
        self.follow_var.set(bool(data.get("fill_from_title_id", True)))
        self.unclassified_var.set(bool(data.get("patch_unclassified", True)))

    def _save_settings(self) -> None:
        data = {
            "folder": self.folder_var.get(),
            "title_id": self.title_id_var.get(),
            "secret_key": self.secret_key_var.get(),
            "api_url": self.api_url_var.get(),
            "fill_from_title_id": self.follow_var.get(),
            "patch_unclassified": self.unclassified_var.get(),
        }
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
        except OSError:
            pass

    def _on_close(self) -> None:
        self._save_settings()
        self.destroy()


def folder_or_none(changes: list[patch_mod.Change]) -> str:
    """Best-effort game root for log lines when no scan result is cached."""
    for change in changes:
        path = change.site.path
        lowered = path.lower()
        for marker in ("_data" + os.sep, "_data/", ".playfabpatcher"):
            index = lowered.find(marker)
            if index > 0:
                return path[:index].rstrip("\\/")
    return os.path.dirname(changes[0].site.path) if changes else ""


def main() -> int:
    app = PatcherApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
