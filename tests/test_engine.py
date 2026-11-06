"""Regression tests for the PlayFab scan/patch engine.

Run with:  python -m unittest discover -s tests -v

Everything is built from scratch in a temporary folder, so the tests never
touch a real game.  The assembly test uses the .NET Framework C# compiler when
it is available and is skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from playfabpatcher import dnmeta, patch, scan

CSC_PATHS = (
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
)

SOURCE = """
public static class PlayFabConfig
{
    const string TitleId = "A89CF";
    const string SecretKey = "Xk7Q2mNv8ZpR4tLb6YsW9cHd3JfG5aKe1BuV0iTy7";
    const string Url = "https://A89CF.playfabapi.com/";
    public static string All() { return "titleid=" + TitleId + ";secret=" + SecretKey + ";url=" + Url; }
}
"""

OLD_TITLE = "A89CF"
NEW_TITLE = "BDFF1"
LONG_TITLE = "BDFF12"
OLD_SECRET = "Xk7Q2mNv8ZpR4tLb6YsW9cHd3JfG5aKe1BuV0iTy7"
NEW_SECRET = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3Ab"
OLD_URL = "https://A89CF.playfabapi.com/"


def unity_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    padded = raw + b"\0" * ((-len(raw)) % 4)
    return struct.pack("<i", len(raw)) + padded


def append_unity_string(blob: bytearray, text: str) -> None:
    """Append like Unity does: pad to a 4 byte boundary of the whole file."""
    raw = text.encode("utf-8")
    blob += struct.pack("<i", len(raw))
    blob += raw
    blob += b"\0" * ((-len(blob)) % 4)


def make_settings(title: str | None = OLD_TITLE, secret: str = "", url: str = "") -> bytes:
    """A player-build style ``PlayFabSharedSettings`` object.

    The SDK serializes the object name followed by the TitleId, the developer
    secret key and the environment URL, each as a Unity string.
    """
    blob = bytearray(b"\0" * 128)
    append_unity_string(blob, "PlayFabSharedSettings")
    append_unity_string(blob, title or "")
    append_unity_string(blob, secret)
    append_unity_string(blob, url)
    blob += b"\1\0\0\0" * 4
    return bytes(blob)


class TempGame(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="playfabpatcher-test-")
        self.data = os.path.join(self.root, "Game_Data")
        os.makedirs(self.data)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, relative: str, payload: bytes) -> str:
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(payload)
        return path


class TestSettingsObject(TempGame):
    def test_title_id_is_found(self) -> None:
        blob = make_settings()
        self.write("Game_Data/resources.assets", blob)
        result = scan.scan(self.root)
        site = next(site for site in result.sites if site.value == OLD_TITLE)
        self.assertEqual(site.role, scan.TITLE_ID)
        self.assertGreaterEqual(site.confidence, 0.9)
        self.assertEqual(site.offset, blob.index(OLD_TITLE.encode()))
        self.assertIn("playfab", result.evidence)

    def test_title_id_patches_in_place_and_restores(self) -> None:
        blob = make_settings()
        path = self.write("Game_Data/resources.assets", blob)
        result = scan.scan(self.root)
        changes = patch.plan(result.sites, patch.Target(title_id=NEW_TITLE))
        report = patch.apply(self.root, changes)
        self.assertEqual(report.summary().split(",")[0], "1 patched")

        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(blob))
        self.assertEqual(patched.count(NEW_TITLE.encode()), 1)
        self.assertNotIn(OLD_TITLE.encode(), patched)

        again = scan.scan(self.root)
        self.assertIn(NEW_TITLE, [site.value for site in again.sites])

        patch.restore(self.root)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), blob)

    def test_longer_title_id_still_fits_the_slot(self) -> None:
        blob = make_settings()
        path = self.write("Game_Data/resources.assets", blob)
        result = scan.scan(self.root)
        report = patch.apply(self.root, patch.plan(result.sites, patch.Target(title_id=LONG_TITLE)))
        self.assertFalse(report.failed, [change.message for change in report.failed])
        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(blob))
        self.assertIn(struct.pack("<i", len(LONG_TITLE)) + LONG_TITLE.encode(), patched)

    def test_secret_key_and_url_are_found(self) -> None:
        self.write(
            "Game_Data/resources.assets",
            make_settings(secret=OLD_SECRET, url=OLD_URL),
        )
        roles = {site.role for site in scan.scan(self.root).sites}
        self.assertEqual(roles, {scan.TITLE_ID, scan.SECRET_KEY, scan.API_URL})

    def test_endpoint_title_id_follows_the_target(self) -> None:
        self.write(
            "Game_Data/resources.assets",
            make_settings(secret=OLD_SECRET, url=OLD_URL),
        )
        sites = scan.scan(self.root).sites
        url_site = next(site for site in sites if site.role == scan.API_URL)
        self.assertEqual(url_site.extra.get("title_id"), OLD_TITLE)

        changes = patch.plan([url_site], patch.Target(title_id=NEW_TITLE))
        self.assertEqual(changes[0].status, "pending")
        self.assertEqual(changes[0].new_value, "https://BDFF1.playfabapi.com/")

        explicit = patch.plan([url_site], patch.Target(title_id=NEW_TITLE, api_url="https://proxy.local/"))
        self.assertEqual(explicit[0].new_value, "https://proxy.local/")

    def test_secret_key_patch_changes_length(self) -> None:
        blob = make_settings(secret=OLD_SECRET)
        path = self.write("Game_Data/resources.assets", blob)
        sites = scan.scan(self.root).sites
        secret = next(site for site in sites if site.role == scan.SECRET_KEY)
        report = patch.apply(self.root, patch.plan([secret], patch.Target(secret_key=NEW_SECRET)))
        self.assertFalse(report.failed, [change.message for change in report.failed])
        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertIn(NEW_SECRET.encode(), patched)
        self.assertNotIn(OLD_SECRET.encode(), patched)
        self.assertEqual(len(patched), len(blob))

    def test_two_playfab_objects_are_both_reported(self) -> None:
        blob = bytearray(make_settings())
        blob += b"\0" * 64
        append_unity_string(blob, "PlayFabBackend")
        append_unity_string(blob, "BDFF1")
        self.write("Game_Data/data.unity3d", bytes(blob))

        sites = scan.scan(self.root).sites
        values = [site.value for site in sites]
        self.assertIn(OLD_TITLE, values)
        self.assertIn("BDFF1", values)
        backend = next(site for site in sites if site.value == "BDFF1")
        self.assertEqual(backend.role, scan.TITLE_ID)
        self.assertLess(backend.confidence, 0.8)

    def test_unrelated_short_token_is_ignored(self) -> None:
        junk = b"\0" * 600 + unity_string("ABCD") + b"\0" * 600
        self.write("Game_Data/sharedassets0.assets", junk)
        self.assertEqual(scan.scan(self.root).sites, [])

    def test_type_table_name_alone_is_not_a_setting(self) -> None:
        blob = bytearray(b"\0" * 64)
        append_unity_string(blob, "PlayFabSharedSettings")
        append_unity_string(blob, "Assembly-CSharp.dll")
        self.write("Game_Data/sharedassets1.assets", bytes(blob))
        self.assertEqual(scan.scan(self.root).sites, [])


class TestLargeBundle(TempGame):
    """Bundles past the in-memory limit are mapped, then patched in place."""

    def setUp(self) -> None:
        super().setUp()
        self.scan_limit = scan.MAX_BLOB
        self.patch_limit = patch.MAX_BLOB
        scan.MAX_BLOB = 1024
        patch.MAX_BLOB = 1024

    def tearDown(self) -> None:
        scan.MAX_BLOB = self.scan_limit
        patch.MAX_BLOB = self.patch_limit
        super().tearDown()

    def write_big_asset(self, secret: str = "") -> tuple[str, bytes]:
        padding = b"\0" * (1024 * 1024)
        payload = padding + make_settings(secret=secret) + padding
        return self.write("Game_Data/data.unity3d", payload), payload

    def test_windowed_scan_reports_file_offsets(self) -> None:
        _path, original = self.write_big_asset()
        site = next(site for site in scan.scan(self.root).sites if site.value == OLD_TITLE)
        self.assertEqual(site.role, scan.TITLE_ID)
        self.assertEqual(site.offset, original.index(OLD_TITLE.encode()))

    def test_big_bundle_patches_in_place_and_restores(self) -> None:
        path, original = self.write_big_asset()
        changes = patch.plan(scan.scan(self.root).sites, patch.Target(title_id=NEW_TITLE))
        report = patch.apply(self.root, changes)
        self.assertFalse(report.failed, [change.message for change in report.failed])
        self.assertEqual(len(report.patched), 1)

        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(original))
        self.assertEqual(patched.count(NEW_TITLE.encode()), 1)
        self.assertNotIn(OLD_TITLE.encode(), patched)
        self.assertFalse(os.path.exists(os.path.join(self.root, ".playfabpatcher", "backups")))

        patch.restore(self.root)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), original)

    def test_big_bundle_secret_key_patched_in_place(self) -> None:
        path, original = self.write_big_asset(secret=OLD_SECRET)
        sites = scan.scan(self.root).sites
        secret = next(site for site in sites if site.role == scan.SECRET_KEY)
        report = patch.apply(self.root, patch.plan([secret], patch.Target(secret_key=NEW_SECRET)))
        self.assertFalse(report.failed, [change.message for change in report.failed])
        with open(path, "rb") as handle:
            patched = handle.read()
        self.assertEqual(len(patched), len(original))
        self.assertIn(NEW_SECRET.encode(), patched)

        patch.restore(self.root)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), original)


class TestTextConfig(TempGame):
    def test_json_config_is_found(self) -> None:
        self.write(
            "Game_Data/playfab.json",
            b'{"playfabTitleId": "A89CF", "productionEnvironmentUrl": "https://A89CF.playfabapi.com/"}',
        )
        roles = {site.value: site.role for site in scan.scan(self.root).sites}
        self.assertEqual(roles.get(OLD_TITLE), scan.TITLE_ID)
        self.assertEqual(roles.get(OLD_URL), scan.API_URL)

    def test_text_patch_and_restore(self) -> None:
        path = self.write(
            "Game_Data/settings.ini",
            b"[playfab]\nTitleId=A89CF\ndeveloperSecretKey=" + OLD_SECRET.encode() + b"\n",
        )
        result = scan.scan(self.root)
        self.assertTrue(any(site.kind == "text" for site in result.sites))
        report = patch.apply(self.root, patch.plan(result.sites, patch.Target(title_id=NEW_TITLE)))
        self.assertFalse(report.failed, [change.message for change in report.failed])
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("TitleId=BDFF1", text)
        patch.restore(self.root)
        with open(path, encoding="utf-8") as handle:
            self.assertIn("TitleId=A89CF", handle.read())


class TestValidation(unittest.TestCase):
    def test_title_id_rules(self) -> None:
        self.assertIsNone(patch.validate_value("A89CF", scan.TITLE_ID))
        self.assertIsNone(patch.validate_value("1A2B", scan.TITLE_ID))
        self.assertIsNone(patch.validate_value("A89CF1", scan.TITLE_ID))
        self.assertIsNotNone(patch.validate_value("a89cf", scan.TITLE_ID))
        self.assertIsNotNone(patch.validate_value("TOOLONG", scan.TITLE_ID))
        self.assertIsNotNone(patch.validate_value("A8 9CF", scan.TITLE_ID))
        self.assertIsNotNone(patch.validate_value("", scan.TITLE_ID))

    def test_secret_and_url_rules(self) -> None:
        self.assertIsNone(patch.validate_value(OLD_SECRET, scan.SECRET_KEY))
        self.assertIsNotNone(patch.validate_value("short", scan.SECRET_KEY))
        self.assertIsNone(patch.validate_value("https://x.playfabapi.com/", scan.API_URL))
        self.assertIsNotNone(patch.validate_value("not-a-url", scan.API_URL))

    def test_value_shapes(self) -> None:
        self.assertTrue(scan.looks_like_title_id("A89CF"))
        self.assertTrue(scan.looks_like_title_id("1A2B"))
        self.assertFalse(scan.looks_like_title_id("0000"))
        self.assertFalse(scan.looks_like_title_id("toolongtitle"))
        self.assertTrue(scan.looks_like_endpoint(".playfabapi.com"))
        self.assertTrue(scan.looks_like_endpoint("https://a89cf.playfabapi.com/"))
        self.assertFalse(scan.looks_like_endpoint("https://example.com/"))
        self.assertEqual(scan.role_for_value("A89CF"), scan.TITLE_ID)
        self.assertEqual(scan.role_for_value(OLD_SECRET), scan.SECRET_KEY)
        self.assertEqual(scan.role_for_value(OLD_URL), scan.API_URL)

    def test_plan_skips_when_no_target(self) -> None:
        site = scan.Site(
            path="x", kind="text", offset=0, encoding="utf-8",
            value=OLD_TITLE, role=scan.TITLE_ID, confidence=0.9,
        )
        self.assertEqual(patch.plan([site], patch.Target())[0].status, "skipped")
        self.assertEqual(patch.plan([site], patch.Target(title_id=OLD_TITLE))[0].message, "already patched")
        skipped = patch.plan([site], patch.Target(title_id="bad value"))
        self.assertEqual(skipped[0].status, "skipped")
        self.assertIn("whitespace", skipped[0].message)

    def test_unclassified_follows_title_id_only_when_asked(self) -> None:
        site = scan.Site(
            path="x", kind="raw", offset=0, encoding="utf-8",
            value="BDFF1", role=scan.UNCLASSIFIED, confidence=0.6,
        )
        self.assertEqual(patch.plan([site], patch.Target(title_id=NEW_TITLE))[0].new_value, NEW_TITLE)
        self.assertEqual(
            patch.plan([site], patch.Target(title_id=NEW_TITLE, patch_unclassified=False))[0].status,
            "skipped",
        )


class TestAssemblyPatch(TempGame):
    @classmethod
    def setUpClass(cls) -> None:
        cls.csc = next((path for path in CSC_PATHS if os.path.isfile(path)), None)

    def build_dll(self) -> str:
        source = os.path.join(self.root, "PlayFabTest.cs")
        with open(source, "w", encoding="utf-8") as handle:
            handle.write(SOURCE)
        dll = os.path.join(self.root, "PlayFabTest.dll")
        result = subprocess.run(
            [self.csc, "/nologo", "/target:library", f"/out:{dll}", source],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return dll

    def test_literal_title_id_is_found_and_patched(self) -> None:
        if not self.csc:
            self.skipTest("no C# compiler on this machine")
        dll = self.build_dll()
        with open(dll, "rb") as handle:
            target = self.write("Game_Data/Managed/PlayFabTest.dll", handle.read())

        with open(target, "rb") as handle:
            original = handle.read()

        result = scan.scan(self.root)
        kinds = {(site.kind, site.role) for site in result.sites if site.value == OLD_TITLE}
        self.assertIn(("us", scan.TITLE_ID), kinds)

        # Only the metadata literals can grow; the raw copies are same length.
        sites = [site for site in result.sites if site.kind == "us"]
        changes = patch.plan(sites, patch.Target(title_id=LONG_TITLE))
        report = patch.apply(self.root, changes)
        self.assertFalse(report.failed, [change.message for change in report.failed])
        self.assertTrue(report.patched)

        with open(target, "rb") as handle:
            patched = handle.read()
        meta = dnmeta.Metadata(patched)
        literals = [entry.value for entry in meta.user_strings()]
        self.assertTrue(any(LONG_TITLE in value for value in literals))

        patch.restore(self.root)
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), original)


if __name__ == "__main__":
    unittest.main()
