"""Verify the local GLib source differs from the registry crate only as reviewed."""
import hashlib
import json
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]
VENDOR = REPO / 'third_party/glib-0.18.5-variant-str-iter'
ARCHIVE_SHA = '233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5'
LINT_COMPATIBILITY = b'''\n# Rust 1.94 can ICE while rendering this new stylistic lint on GLib 0.18.
# Keep this workaround crate-local; unknown_lints supports our Rust 1.88 MSRV.
[lints.rust]
unknown_lints = "allow"
mismatched_lifetime_syntaxes = "allow"
'''


class GlibBackportTests(unittest.TestCase):
    def test_only_reviewed_upstream_and_build_compatibility_changes_are_present(self):
        inventory = json.loads((VENDOR / 'UPSTREAM-FILES.json').read_bytes())
        self.assertEqual(inventory['upstream_crate'], 'glib')
        self.assertEqual(inventory['upstream_version'], '0.18.5')
        self.assertEqual(inventory['upstream_archive_sha256'], ARCHIVE_SHA)
        expected = inventory['files']
        self.assertEqual(len(expected), 121)
        actual = set()
        for path in VENDOR.rglob('*'):
            self.assertFalse(path.is_symlink(), str(path))
            if path.is_file():
                actual.add(path.relative_to(VENDOR).as_posix())
        self.assertEqual(actual, set(expected) | {'UPSTREAM-FILES.json', 'README.commonfoundry.md'})
        for name, identity in expected.items():
            data = (VENDOR / name).read_bytes()
            if name == 'src/variant_iter.rs':
                before = b'let p: *mut libc::c_char = std::ptr::null_mut();'
                after = b'let mut p: *mut libc::c_char = std::ptr::null_mut();'
                self.assertEqual(data.count(after), 1)
                self.assertEqual(data.count(b'                &mut p,'), 1)
                data = data.replace(after, before).replace(b'                &mut p,', b'                &p,')
            elif name == 'Cargo.toml':
                self.assertTrue(data.endswith(LINT_COMPATIBILITY))
                data = data.removesuffix(LINT_COMPATIBILITY)
            self.assertEqual(len(data), identity['bytes'], name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), identity['sha256'], name)

    def test_workspace_selects_truthfully_versioned_patch(self):
        workspace = (REPO / 'Cargo.toml').read_text()
        self.assertIn('glib = { path = "third_party/glib-0.18.5-variant-str-iter" }', workspace)
        manifest = (VENDOR / 'Cargo.toml').read_text()
        self.assertIn('version = "0.18.5"', manifest)
        self.assertTrue((VENDOR / 'LICENSE').is_file())
        self.assertTrue((VENDOR / 'COPYRIGHT').is_file())


if __name__ == '__main__':
    unittest.main(verbosity=2)
