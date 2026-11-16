import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ip_sentinel import GENESIS_PREVIOUS_HASH, IPSentinel, verify_package


class IPSentinelTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.workspace = base / "workspace"
        self.workspace.mkdir()
        self.sentinel = IPSentinel(storage_dir=base / "ledger")

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, text):
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def commit(self):
        return self.sentinel.commit_custody_log(self.sentinel.scan_and_discover(self.workspace), author="Tester")

    def test_scan_hashes_files_and_labels_changes(self):
        self.write("a.txt", "alpha")
        self.write("sub/b.txt", "beta")
        self.write(".DS_Store", "ignored")

        first = self.sentinel.scan_and_discover(self.workspace)
        self.assertEqual([e["relative_path"] for e in first], ["a.txt", "sub/b.txt"])
        self.assertEqual(first[0]["sha256_hash"], hashlib.sha256(b"alpha").hexdigest())
        self.assertEqual({e["status"] for e in first}, {"new"})

        self.sentinel.commit_custody_log(first, author="Tester")
        self.write("a.txt", "alpha v2")
        self.write("c.txt", "gamma")
        statuses = {e["relative_path"]: e["status"] for e in self.sentinel.scan_and_discover(self.workspace)}
        self.assertEqual(statuses, {"a.txt": "modified", "c.txt": "new", "sub/b.txt": "unchanged"})

    def test_blocks_link_and_persist_across_instances(self):
        self.write("a.txt", "alpha")
        block_0 = self.commit()
        self.write("a.txt", "alpha v2")
        block_1 = self.commit()

        self.assertEqual(block_0["previous_block_hash"], GENESIS_PREVIOUS_HASH)
        self.assertEqual(block_1["previous_block_hash"], block_0["block_hash"])

        reopened = IPSentinel(storage_dir=self.sentinel.storage_dir)
        report = reopened.verify_integrity()
        self.assertTrue(report)
        self.assertEqual(report.blocks_checked, 2)

    def test_tampering_on_disk_is_detected_and_blocks_new_commits(self):
        self.write("a.txt", "alpha")
        self.commit()
        self.commit()

        data = json.loads(self.sentinel.chain_path.read_text())
        data["blocks"][0]["entries"][0]["sha256_hash"] = "f" * 64
        self.sentinel.chain_path.write_text(json.dumps(data))

        report = self.sentinel.verify_integrity()
        self.assertFalse(report)
        self.assertIn("block 0", str(report))
        with self.assertRaises(RuntimeError):
            self.commit()

    def test_storage_dir_inside_workspace_is_not_scanned(self):
        sentinel = IPSentinel(storage_dir=self.workspace / "ledger")
        self.write("a.txt", "alpha")
        sentinel.commit_custody_log(sentinel.scan_and_discover(self.workspace), author="Tester")
        paths = [e["relative_path"] for e in sentinel.scan_and_discover(self.workspace)]
        self.assertEqual(paths, ["a.txt"])

    def test_exported_package_verifies_standalone_and_detects_edits(self):
        self.write("a.txt", "alpha")
        self.commit()
        self.write("a.txt", "alpha v2")
        self.commit()

        package = json.loads(json.dumps(self.sentinel.generate_verification_package()))
        self.assertTrue(verify_package(package))

        forged = copy.deepcopy(package)
        forged["blocks"][1]["timestamp"] = "2020-01-01T00:00:00+00:00"
        self.assertFalse(verify_package(forged))

    def test_find_file_hash_returns_every_block_containing_it(self):
        self.write("a.txt", "alpha")
        self.commit()
        self.write("b.txt", "beta")
        self.commit()

        matches = self.sentinel.find_file_hash(hashlib.sha256(b"alpha").hexdigest().upper())
        self.assertEqual([(m["block_index"], m["status"]) for m in matches], [(0, "new"), (1, "unchanged")])
        self.assertEqual(self.sentinel.find_file_hash("0" * 64), [])

    def test_rejects_empty_or_malformed_commits(self):
        with self.assertRaises(ValueError):
            self.sentinel.commit_custody_log([], author="Tester")
        self.write("a.txt", "alpha")
        scan = self.sentinel.scan_and_discover(self.workspace)
        with self.assertRaises(ValueError):
            self.sentinel.commit_custody_log(scan, author="  ")
        scan[0]["sha256_hash"] = "not-a-hash"
        with self.assertRaises(ValueError):
            self.sentinel.commit_custody_log(scan, author="Tester")


if __name__ == "__main__":
    unittest.main()
