"""Guard against stale inputs and mistaking a Go wrapper for assembly."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "reported_assembly", Path(__file__).with_name("check-reported-assembly.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class EvidenceTests(unittest.TestCase):
    def test_reported_abi0_programs_keep_exact_bodies_and_pins(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "testdata/reported/assembly.json").read_text())
        script = Path(__file__).with_name("check-reported-runtime.sh").read_text()
        defaults = next(line.strip()[7:-1].split() for line in script.splitlines()
                        if line.strip().startswith("names=(funcval "))
        self.assertEqual(len(defaults), 9)
        self.assertEqual(len(set(defaults)), 9)
        expected = {
            "crc32": ("github.com/klauspost/crc32", "v1.3.0", "crc32_amd64.s", [
                "github.com/klauspost/crc32.castagnoliSSE42",
                "github.com/klauspost/crc32.castagnoliSSE42Triple",
                "github.com/klauspost/crc32.ieeeCLMUL"]),
            "libcabi0": ("modernc.org/libc", "v1.75.7", "abi0_linux_amd64.s", [
                "modernc.org/libc.Y__builtin_mul_overflowUint128",
                "modernc.org/libc.Y__builtin_copysign",
                "modernc.org/libc.Y__builtin_copysignf"]),
        }
        for name, (module, version, assembly, entries) in expected.items():
            with self.subTest(case=name):
                self.assertIn(name, defaults)
                case = manifest[name]
                self.assertEqual((case["module"], case["package"], case["version"]),
                                 (module, module, version))
                self.assertEqual(case["file_definitions"], {assembly: entries})
                self.assertTrue(case["go_abi0_suffix"])
                self.assertIn(module + " " + version,
                              (root / "testdata/reported" / name / "go.mod").read_text())
                with patch.object(checker, "unchanged"), patch.object(checker, "output") as output:
                    output.return_value = "\n".join("1234 T " + entry for entry in entries)
                    checker.linked(case, Path("unused"), "llgo", Path("unused"))
                    with self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                        checker.linked(case, Path("unused"), "go", Path("unused"))
                    output.return_value = "\n".join("1234 T " + entry + ".abi0" for entry in entries)
                    checker.linked(case, Path("unused"), "go", Path("unused"))
                    for missing in entries:
                        with self.subTest(missing=missing):
                            output.return_value = "\n".join("1234 T " + entry for entry in entries if entry != missing)
                            with self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                                checker.linked(case, Path("unused"), "llgo", Path("unused"))

    def test_runtime_requires_exact_audited_go(self):
        script = Path(__file__).with_name("check-reported-runtime.sh").read_text()
        start = script.index("if [[ $(go env GOVERSION)")
        end = script.index("\nfi", start) + len("\nfi")
        # Execute the actual preflight with a shell function, never a Go tool.
        guard = 'go() { printf "%s\\n" "$FIXTURE_GOVERSION"; }\n' + script[start:end]
        for version in ("go1.27.3", "go1.27.0", "go1.27.2", "go1.27.30", "go1.28.0"):
            with self.subTest(version=version):
                result = subprocess.run(["bash", "-c", guard],
                                        env={"FIXTURE_GOVERSION": version},
                                        capture_output=True, text=True, timeout=5)
                if version == "go1.27.3":
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, "unexpected SDK accepted: " + version)

    def test_changed_or_added_inputs_revoke_snapshot(self):
        for location in ("probe", "package"):
            for mutation in ("modify", "add", "delete"):
                with self.subTest(location=location, mutation=mutation):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        probe, package = root / "probe", root / "package"
                        probe.mkdir()
                        package.mkdir()
                        (probe / "main.go").write_text("package main\n")
                        (package / "abi.h").write_text("#define WIDTH 8\n")
                        files = [probe / "main.go", package / "abi.h"]
                        report = root / "source.json"
                        report.write_text(json.dumps({
                            "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
                            "probe_dir": str(probe), "probe_files": ["main.go"],
                            "package_dir": str(package), "package_names": ["abi.h"],
                        }))
                        checker.unchanged(report)
                        parent = probe if location == "probe" else package
                        target = parent / ("main.go" if location == "probe" else "abi.h")
                        if mutation == "modify":
                            target.write_text("changed\n")
                        elif mutation == "add":
                            (parent / "extra.go").write_text("package main\n")
                        else:
                            target.unlink()
                        with self.assertRaises((RuntimeError, FileNotFoundError)):
                            checker.unchanged(report)

    def test_stock_go_wrapper_is_not_an_assembly_body(self):
        case = {"go_abi0_suffix": True, "file_definitions": {"entry.s": ["example.fn"]}}
        with patch.object(checker, "unchanged"), patch.object(checker, "output") as output:
            output.return_value = "1234 T example.fn\n"
            with self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                checker.linked(case, Path("unused"), "go", Path("unused"))
            output.return_value += "1250 T example.fn.abi0\n"
            checker.linked(case, Path("unused"), "go", Path("unused"))

    def test_native_entry_requires_exact_package_and_source_symbol(self):
        case = {
            "package": "github.com/ebitengine/purego", "go_abi0_suffix": False,
            "native_code_entries": ["syscallX"], "file_definitions": {"entry.s": ["syscallX"]},
        }
        native = "__llgo_native_address_71e454a1e647c4671c6ada1525df8ffe0eea929f82b17cff408047d33aaab6e5"
        with patch.object(checker, "unchanged"), patch.object(checker, "output") as output:
            output.return_value = "1234 T " + native + "\n"
            checker.linked(case, Path("unused"), "llgo", Path("unused"))
            for changed in ({**case, "package": "example.com/other"},
                            {**case, "file_definitions": {"entry.s": ["callbackasm"]}}):
                with self.subTest(case=changed), self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                    checker.linked(changed, Path("unused"), "llgo", Path("unused"))
            output.return_value = "1234 T syscallX\n"
            with self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                checker.linked(case, Path("unused"), "llgo", Path("unused"))
            checker.linked(case, Path("unused"), "go", Path("unused"))

    def test_code_address_alias_keeps_its_exact_source_symbol(self):
        case = {
            "package": "github.com/ebitengine/purego", "go_abi0_suffix": False,
            "native_code_entries": ["syscallX"],
            "file_definitions": {"entry.s": ["syscallX", "callbackasm"]},
        }
        native = "__llgo_native_address_71e454a1e647c4671c6ada1525df8ffe0eea929f82b17cff408047d33aaab6e5"
        with patch.object(checker, "unchanged"), patch.object(checker, "output") as output:
            output.return_value = "1234 T " + native + "\n1250 T callbackasm\n"
            checker.linked(case, Path("unused"), "llgo", Path("unused"))
            output.return_value = "1234 T " + native + "\n1250 T unrelated_alias\n"
            with self.assertRaisesRegex(RuntimeError, "original assembly entry callbackasm"):
                checker.linked(case, Path("unused"), "llgo", Path("unused"))

    def test_turso_reported_native_bodies_and_alias(self):
        manifest = Path(__file__).resolve().parents[1] / "testdata/reported/assembly.json"
        case = json.loads(manifest.read_text())["turso"]
        self.assertEqual(case["module"], "github.com/ebitengine/purego")
        self.assertEqual(case["version"], "v0.9.1")
        self.assertEqual(case["file_definitions"], {
            "sys_amd64.s": ["syscall15X", "callbackasm1"],
            "zcallback_amd64.s": ["callbackasm"],
        })
        self.assertEqual(case["native_code_entries"], ["syscall15X", "callbackasm1"])
        self.assertFalse(case["go_abi0_suffix"])
        entries = ["__llgo_native_address_" + hashlib.sha256(
            (case["package"] + "\0" + name).encode()).hexdigest()
            for name in case["native_code_entries"]] + ["callbackasm"]
        with patch.object(checker, "unchanged"), patch.object(checker, "output") as output:
            output.return_value = "\n".join("1234 T " + name for name in entries)
            checker.linked(case, Path("unused"), "llgo", Path("llvm-linked"))
            output.assert_called_once_with("llvm-nm-22", "--defined-only", "llvm-linked")
            for missing in entries:
                with self.subTest(missing=missing):
                    output.return_value = "\n".join("1234 T " + name for name in entries if name != missing)
                    with self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                        checker.linked(case, Path("unused"), "llgo", Path("llvm-linked"))
            output.return_value = "1234 T syscall15X\n1250 T callbackasm1\n1260 T callbackasm\n"
            checker.linked(case, Path("unused"), "go", Path("go-linked"))
            with self.assertRaisesRegex(RuntimeError, "original assembly entry"):
                checker.linked(case, Path("unused"), "llgo", Path("llvm-linked"))


if __name__ == "__main__":
    unittest.main()
