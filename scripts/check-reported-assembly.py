#!/usr/bin/env python3
"""Check the selected original TEXT definitions and their final linked entries."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.parse


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def output(*command):
    return subprocess.check_output(command, text=True, timeout=60)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def probe_files(directory):
    return sorted(str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file())


def source(case, report):
    require(bool(case["file_definitions"]) and all(case["file_definitions"].values()),
            "assembly check needs nonempty TEXT definitions")
    package = json.loads(output("go", "list", "-json", case["package"]))
    module = package.get("Module", {})
    require(package["ImportPath"] == case["package"], "selected package differs")
    require(module.get("Path") == case["module"], "selected module differs")
    require(module.get("Version") == case["version"], "selected version differs")
    require(not module.get("Replace"), "reported library must not use a replacement")
    require(set(case["file_definitions"]) <= set(package.get("SFiles", [])),
            "required original assembly files are not selected")
    config = json.loads(output("go", "env", "-json", "GOROOT", "GOAMD64"))
    require(bool(config["GOAMD64"]), "missing actual GOAMD64 configuration")
    source_paths = {path.resolve() for path in Path.cwd().rglob("*") if path.is_file()}
    # Dispatch Go bodies, selected headers and the C oracle are also inputs.
    # gensymabis intentionally uses an empty generated go_asm.h; the ordinary
    # complete Go build independently checks the real compiler-generated one.
    for kind in ("GoFiles", "CgoFiles", "SFiles", "HFiles", "CFiles"):
        source_paths.update(Path(package["Dir"]) / name for name in package.get(kind, []))
    repository = Path(__file__).resolve().parents[1]
    source_paths.update(repository / name for name in (
        "scripts/check-reported-assembly.py", "scripts/check-reported-runtime.sh",
        "testdata/reported/assembly.json",
    ))
    files = {str(path): digest(path) for path in sorted(source_paths)}
    for filename, symbols in case["file_definitions"].items():
        path = Path(package["Dir"]) / filename
        with tempfile.TemporaryDirectory(prefix="reported-asm-origin-") as directory:
            temporary = Path(directory)
            (temporary / "go_asm.h").write_bytes(b"")
            symabis = temporary / "symabis"
            subprocess.run([
                "go", "tool", "asm", "-gensymabis", "-p", case["package"],
                "-I", directory, "-I", str(Path(config["GOROOT"]) / "pkg/include"),
                "-I", package["Dir"], "-D", "GOOS_linux", "-D", "GOARCH_amd64",
                "-D", "GOAMD64_" + config["GOAMD64"], "-o", str(symabis), str(path),
            ], check=True, timeout=60)
            definitions = set()
            for line in symabis.read_text().splitlines():
                fields = line.split()
                require(len(fields) == 3 and fields[0] in ("def", "ref") and
                        fields[2] in ("ABI0", "ABIInternal"), "invalid symabis record")
                if fields[0] == "def":
                    definitions.add(urllib.parse.unquote(fields[1]))
            require(set(symbols) <= definitions, "expected entry lacks an original TEXT definition")
            report.with_name(report.stem + "-" + filename + ".symabis").write_bytes(symabis.read_bytes())
    report.write_text(json.dumps({
        "module": module, "files": files,
        "probe_dir": str(Path.cwd()), "probe_files": probe_files(Path.cwd()),
        "package_dir": package["Dir"],
        "package_names": sorted(path.name for path in Path(package["Dir"]).iterdir()),
    }, indent=2) + "\n")


def unchanged(report):
    snapshot = json.loads(report.read_text())
    files = snapshot["files"]
    require(probe_files(Path(snapshot["probe_dir"])) == snapshot["probe_files"],
            "probe input membership changed during verification")
    names = sorted(path.name for path in Path(snapshot["package_dir"]).iterdir())
    require(names == snapshot["package_names"], "selected package membership changed during verification")
    require(bool(files), "source report contains no inputs")
    require(all(digest(path) == expected for path, expected in files.items()),
            "probe or selected package input changed during verification")


def linked(case, report, compiler, binary):
    unchanged(report)
    symbols = set()
    for line in output("llvm-nm-22", "--defined-only", str(binary)).splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] in ("T", "t"):
            symbols.add(fields[-1])
    suffix = ".abi0" if compiler == "go" and case["go_abi0_suffix"] else ""
    for definitions in case["file_definitions"].values():
        for symbol in definitions:
            # A stock Go ABIInternal wrapper alone is not the original body.
            expected = symbol + suffix
            if compiler == "llgo" and symbol in case.get("native_code_entries", []):
                # Source-selected bare TEXT entries have no Go prototype.
                # Match their exact component identity, never an arbitrary
                # native-looking prefix or an unrelated linked Go wrapper.
                identity = (case["package"] + "\0" + symbol).encode()
                expected = "__llgo_native_address_" + hashlib.sha256(identity).hexdigest()
            require(expected in symbols, "final binary lacks original assembly entry " + expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("source", "linked", "unchanged"))
    parser.add_argument("case")
    parser.add_argument("report", type=Path)
    parser.add_argument("--compiler", choices=("go", "llgo"))
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    manifest = Path(__file__).resolve().parents[1] / "testdata/reported/assembly.json"
    case = json.loads(manifest.read_text())[args.case]
    if args.action == "source":
        source(case, args.report)
    elif args.action == "linked":
        require(args.compiler is not None and args.binary is not None, "linked action needs compiler and binary")
        linked(case, args.report, args.compiler, args.binary)
    else:
        unchanged(args.report)


if __name__ == "__main__":
    main()
