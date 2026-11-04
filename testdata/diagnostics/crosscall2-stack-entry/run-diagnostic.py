#!/usr/bin/env python3
"""One-shot native-hosted diagnostic; every process keeps its actual terminal."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

fixture = Path(__file__).resolve().parent
out = Path(os.environ['DIAGNOSTIC_OUT']).resolve()
out.mkdir(parents=True, exist_ok=True)
rows = []
failed = False


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs():
    return {p.name: digest(p) for p in sorted(fixture.iterdir()) if p.is_file()}


before = inputs()
(out / 'fixture-before.json').write_text(json.dumps(before, indent=2) + '\n')


def run(label, command, seconds=30, cwd=fixture):
    global failed
    with (out / (label + '.stdout')).open('wb') as stdout, (out / (label + '.stderr')).open('wb') as stderr:
        result = subprocess.run(['timeout', '-k', '10s', str(seconds) + 's', *command], cwd=cwd, stdout=stdout, stderr=stderr)
    row = {'stage': label, 'command': command, 'exit': result.returncode}
    rows.append(row)
    with (out / 'terminals.jsonl').open('a') as stream:
        stream.write(json.dumps(row) + '\n')
    failed |= result.returncode != 0
    return result.returncode


def observe(binary, label, symbols):
    global failed
    run(label + '-symbols', ['llvm-nm-22', '--defined-only', str(binary)])
    defined = {fields[-1] for line in (out / (label + '-symbols.stdout')).read_text().splitlines() if len(fields := line.split()) >= 2 and fields[-2] in ('T', 't')}
    missing = sorted(set(symbols) - defined)
    (out / (label + '-required-symbols.json')).write_text(json.dumps({'required': symbols, 'missing': missing}, indent=2) + '\n')
    failed |= bool(missing)
    run(label + '-disassembly', ['llvm-objdump-22', '-d', '--disassemble-symbols=' + ','.join(symbols), str(binary)])
    run(label + '-object', ['llvm-readobj-22', '--file-headers', '--relocations', str(binary)])
    run(label + '-libraries', ['ldd', str(binary)])
    (out / (label + '.sha256')).write_text(digest(binary) + '  ' + binary.name + '\n')


go_root = Path(json.loads((out / 'go-env.json').read_text())['GOROOT'])
run('original-go-assembly', ['go', 'tool', 'asm', '-S', '-p', 'main', '-I', str(go_root / 'pkg/include'), '-o', str(out / 'entry-go.o'), 'entry_amd64.s'])
for compiler, tool in [('go', 'go'), ('llgo', os.environ['LLGO'])]:
    binary = out / ('entry-' + compiler)
    built = run(compiler + '-build', [tool, 'build', '-mod=readonly', '-o', str(binary), '.'], 300) == 0
    for mode, remainder in [('aligned', 0), ('eight-aligned', 8)]:
        label = compiler + '-' + mode
        if not built:
            row = {'stage': label, 'state': 'NOT_RUN_BUILD_FAILED', 'exit': None}
            rows.append(row)
            with (out / 'terminals.jsonl').open('a') as stream:
                stream.write(json.dumps(row) + '\n')
            continue
        code = run(label, [str(binary), mode], 60)
        expected = f'{mode} entry=8 call={remainder} callbacks=1 result=42\n'.encode()
        match = (out / (label + '.stdout')).read_bytes() == expected and not (out / (label + '.stderr')).read_bytes()
        rows[-1]['output_matches_expected'] = match
        failed |= code != 0 or not match
    if built:
        symbols = ['crosscall2', 'main.dispatch']
        if compiler == 'go':
            symbols += ['alignedEntry', 'eightAlignedEntry']
        else:
            symbols += ['__llgo_native_address_' + hashlib.sha256(('example.com/crosscall2-stack-entry\0' + name).encode()).hexdigest() for name in ['alignedEntry', 'eightAlignedEntry']]
        observe(binary, compiler, symbols)

# Keep actual cached LLVM package objects in addition to final ELF disassembly.
# This searches only this job's fresh LLGo cache, never external source inventory.
archives = []
for archive in sorted(Path(os.environ['XDG_CACHE_HOME']).rglob('*.a')):
    path = archive.as_posix()
    if archive.parent.name not in ('crosscall2-stack-entry', 'runtime'):
        continue
    copied = out / ('llvm-package-' + str(len(archives)) + '.a')
    shutil.copyfile(archive, copied)
    run(copied.stem + '-members', ['llvm-ar-22', 't', str(copied)])
    archives.append({'cache_path': path, 'copy': copied.name, 'sha256': digest(copied)})
(out / 'llvm-package-objects.json').write_text(json.dumps(archives, indent=2) + '\n')
after = inputs()
(out / 'fixture-after.json').write_text(json.dumps(after, indent=2) + '\n')
failed |= before != after
expected = {compiler + '-' + mode for compiler in ['go', 'llgo'] for mode in ['aligned', 'eight-aligned']}
actual = [row for row in rows if row['stage'] in expected]
failed |= len(actual) != 4 or {r['stage'] for r in actual} != expected
(out / 'summary.json').write_text(json.dumps({'status': 'FAIL' if failed else 'PASS', 'fixture_frozen': before == after, 'required_processes': sorted(expected), 'actual_processes': actual, 'all_stages': rows, 'llvm_package_archives': archives}, indent=2) + '\n')
sys.exit(int(failed))
