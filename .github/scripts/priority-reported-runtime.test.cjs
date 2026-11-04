const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { test } = require('node:test');
const root = path.resolve(__dirname, '../..');
const corpus = fs.readFileSync(path.join(root, '.github/workflows/go-ci.yml'), 'utf8');
const runtime = fs.readFileSync(path.join(root, '.github/workflows/reported-runtime.yml'), 'utf8');
function event(source, name) {
  const start = source.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, name);
  const rest = source.slice(start + name.length + 5);
  const end = rest.search(/\n(?:  [a-z_]+:|\S)/);
  return end < 0 ? rest : rest.slice(0, end);
}
function paths(section) {
  return [...section.matchAll(/^      - '([^']+)'$/gm)].map(match => match[1]);
}
test('only the complete finite curated set bypasses corpus PR jobs', () => {
  const ignored = paths(event(corpus, 'pull_request'));
  assert.equal(new Set(ignored).size, ignored.length);
  assert.ok(ignored.length > 0 && ignored.length < 150); // Even rename pairs remain below GitHub's 300-file diff limit.
  for (const name of ignored) assert.ok(!['*', '?', '[', ']', '{', '}', '!', '\\'].some(c => name.includes(c)), name);
  const required = execFileSync('git', ['ls-files', '--', 'testdata/reported', 'scripts/check-reported-runtime.sh',
    'scripts/check-reported-assembly.py', 'scripts/test_reported_assembly.py', 'README.md', 'AGENTS.md'], { cwd: root, encoding: 'utf8' }).trim().split('\n');
  required.push('.github/workflows/go-ci.yml', '.github/workflows/reported-runtime.yml', '.github/scripts/priority-reported-runtime.test.cjs');
  assert.deepEqual(ignored, [...new Set(required)].sort());
  assert.match(event(corpus, 'push'), /branches:\n      - main/);
  assert.doesNotMatch(event(corpus, 'push'), /paths/);
  const runtimePaths = paths(event(runtime, 'push'));
  assert.deepEqual(runtimePaths, paths(event(runtime, 'pull_request')));
  const match = name => runtimePaths.some(p => p.endsWith('/**') ? name.startsWith(p.slice(0, -2)) : name === p);
  for (const [changed, full, programs] of [
    [['testdata/reported/turso/main.go'], false, true],
    [['.github/workflows/go-ci.yml'], false, true],
    [['README.md'], false, true],
    [['testdata/reported/new/main.go'], true, true],
    [['testdata/reported/turso/main.go', 'testdata/discovery/ledger/new.jsonl'], true, true],
    [['cmd/plan9asmcorpus/main.go', 'internal/goabi/type.go', 'go.mod'], true, false],
  ]) {
    assert.equal(changed.some(p => !ignored.includes(p)), full, changed.join(','));
    assert.equal(changed.some(match), programs, changed.join(','));
  }
});

test('the bounded runtime job keeps complete policies, one pinned CLI and all programs', () => {
  assert.match(runtime, /runs-on: ubuntu-24\.04\n    timeout-minutes: 45\n/);
  assert.match(runtime, /\n  workflow_dispatch:\n  schedule:\n    - cron: '0 2 \* \* 1'\n/);
  assert.match(runtime, /if: \$\{\{ github\.event_name != 'push' \|\| github\.ref == 'refs\/heads\/main' \|\| github\.event\.repository\.fork \}\}/);
  assert.match(runtime, /go-version: '1\.27\.3'/);
  assert.match(runtime, /ref: c5bd35a66378ade63b2ab5c6e5458ae2041874bd\n/);
  assert.match(runtime, /GOTOOLCHAIN: local\n/);
  assert.match(runtime, /GOSUMDB: sum\.golang\.org\n/);
  assert.ok(runtime.includes('install -y cmake pkg-config libgc-dev libssl-dev zlib1g-dev libffi-dev libcjson-dev libuv1-dev'));
  for (const command of [
    'bash scripts/install-ci-llvm22-ubuntu.sh',
    'node --test .github/scripts/priority-*.test.cjs',
    "go test . -run '^TestCI' -count=1",
    'python3 scripts/test_reported_assembly.py -v',
    'bash -n scripts/check-reported-runtime.sh',
  ]) assert.ok(runtime.includes(command), command);
  assert.equal(runtime.match(/^          go build /gm).length, 1);
  assert.match(runtime, /LLGO="\$GITHUB_WORKSPACE\/_out\/bin\/llgo" bash scripts\/check-reported-runtime\.sh \|\| status=\$\?/);
  assert.match(runtime, /if: always\(\)\n        uses: actions\/upload-artifact@v6/);
  assert.match(runtime, /if-no-files-found: error/);
  assert.doesNotMatch(runtime, /continue-on-error|max-parallel|GOSUMDB: (?:off|'off')/);
});
