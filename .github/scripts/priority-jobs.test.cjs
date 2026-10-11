const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const workflow = fs.readFileSync(path.join(__dirname, '../workflows/go-ci.yml'), 'utf8');

function jobSection(name) {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, `missing job ${name}`);
  const rest = workflow.slice(start + 1);
  const next = rest.slice(1).search(/^  [a-zA-Z0-9_-]+:\s*$/m);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

function shards(section) {
  const match = section.match(/^        shard:\n((?:          - \d+\n)+)/m);
  assert.ok(match, 'missing shard matrix');
  return Array.from(match[1].matchAll(/^          - (\d+)$/gm),
    ([, value]) => Number(value));
}

function stepSection(section, name) {
  const start = section.indexOf(`      - name: ${name}\n`);
  assert.notEqual(start, -1, `missing step ${name}`);
  const next = section.indexOf('\n      - name:', start + 1);
  return section.slice(start, next < 0 ? section.length : next);
}

test('priority and remaining matrices partition all 128 shards exactly once', () => {
  const priority = shards(jobSection('discovered_library_priority'));
  const remaining = shards(jobSection('discovered_library_corpus'));
  // Each former priority shard splits into two children. Both retain their
  // failure-first role, including the repeatedly timed-out parents 36/42.
  assert.deepEqual(priority, [5, 29, 36, 38, 39, 42, 69, 93, 100, 102, 103, 106]);
  assert.deepEqual([...priority, ...remaining].sort((a, b) => a - b),
    Array.from({ length: 128 }, (_, index) => index));
  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    const section = jobSection(name);
    assert.match(section, /discovered-corpus \(shard \$\{\{ matrix\.shard \}\}\/128\)/);
    assert.match(section, /check-discovered-library-corpus\.sh "\$\{\{ matrix\.shard \}\}" 128/);
  }
});

test('both children of every old priority shard retain priority ownership', () => {
  const priority = new Set(shards(jobSection('discovered_library_priority')));
  const oldPriority = new Set([5, 29, 36, 38, 39, 42]);
  for (let child = 0; child < 128; child++) {
    assert.equal(priority.has(child), oldPriority.has(child % 64), `child ${child}`);
  }
});

test('failed exact versions rehash into priority shards', () => {
  const priority = shards(jobSection('discovered_library_priority'));
  for (const exactVersion of [
    'github.com/Qitmeer/go-ethereum@v1.10.12',
    'github.com/RookieCoderrr/neo3fura-ctrverification@v0.0.0-20221201045318-9878de6dbeed',
    'github.com/SysVerification/gokv@v0.0.0-20250508184610-d007325b6ee8',
    'github.com/reddit/milvus/pkg/v3@v3.0.0-20260702082229-182134e29ebf',
    'github.com/apernet/hysteria/app/v2@v2.12.3',
    'github.com/HyNetwork/hysteria/app@v1.3.5',
    'github.com/intel/ixl-go@v0.0.0-20260223204051-3e809238f558',
  ]) {
    const hash = createHash('sha256').update(exactVersion).digest();
    const shard = Number(hash.readBigUInt64BE(0) % 128n);
    assert.ok(priority.includes(shard), `${exactVersion} belongs to shard ${shard}`);
  }
});

test('priority and remaining shards use identical test and artifact steps', () => {
  function steps(name) {
    const section = jobSection(name);
    return section.slice(section.indexOf('    steps:\n')).trim();
  }
  assert.equal(steps('discovered_library_priority'), steps('discovered_library_corpus'));
  assert.match(jobSection('discovered_library_corpus_verify'),
    /needs: \[discovered_library_priority, discovered_library_corpus\]/);
});

test('discovery matrices have no explicit concurrency cap', () => {
  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    assert.doesNotMatch(jobSection(name), /^      max-parallel:/m, name);
  }
});

test('local discovery helpers use the CI shard count by default', () => {
  for (const name of [
    'check-discovered-library-corpus.sh',
    'verify-discovered-library-corpus.sh',
    'discovery-status.sh',
    'update-assembly-ledger.sh',
  ]) {
    const script = fs.readFileSync(path.join(__dirname, '../../scripts', name), 'utf8');
    assert.match(script, /shard_count=\$\{2:-128\}/, name);
  }
});

test('discovery matrices verify checksums against direct signed databases', () => {
  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    const section = jobSection(name);
    assert.match(section, /^          GOSUMDB:.*sum\.golang\.google\.cn.*sum\.golang\.org https:\/\/sum\.golang\.org/m, name);
    assert.doesNotMatch(section, /^          GOSUMDB: ['"]?off/m, name);
  }
});

test('discovery matrices reuse the task-owned restored Go build cache', () => {
  const setup = fs.readFileSync(
    path.join(__dirname, '../actions/setup-go/action.yml'), 'utf8',
  );
  assert.match(setup, /GOCACHE=\$\{RUNNER_TEMP\}\/go-build-cache/);

  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    const section = jobSection(name);
    const start = section.indexOf('      - name: Translate and compile discovered assembly\n');
    assert.notEqual(start, -1, `missing compilation step in ${name}`);
    const next = section.indexOf('\n      - name:', start + 1);
    const compile = section.slice(start, next < 0 ? section.length : next);
    assert.match(compile,
      /^          PLAN9ASM_DISCOVERY_BUILD_CACHE: \$\{\{ runner\.temp \}\}\/go-build-cache$/m,
      `${name} bypasses the restored task-owned Go cache`);
    assert.match(compile,
      /^        run: scripts\/check-discovered-library-corpus\.sh "\$\{\{ matrix\.shard \}\}" 128$/m);
  }
});

test('discovery compilation leaves time for failed partial report upload', () => {
  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    const section = jobSection(name);
    assert.match(section, /^    timeout-minutes: 360$/m, name);
    assert.match(section,
      /- name: Translate and compile discovered assembly\n(?:        #.*\n)*        timeout-minutes: 330\n/,
      `${name} compilation can consume the whole job deadline`);
    assert.match(section,
      /- name: Upload shard report\n        if: always\(\)\n        timeout-minutes: 10\n/,
      `${name} must upload even a failed partial checkpoint`);
    assert.match(section, /^          if-no-files-found: error$/m, name);
    assert.doesNotMatch(section, /continue-on-error:\s*true/);
  }
});

test('discovery matrices retain optional phase timing separately from reports', () => {
  const script = fs.readFileSync(
    path.join(__dirname, '../../scripts/check-discovered-library-corpus.sh'), 'utf8',
  );
  assert.match(script, /PLAN9ASM_DISCOVERY_EVENTS/);
  assert.match(script, /runner_args\+=\("-discovery-events=\$\{report_path%\.json\}\.events\.jsonl"\)/);

  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    const section = jobSection(name);
    assert.match(section, /^          PLAN9ASM_DISCOVERY_EVENTS: '1'$/m, name);
    assert.match(section,
      /_out\/discovered-library-corpus\/shard-\$\{\{ matrix\.shard \}\}\.events\.jsonl/,
      `${name} drops the requested phase timing artifact`);
  }
});

test('discovery report uploads cannot succeed with only a phase journal', () => {
  for (const name of ['discovered_library_priority', 'discovered_library_corpus']) {
    const section = jobSection(name);
    const report = stepSection(section, 'Upload shard report');
    assert.match(report,
      /^          path: _out\/discovered-library-corpus\/shard-\$\{\{ matrix\.shard \}\}\.json$/m,
      `${name} must require the report itself, not either report or journal`);
    assert.match(report,
      /^          name: discovered-corpus-shard-\$\{\{ matrix\.shard \}\}$/m);
    assert.doesNotMatch(report, /\.events\.jsonl/);

    const events = stepSection(section, 'Upload shard phase journal');
    assert.match(events,
      /^          path: _out\/discovered-library-corpus\/shard-\$\{\{ matrix\.shard \}\}\.events\.jsonl$/m);
    assert.match(events,
      /^          name: discovered-corpus-events-\$\{\{ matrix\.shard \}\}$/m);
    assert.doesNotMatch(events, /name: discovered-corpus-shard-/);

    for (const upload of [report, events]) {
      assert.match(upload, /^        if: always\(\)$/m);
      assert.match(upload, /^        timeout-minutes: 10$/m);
      assert.match(upload, /^        uses: actions\/upload-artifact@v6$/m);
      assert.match(upload, /^          if-no-files-found: error$/m);
      assert.doesNotMatch(upload, /continue-on-error:/);
    }
  }

  assert.match(jobSection('discovered_library_corpus_verify'),
    /^          pattern: discovered-corpus-shard-\*$/m);
});
