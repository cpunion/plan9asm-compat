const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'scripts/verify-discovered-library-corpus.sh'), 'utf8');

test('aggregate audits reports once for progress, strict completion and ledger comparison', () => {
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/go-ci.yml'), 'utf8');
  const aggregate = workflow.split('\n  discovered_library_corpus_verify:\n')[1].split('\n  stdlib-corpus:\n')[0];
  assert.equal((aggregate.match(/run: scripts\/verify-discovered-library-corpus.sh --progress/g) || []).length, 1);
  assert.doesNotMatch(aggregate, /scripts\/discovery-status.sh/);
  assert.match(aggregate, /Upload discovery progress\n        if: \$\{\{ !cancelled\(\) \}\}/);

  const main = fs.readFileSync(path.join(root, 'cmd/plan9asmcorpus/main.go'), 'utf8');
  const verification = main.split('\n\tif *verifyDiscoveryReports != "" {')[1].split('\n\tif *assemblyLedgerStatusPath != "" {')[0];
  assert.equal((verification.match(/collectDiscoveryProgress\(/g) || []).length, 1);
  assert.doesNotMatch(verification, /verifyDiscoveryCorpusReports\(/);
});

function verifyFixture(t, mode) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-aggregate-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const scripts = path.join(temporary, 'scripts');
  const bin = path.join(temporary, 'bin');
  const reports = path.join(temporary, 'reports');
  const calls = path.join(temporary, 'calls.jsonl');
  fs.mkdirSync(scripts);
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(scripts, 'verify-discovered-library-corpus.sh'), source, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'go'), `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FIXTURE_CALLS, JSON.stringify(args) + '\\n');
if (args.includes('-discovery-progress-directory')) {
  if (process.env.FIXTURE_MODE === 'preflight failure') {
    process.stderr.write('unsafe output directory\\n');
    process.exit(1);
  }
  process.stdout.write(path.resolve(args[args.indexOf('-discovery-progress-directory') + 1]) + '\\n');
} else if (args.includes('./cmd/plan9asmdiscover')) {
  if (process.env.FIXTURE_MODE === 'scan failure') {
    process.stderr.write('scan fixture failed\\n');
    process.exit(7);
  }
  if (process.env.FIXTURE_MODE === 'late scan') {
    fs.writeFileSync(process.env.FIXTURE_REPORTS + '/scan-status.json', '{"original":"scan"}\\n', {flag: 'wx'});
  }
  if (process.env.FIXTURE_MODE === 'late scan directory') {
    fs.mkdirSync(process.env.FIXTURE_REPORTS + '/scan-status.json');
  }
  process.stdout.write('{"index_entries":12}\\n');
} else if (args.includes('-discovery-progress-output')) {
  if (process.env.FIXTURE_MODE === 'late progress') {
    fs.writeFileSync(process.env.FIXTURE_REPORTS + '/assembly-progress.json', '{"original":"progress"}\\n', {flag: 'wx'});
  }
  if (process.env.FIXTURE_MODE !== 'invalid') {
    const output = args[args.indexOf('-discovery-progress-output') + 1];
    fs.writeFileSync(output, JSON.stringify({complete: process.env.FIXTURE_MODE === 'pass', verified: process.env.FIXTURE_MODE === 'pass'}) + '\\n', {flag: 'wx'});
  }
  if (['partial', 'invalid'].includes(process.env.FIXTURE_MODE)) {
    process.stderr.write('strict reader remains failed\\n');
    process.exit(1);
  }
} else {
  process.stderr.write('expected one combined strict/progress invocation\\n');
  process.exit(9);
}

`, { mode: 0o755 });
  const result = spawnSync('bash', [path.join(scripts, 'verify-discovered-library-corpus.sh'), '--progress', reports], {
    encoding: 'utf8', timeout: 10000,
    env: { ...process.env, PATH: bin + path.delimiter + process.env.PATH, FIXTURE_CALLS: calls, FIXTURE_MODE: mode, FIXTURE_REPORTS: reports },
  });
  assert.ifError(result.error);
  const invocations = fs.existsSync(calls) ? fs.readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse) : [];
  return { result, invocations, reports };
}

test('aggregate phase logging preserves a scan failure exit and cleans only its temporary output', (t) => {
  const { result, invocations, reports } = verifyFixture(t, 'scan failure');
  assert.equal(result.status, 7, result.stderr);
  assert.equal(invocations.length, 2);
  assert.match(result.stderr, /discovery verification: scan-ledger finished status=7 elapsed=[0-9]+s/);
  assert.doesNotMatch(result.stderr, /discovery verification: report-audit/);
  assert.equal(result.stdout, '');
  assert.deepEqual(fs.readdirSync(reports), []);
});

for (const mode of ['late scan', 'late progress']) {
  test(`aggregate refuses to overwrite a ${mode} destination`, (t) => {
    const { result, invocations, reports } = verifyFixture(t, mode);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(invocations.length, mode === 'late scan' ? 2 : 3);
    const filename = mode === 'late scan' ? 'scan-status.json' : 'assembly-progress.json';
    const original = mode === 'late scan' ? 'scan' : 'progress';
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(reports, filename), 'utf8')), { original });
    assert.deepEqual(fs.readdirSync(reports).filter(name => name.startsWith('.status-')), []);
  });
}

test('aggregate refuses a late directory without linking inside it', (t) => {
  const { result, invocations, reports } = verifyFixture(t, 'late scan directory');
  assert.equal(result.status, 1, result.stderr);
  assert.equal(invocations.length, 2);
  assert.deepEqual(fs.readdirSync(path.join(reports, 'scan-status.json')), []);
  assert.deepEqual(fs.readdirSync(reports).filter(name => name.startsWith('.status-')), []);
});

for (const mode of ['pass', 'partial', 'invalid']) {
  test(`combined aggregate ${mode} preserves the strict exit and only audited progress`, (t) => {
    const { result, invocations, reports } = verifyFixture(t, mode);
    assert.equal(result.status, mode === 'pass' ? 0 : 1, result.stderr);
    assert.equal(invocations.length, 3);
    assert.ok(invocations[0].includes('-discovery-progress-directory'));
    assert.ok(invocations[2].includes('-discovery-progress-output'));
    assert.ok(invocations[2].includes('-verify-discovery-reports'));
    assert.ok(invocations[2].includes('-compare-assembly-ledger'));
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(reports, 'scan-status.json'), 'utf8')), { index_entries: 12 });
    const progress = path.join(reports, 'assembly-progress.json');
    if (mode === 'invalid') {
      assert.equal(fs.existsSync(progress), false);
    } else {
      assert.deepEqual(JSON.parse(fs.readFileSync(progress, 'utf8')), { complete: mode === 'pass', verified: mode === 'pass' });
    }
    assert.deepEqual(fs.readdirSync(reports).filter(name => name.startsWith('.status-')), []);
  });
}

test('aggregate rejects unsafe output before mkdir or status collection', (t) => {
  const { result, invocations, reports } = verifyFixture(t, 'preflight failure');
  assert.equal(result.status, 1);
  assert.equal(invocations.length, 1);
  assert.ok(invocations[0].includes('-discovery-progress-directory'));
  assert.equal(fs.existsSync(reports), false);
});

for (const mode of ['pass', 'partial', 'invalid', 'preflight failure']) {
  test(`aggregate ${mode} exposes each running phase without polluting JSON`, (t) => {
    const { result, invocations, reports } = verifyFixture(t, mode);
    const phases = mode === 'preflight failure'
      ? ['directory-preflight']
      : ['directory-preflight', 'scan-ledger', 'report-audit'];
    const lines = result.stderr.split('\n').filter(line => line.startsWith('discovery verification:'));
    assert.equal(lines.length, phases.length * 2, result.stderr);
    for (const [index, phase] of phases.entries()) {
      assert.equal(lines[index * 2], `discovery verification: ${phase} started`);
      const failed = index === phases.length - 1 && mode !== 'pass';
      assert.match(lines[index * 2 + 1], new RegExp(
        `^discovery verification: ${phase} finished status=${failed ? 1 : 0} elapsed=[0-9]+s$`));
    }
    assert.equal(invocations.length, phases.length);
    assert.equal(result.stdout, '');
    if (mode !== 'preflight failure') {
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(reports, 'scan-status.json'), 'utf8')),
        { index_entries: 12 });
    }
  });
}
