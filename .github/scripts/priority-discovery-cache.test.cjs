const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../scripts/check-discovered-library-corpus.sh'),
  'utf8',
);

function runCorpusFixture(t, failedShard = '', priorityShards = '', phaseEvents = '0',
  aggregateFails = false, shardCount = '5') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-cache-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const scripts = path.join(root, 'scripts');
  const bin = path.join(root, 'bin');
  fs.mkdirSync(scripts);
  fs.mkdirSync(bin);
  const calls = path.join(root, 'calls');
  const verified = path.join(root, 'verified');
  const aggregateArgsFile = path.join(root, 'aggregate-args');
  const dispatch = path.join(root, 'dispatch');
  const caches = path.join(root, 'caches');
  fs.mkdirSync(caches);
  const callerCache = path.join(root, 'caller-cache');
  fs.mkdirSync(callerCache);
  fs.writeFileSync(path.join(callerCache, 'keep'), 'caller-owned');
  const runner = path.join(scripts, 'check-discovered-library-corpus.sh');
  fs.writeFileSync(runner, source, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'xargs'), `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "\${PLAN9ASM_DISCOVERY_BUILD_CACHE+x}" ]]; then
  echo 'queue inherited a shared build cache' >&2
  exit 91
fi
printf '%s\\n' "$@" >> "$FIXTURE_DISPATCH"
status=0
while IFS= read -r shard; do
  printf '%s\\n' "$shard" >> "$FIXTURE_CALLS"
  if [[ "$shard" == "$FIXTURE_FAILED_SHARD" ]]; then
    status=123
  fi
done
exit "$status"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(scripts, 'verify-discovered-library-corpus.sh'), `#!/usr/bin/env bash
set -euo pipefail
printf 'verified\n' >> "$FIXTURE_VERIFIED"
printf '%s\\n' "$@" > "$FIXTURE_AGGREGATE_ARGS"
test "$FIXTURE_AGGREGATE_FAIL" = 0
`, { mode: 0o755 });
  const args = [runner, 'all'];
  if (shardCount !== null) args.push(shardCount);
  const result = spawnSync('bash', args, {
    encoding: 'utf8',
    timeout: 10000,
    env: {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      TMPDIR: caches,
      PLAN9ASM_DISCOVERY_PARALLELISM: '2',
      PLAN9ASM_DISCOVERY_PRIORITY_SHARDS: priorityShards,
      PLAN9ASM_DISCOVERY_EVENTS: phaseEvents,
      PLAN9ASM_DISCOVERY_BUILD_CACHE: callerCache,
      FIXTURE_CALLS: calls,
      FIXTURE_DISPATCH: dispatch,
      FIXTURE_VERIFIED: verified,
      FIXTURE_AGGREGATE_ARGS: aggregateArgsFile,
      FIXTURE_FAILED_SHARD: failedShard,
      FIXTURE_AGGREGATE_FAIL: aggregateFails ? '1' : '0',
    },
  });
  assert.ifError(result.error);
  const records = fs.existsSync(calls)
    ? fs.readFileSync(calls, 'utf8').trim().split('\n')
    : [];
  const dispatchArgs = fs.existsSync(dispatch)
    ? fs.readFileSync(dispatch, 'utf8').trim().split('\n')
    : [];
  const aggregateArgs = fs.existsSync(aggregateArgsFile)
    ? fs.readFileSync(aggregateArgsFile, 'utf8').trim().split('\n')
    : [];
  assert.equal(fs.readFileSync(path.join(callerCache, 'keep'), 'utf8'), 'caller-owned');
  return { result, records, dispatchArgs, aggregateArgs, runner, root, caches, verified };
}

// The Go TestDiscoveryAllQueue* fixtures execute real concurrent children and
// prove immediate refill. This cheap policy fixture checks the shell handoff,
// not the old batch barrier or the corpus process's own cache implementation.
test('discovery dispatches one bounded refill queue without a shared caller cache', (t) => {
  const { result, records, dispatchArgs, runner, root, caches, verified } = runCorpusFixture(t);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(records, ['0', '1', '2', '3', '4']);
  assert.deepEqual(dispatchArgs, [
    '-P', '2', '-I', '{}', runner, '{}', '5',
    path.join(root, '_out/discovered-library-corpus/shard-{}.json'),
  ]);
  assert.deepEqual(fs.readdirSync(caches), []);
  assert.equal(fs.readFileSync(verified, 'utf8'), 'verified\n');
});

test('failed discovery shards retain failures, drain the queue and run the final gate', (t) => {
  const { result, records, caches, verified } = runCorpusFixture(t, '2');
  assert.notEqual(result.status, 0);
  assert.deepEqual(records, ['0', '1', '2', '3', '4']);
  assert.deepEqual(fs.readdirSync(caches), []);
  assert.equal(fs.readFileSync(verified, 'utf8'), 'verified\n');
});

test('priority shards run first without omitting or repeating other shards', (t) => {
  const { result, records, caches, verified } = runCorpusFixture(t, '', '4,2');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(records, ['4', '2', '0', '1', '3']);
  assert.deepEqual(fs.readdirSync(caches), []);
  assert.equal(fs.readFileSync(verified, 'utf8'), 'verified\n');
});

test('default split queue and aggregate agree on all 128 shards', (t) => {
  const priority = [5, 29, 36, 38, 39, 42, 69, 93, 100, 102, 103, 106];
  const { result, records, dispatchArgs, aggregateArgs, root } =
    runCorpusFixture(t, '', priority.join(','), '0', false, null);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(records.slice(0, priority.length), priority.map(String));
  assert.deepEqual(records.map(Number).sort((a, b) => a - b),
    Array.from({ length: 128 }, (_, index) => index));
  assert.equal(dispatchArgs[6], '128');
  assert.deepEqual(aggregateArgs, [
    path.join(root, '_out/discovered-library-corpus'), '128',
  ]);
});

test('successful shards cannot hide a failed final aggregate', (t) => {
  const { result, records, verified } = runCorpusFixture(t, '', '', '0', true);
  assert.notEqual(result.status, 0);
  assert.deepEqual(records, ['0', '1', '2', '3', '4']);
  assert.equal(fs.readFileSync(verified, 'utf8'), 'verified\n');
});

test('invalid priority lists fail before starting corpus work', (t) => {
  for (const priority of ['5', '2,2', '-1', '1,,2', ',1', '1,', '01', '1 x',
    '18446744073709551616']) {
    const { result, records, caches, verified } = runCorpusFixture(t, '', priority);
    assert.notEqual(result.status, 0, `accepted invalid priority ${priority}`);
    assert.deepEqual(records, []);
    assert.deepEqual(fs.readdirSync(caches), []);
    assert.equal(fs.existsSync(verified), false);
  }
});

test('invalid phase timing options fail before starting corpus work', (t) => {
  for (const value of ['true', '2', '-1', '1 x']) {
    const { result, records, caches, verified } = runCorpusFixture(t, '', '', value);
    assert.equal(result.status, 2, `accepted invalid timing option ${value}`);
    assert.match(result.stderr, /invalid PLAN9ASM_DISCOVERY_EVENTS/);
    assert.deepEqual(records, []);
    assert.deepEqual(fs.readdirSync(caches), []);
    assert.equal(fs.existsSync(verified), false);
  }
});
