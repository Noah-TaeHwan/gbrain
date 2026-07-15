import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { mkdirSync, rmSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { withEnv } from './helpers/with-env';
import {
  __testing,
  acquireLock,
  classifyLockRecord,
  livenessFromKillError,
  readBootIdentity,
  readBootStartedAt,
  readProcessStartIdentity,
  refreshLock,
  releaseLock,
  type LockHandle,
  type LockRecordV2,
} from '../src/core/pglite-lock';

const TEST_DIR = join(tmpdir(), 'gbrain-lock-test-' + process.pid);

describe('pglite-lock', () => {
  beforeEach(() => {
    // Clean up test directory
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
  });

  test('acquires and releases lock', async () => {
    const lock = await acquireLock(TEST_DIR);
    expect(lock.acquired).toBe(true);
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(true);

    await releaseLock(lock);
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(false);
  });

  test('creates missing data directory before acquiring lock', async () => {
    const missingDataDir = join(TEST_DIR, 'missing-data-dir');

    const lock = await acquireLock(missingDataDir);
    expect(lock.acquired).toBe(true);
    expect(existsSync(missingDataDir)).toBe(true);
    expect(existsSync(join(missingDataDir, '.gbrain-lock'))).toBe(true);

    await releaseLock(lock);
    expect(existsSync(join(missingDataDir, '.gbrain-lock'))).toBe(false);
  });

  test('prevents concurrent lock acquisition', async () => {
    const lock1 = await acquireLock(TEST_DIR, { timeoutMs: 2000 });
    expect(lock1.acquired).toBe(true);

    // Second lock attempt should timeout
    await expect(acquireLock(TEST_DIR, { timeoutMs: 1000 })).rejects.toThrow(/Timed out/);

    await releaseLock(lock1);
  });

  test('keeps a same-boot dead-PID lock fail-closed for approval-gated recovery', async () => {
    // Simulate a stale lock from a dead process
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    mkdirSync(lockDir);
    writeFileSync(join(lockDir, 'lock'), JSON.stringify({
      pid: 999999999, // Non-existent PID
      acquired_at: Date.now(),
      command: 'test',
    }));

    await expect(acquireLock(TEST_DIR, { timeoutMs: 100 })).rejects.toThrow(/state: dead/);
    expect(existsSync(lockDir)).toBe(true);
  });

  test('reclaims a live-PID legacy lock that provably predates this boot', async () => {
    const currentBootStartedAt = readBootStartedAt();
    expect(currentBootStartedAt).toBeDefined();
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    mkdirSync(lockDir);
    writeFileSync(join(lockDir, 'lock'), JSON.stringify({
      pid: process.pid,
      acquired_at: (currentBootStartedAt as number) - 10_000,
      refreshed_at: (currentBootStartedAt as number) - 9_000,
      command: 'legacy-owner',
    }));

    const lock = await acquireLock(TEST_DIR);
    const after = JSON.parse(readFileSync(join(lockDir, 'lock'), 'utf-8'));
    expect(after.version).toBe(2);
    await releaseLock(lock);
  });

  test('reclaims a v2 lock from a previous boot even when its PID was reused', async () => {
    const currentBoot = readBootIdentity();
    const currentStart = readProcessStartIdentity(process.pid);
    expect(currentBoot).toBeDefined();
    expect(currentStart).toBeDefined();
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    mkdirSync(lockDir);
    writeFileSync(join(lockDir, 'lock'), JSON.stringify({
      version: 2,
      owner_id: 'old-boot-owner',
      pid: process.pid,
      process_started_at: currentStart,
      boot_id: `${currentBoot}-previous`,
      acquired_at: Date.now() - 10_000,
      refreshed_at: Date.now() - 10_000,
      command: 'old-owner',
    }));

    const lock = await acquireLock(TEST_DIR);
    const after = JSON.parse(readFileSync(join(lockDir, 'lock'), 'utf-8'));
    expect(after.owner_id).not.toBe('old-boot-owner');
    await releaseLock(lock);
  });

  test('reclaims same-boot PID reuse when process-start identity differs', async () => {
    const currentBoot = readBootIdentity();
    const currentStart = readProcessStartIdentity(process.pid);
    expect(currentBoot).toBeDefined();
    expect(currentStart).toBeDefined();
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    mkdirSync(lockDir);
    writeFileSync(join(lockDir, 'lock'), JSON.stringify({
      version: 2,
      owner_id: 'reused-pid-owner',
      pid: process.pid,
      process_started_at: `${currentStart}-different`,
      boot_id: currentBoot,
      acquired_at: Date.now() - 10_000,
      refreshed_at: Date.now() - 10_000,
      command: 'old-owner',
    }));

    const lock = await acquireLock(TEST_DIR);
    const after = JSON.parse(readFileSync(join(lockDir, 'lock'), 'utf-8'));
    expect(after.owner_id).not.toBe('reused-pid-owner');
    await releaseLock(lock);
  });

  test('skips lock for in-memory (undefined dataDir)', async () => {
    const lock = await acquireLock(undefined);
    expect(lock.acquired).toBe(true);
    expect(lock.lockDir).toBe('');

    // Release should be a no-op
    await releaseLock(lock);
  });

  test('lock file contains v2 owner, boot, process-start, and heartbeat identities', async () => {
    const lock = await acquireLock(TEST_DIR);
    const lockData = JSON.parse(readFileSync(join(TEST_DIR, '.gbrain-lock', 'lock'), 'utf-8'));

    expect(lockData.version).toBe(2);
    expect(typeof lockData.owner_id).toBe('string');
    expect(lockData.owner_id.length).toBeGreaterThan(0);
    expect(lockData.pid).toBe(process.pid);
    expect(typeof lockData.process_started_at).toBe('string');
    expect(lockData.process_started_at.length).toBeGreaterThan(0);
    expect(typeof lockData.boot_id).toBe('string');
    expect(lockData.boot_id.length).toBeGreaterThan(0);
    expect(lockData.acquired_at).toBeDefined();
    expect(lockData.refreshed_at).toBeDefined();
    expect(lockData.command).toBeDefined();
    // Arguments can carry secrets and are deliberately absent from v2 records.
    expect(lockData.command).not.toContain(' ');

    await releaseLock(lock);
  });

  test('process-start identity is invariant across caller locale and timezone', async () => {
    const localized = await withEnv(
      { LC_ALL: 'ko_KR.UTF-8', LANG: 'ko_KR.UTF-8', TZ: 'Asia/Seoul' },
      () => readProcessStartIdentity(process.pid),
    );
    const canonical = await withEnv(
      { LC_ALL: 'C', LANG: 'C', TZ: 'UTC' },
      () => readProcessStartIdentity(process.pid),
    );
    expect(localized).toBeDefined();
    expect(localized).toBe(canonical);
  });

  test('an unreadable lock is fail-closed and is not automatically removed', async () => {
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    mkdirSync(lockDir);
    writeFileSync(join(lockDir, 'lock'), '{not-json');

    await expect(acquireLock(TEST_DIR, { timeoutMs: 100 })).rejects.toThrow(/state: unknown/);
    expect(existsSync(lockDir)).toBe(true);
  });

  test('releases lock on disconnect even if DB close fails', async () => {
    const lock = await acquireLock(TEST_DIR);
    expect(lock.acquired).toBe(true);

    // Simulate DB already closed
    await releaseLock(lock);
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(false);

    // Second acquisition should work
    const lock2 = await acquireLock(TEST_DIR);
    expect(lock2.acquired).toBe(true);
    await releaseLock(lock2);
  });
});

describe('pglite-lock owner identity + fail-closed recovery', () => {
  beforeEach(() => {
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
  });
  afterEach(() => {
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
  });

  function writeHolder(fields: { pid: number; acquiredAgoMs: number; refreshedAgoMs: number }) {
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    mkdirSync(lockDir, { recursive: true });
    const now = Date.now();
    writeFileSync(join(lockDir, 'lock'), JSON.stringify({
      pid: fields.pid,
      acquired_at: now - fields.acquiredAgoMs,
      refreshed_at: now - fields.refreshedAgoMs,
      command: 'test holder',
    }));
  }

  test('[REGRESSION] a LIVE holder with a fresh heartbeat is NOT stolen even when the lock is old', async () => {
    // The WAL-corruption bug: a >5min embed used to get its lock force-removed.
    // Now an alive holder that heartbeated recently is left alone regardless of
    // age. acquired 20min ago, but refreshed just now → must wait, not steal.
    writeHolder({ pid: process.pid, acquiredAgoMs: 20 * 60_000, refreshedAgoMs: 0 });

    await expect(acquireLock(TEST_DIR, { timeoutMs: 1200 })).rejects.toThrow(/Timed out/);
    // Holder's lock still present (was never stolen).
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(true);
  });

  test('[REGRESSION #2348] a LIVE PID with a STALE heartbeat is NOT stolen', async () => {
    // The #2348 corruption: a live `gbrain dream`/embed holder whose heartbeat
    // lapsed (the JS event loop is blocked during a long synchronous WASM
    // import) used to get its lock reaped past the grace window — letting a
    // second OS process open the same data dir and corrupt the catalog +
    // pgvector extension state. A live PID is now NEVER stolen, regardless of
    // how stale its heartbeat is. Acquire must time out, not steal.
    writeHolder({ pid: process.pid, acquiredAgoMs: 25 * 60_000, refreshedAgoMs: 20 * 60_000 });

    await expect(acquireLock(TEST_DIR, { timeoutMs: 1200 })).rejects.toThrow(/Timed out/);
    // The live holder's lock is still present — never force-removed.
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(true);
  });

  test('[REGRESSION] releaseLock does NOT remove a lock that was stolen + re-acquired by another process', async () => {
    // We acquire, then simulate a steal: another process reaped us past grace
    // and now owns the lock (different pid + acquired_at). Our releaseLock must
    // NOT delete their live lock — doing so would let a third process in
    // alongside the new owner (the #2058 corruption class).
    const lock: LockHandle = await acquireLock(TEST_DIR);
    expect(lock.acquired).toBe(true);
    expect(lock.ownerToken).toBeDefined();
    if (lock.heartbeat) clearInterval(lock.heartbeat); // stop our heartbeat for a deterministic test

    // Overwrite the lock file as if process B re-acquired it.
    const lockFile = join(TEST_DIR, '.gbrain-lock', 'lock');
    const bNow = Date.now() + 1;
    const original = JSON.parse(readFileSync(lockFile, 'utf-8')) as LockRecordV2;
    writeFileSync(lockFile, JSON.stringify({
      ...original,
      owner_id: 'replacement-owner',
      acquired_at: bNow,
      refreshed_at: bNow,
    }));

    await releaseLock(lock); // our (stale) handle

    // B's lock survives — we did not clobber it.
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(true);
    const after = JSON.parse(readFileSync(lockFile, 'utf-8'));
    expect(after.owner_id).toBe('replacement-owner');

    // Cleanup for afterEach.
    rmSync(join(TEST_DIR, '.gbrain-lock'), { recursive: true, force: true });
  });

  test('acquire starts a heartbeat and seeds refreshed_at; release clears it', async () => {
    const lock: LockHandle = await acquireLock(TEST_DIR);
    expect(lock.acquired).toBe(true);
    expect(lock.heartbeat).toBeDefined();
    const data = JSON.parse(readFileSync(join(TEST_DIR, '.gbrain-lock', 'lock'), 'utf-8'));
    expect(data.refreshed_at).toBeDefined();
    expect(typeof data.refreshed_at).toBe('number');

    await releaseLock(lock);
    expect(lock.heartbeat).toBeUndefined();
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(false);
  });

  test('heartbeat refuses to refresh a replacement owner', async () => {
    const lock = await acquireLock(TEST_DIR);
    if (lock.heartbeat) clearInterval(lock.heartbeat);
    const lockFile = join(TEST_DIR, '.gbrain-lock', 'lock');
    const replacement = JSON.parse(readFileSync(lockFile, 'utf-8')) as LockRecordV2;
    replacement.owner_id = 'new-owner';
    replacement.refreshed_at = 123;
    writeFileSync(lockFile, JSON.stringify(replacement));

    expect(refreshLock(lock)).toBe(false);
    const after = JSON.parse(readFileSync(lockFile, 'utf-8'));
    expect(after.owner_id).toBe('new-owner');
    expect(after.refreshed_at).toBe(123);

    await releaseLock(lock);
    expect(existsSync(join(TEST_DIR, '.gbrain-lock'))).toBe(true);
    rmSync(join(TEST_DIR, '.gbrain-lock'), { recursive: true, force: true });
  });

  test('atomic claim preserves a canonical owner created after the claim', async () => {
    const lock = await acquireLock(TEST_DIR);
    if (lock.heartbeat) clearInterval(lock.heartbeat);
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    const lockFile = join(lockDir, 'lock');
    const original = JSON.parse(readFileSync(lockFile, 'utf-8')) as LockRecordV2;
    const replacement = { ...original, owner_id: 'replacement-after-claim' };
    const expected = __testing.ownerFingerprint(original);
    expect(expected).toBeDefined();

    const removed = __testing.claimAndRemoveLockDir(lockDir, expected as string, canonical => {
      writeFileSync(canonical, JSON.stringify(replacement));
    });

    expect(removed).toBe(false);
    expect(existsSync(lockDir)).toBe(true);
    expect(JSON.parse(readFileSync(lockFile, 'utf-8')).owner_id).toBe('replacement-after-claim');
    rmSync(lockDir, { recursive: true, force: true });
  });

  test('heartbeat claim refuses to overwrite a canonical replacement', async () => {
    const lock = await acquireLock(TEST_DIR);
    if (lock.heartbeat) clearInterval(lock.heartbeat);
    const lockDir = join(TEST_DIR, '.gbrain-lock');
    const lockFile = join(lockDir, 'lock');
    const original = JSON.parse(readFileSync(lockFile, 'utf-8')) as LockRecordV2;
    const replacement = { ...original, owner_id: 'heartbeat-race-winner', refreshed_at: 123 };

    const refreshed = __testing.refreshLockWithHook(lock, canonical => {
      writeFileSync(canonical, JSON.stringify(replacement));
    });

    expect(refreshed).toBe(false);
    const after = JSON.parse(readFileSync(lockFile, 'utf-8'));
    expect(after.owner_id).toBe('heartbeat-race-winner');
    expect(after.refreshed_at).toBe(123);
    rmSync(lockDir, { recursive: true, force: true });
  });
});

describe('pglite-lock v2 classifier', () => {
  const record: LockRecordV2 = {
    version: 2,
    owner_id: 'owner-a',
    pid: 123,
    process_started_at: 'start-a',
    boot_id: 'boot-a',
    acquired_at: 100,
    refreshed_at: 200,
    command: 'gbrain',
  };

  test('reclaims a record from a previous boot even when the PID is alive', () => {
    expect(classifyLockRecord(record, {
      currentBootId: 'boot-b',
      processLiveness: 'alive',
      currentProcessStartedAt: 'start-a',
    })).toEqual({ state: 'preboot', reclaimable: true, reason: 'boot_identity_changed' });
  });

  test('reclaims a legacy record whose acquired_at predates the current boot', () => {
    expect(classifyLockRecord({ pid: 123, acquired_at: 1_000 }, {
      currentBootId: 'boot-a',
      currentBootStartedAt: 10_000,
      processLiveness: 'alive',
      currentProcessStartedAt: 'start-a',
    })).toEqual({ state: 'preboot', reclaimable: true, reason: 'acquired_before_current_boot' });
  });

  test('uses boot_id, not acquired_at, for a valid same-boot v2 owner', () => {
    expect(classifyLockRecord({ ...record, acquired_at: 100 }, {
      currentBootId: 'boot-a',
      currentBootStartedAt: 10_000,
      processLiveness: 'alive',
      currentProcessStartedAt: 'start-a',
    })).toEqual({ state: 'live_owner', reclaimable: false, reason: 'owner_identity_matches' });
  });

  test('reclaims same-boot PID reuse', () => {
    expect(classifyLockRecord(record, {
      currentBootId: 'boot-a',
      processLiveness: 'alive',
      currentProcessStartedAt: 'start-b',
    })).toEqual({ state: 'pid_reused', reclaimable: true, reason: 'process_start_identity_changed' });
  });

  test('keeps a genuine live owner even when command diagnostics differ', () => {
    expect(classifyLockRecord({ ...record, command: 'unrelated-name' }, {
      currentBootId: 'boot-a',
      processLiveness: 'alive',
      currentProcessStartedAt: 'start-a',
    })).toEqual({ state: 'live_owner', reclaimable: false, reason: 'owner_identity_matches' });
  });

  test('fails closed on EPERM and other unknown liveness errors', () => {
    expect(livenessFromKillError(Object.assign(new Error('denied'), { code: 'EPERM' }))).toBe('unknown');
    expect(classifyLockRecord(record, {
      currentBootId: 'boot-a',
      processLiveness: 'unknown',
    })).toEqual({ state: 'unknown', reclaimable: false, reason: 'pid_liveness_unknown' });
  });

  test('keeps a live legacy lock because PID reuse cannot be proven', () => {
    expect(classifyLockRecord({ pid: 123, acquired_at: 100, command: 'legacy' }, {
      currentBootId: 'boot-a',
      processLiveness: 'alive',
      currentProcessStartedAt: 'start-b',
    })).toEqual({ state: 'live_owner', reclaimable: false, reason: 'legacy_live_pid' });
  });

  test('does not auto-reap a same-boot dead PID', () => {
    expect(classifyLockRecord({ pid: 123, acquired_at: 100 }, {
      currentBootId: 'boot-a',
      processLiveness: 'dead',
    })).toEqual({
      state: 'dead',
      reclaimable: false,
      reason: 'pid_not_running_manual_recovery_required',
    });
  });

  test('fails closed on a malformed record that claims version 2', () => {
    expect(classifyLockRecord({ pid: 123, acquired_at: 100, version: 2 }, {
      currentBootId: 'boot-a',
      currentBootStartedAt: 10_000,
      processLiveness: 'dead',
    })).toEqual({ state: 'unknown', reclaimable: false, reason: 'lock_record_invalid' });
  });

  test('fails closed on a future lock record instead of treating it as legacy', () => {
    expect(classifyLockRecord({ pid: 123, acquired_at: 100, version: 3 }, {
      currentBootId: 'boot-a',
      currentBootStartedAt: 10_000,
      processLiveness: 'dead',
    })).toEqual({ state: 'unknown', reclaimable: false, reason: 'lock_record_invalid' });
  });
});
