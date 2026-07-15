/**
 * PGLite File Lock — prevents concurrent process access to the same data directory.
 *
 * PGLite uses embedded Postgres (WASM) and must have a single OS-process owner.
 * The lock directory is acquired with an atomic mkdir. Lock record v2 binds the
 * PID to a boot identity, process-start identity, and random owner id so a PID
 * reused after reboot (or later in the same boot) cannot impersonate the holder.
 */

import {
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'fs';
import { execFileSync } from 'child_process';
import { randomBytes, randomUUID } from 'crypto';
import { basename, join } from 'path';

const LOCK_DIR_NAME = '.gbrain-lock';
const LOCK_FILE = 'lock';
const HEARTBEAT_INTERVAL_MS = 30_000;
const RETRY_INTERVAL_MS = 250;
const BOOT_TIME_SKEW_MS = 1_000;

export type ProcessLiveness = 'alive' | 'dead' | 'unknown';
export type LockOwnerState = 'live_owner' | 'dead' | 'preboot' | 'pid_reused' | 'unknown';

export interface LockRecordV2 {
  version: 2;
  owner_id: string;
  pid: number;
  process_started_at: string;
  boot_id: string;
  acquired_at: number;
  refreshed_at: number;
  /** Diagnostic executable basename only. Arguments are intentionally omitted. */
  command: string;
}

interface LegacyLockRecord {
  pid: number;
  acquired_at: number;
  refreshed_at?: number;
  command?: string;
}

export interface LockProbeSnapshot {
  currentBootId?: string;
  currentBootStartedAt?: number;
  processLiveness: ProcessLiveness;
  currentProcessStartedAt?: string;
}

export interface LockClassification {
  state: LockOwnerState;
  reclaimable: boolean;
  reason: string;
}

export interface LockHandle {
  lockDir: string;
  acquired: boolean;
  heartbeat?: ReturnType<typeof setInterval>;
  lockPath?: string;
  /** Random v2 ownership identity. Heartbeat and release require an exact match. */
  ownerId?: string;
  /** Deprecated compatibility alias for callers that inspected the former token. */
  ownerToken?: string;
}

function isPositivePid(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function hasLockRecordBase(value: unknown): value is LegacyLockRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return isPositivePid(record.pid)
    && typeof record.acquired_at === 'number'
    && Number.isFinite(record.acquired_at);
}

function isLegacyLockRecord(value: unknown): value is LegacyLockRecord {
  return hasLockRecordBase(value)
    && !Object.prototype.hasOwnProperty.call(value, 'version');
}

function isLockRecordV2(value: unknown): value is LockRecordV2 {
  if (!hasLockRecordBase(value)) return false;
  const record = value as unknown as Record<string, unknown>;
  return record.version === 2
    && typeof record.owner_id === 'string'
    && record.owner_id.length > 0
    && typeof record.process_started_at === 'string'
    && record.process_started_at.length > 0
    && typeof record.boot_id === 'string'
    && record.boot_id.length > 0
    && typeof record.refreshed_at === 'number'
    && Number.isFinite(record.refreshed_at);
}

/**
 * Compare boot identities while accepting Darwin lock-v2 records written as
 * `darwin:<sec>:<usec>`. macOS can change the microsecond component after
 * clock adjustments even though the boot itself is unchanged. Linux boot
 * UUIDs and unknown formats retain exact-match semantics.
 */
function bootIdentitiesMatch(left: string, right: string): boolean {
  const canonical = (value: string): string => {
    const match = value.match(/^darwin:(\d+)(?::\d+)?$/);
    return match ? `darwin:${match[1]}` : value;
  };
  return canonical(left) === canonical(right);
}

/**
 * Classify a parsed lock without performing I/O. Unknown identity evidence is
 * fail-closed. A command mismatch is deliberately not part of this decision.
 */
export function classifyLockRecord(record: unknown, probe: LockProbeSnapshot): LockClassification {
  if (!isLegacyLockRecord(record) && !isLockRecordV2(record)) {
    return { state: 'unknown', reclaimable: false, reason: 'lock_record_invalid' };
  }

  // Legacy records have no boot_id, but their epoch-millisecond acquired_at
  // still proves they predate the current boot. A small skew margin avoids an
  // edge around coarse boot timestamps.
  if (isLegacyLockRecord(record)
    && probe.currentBootStartedAt
    && record.acquired_at + BOOT_TIME_SKEW_MS < probe.currentBootStartedAt) {
    return { state: 'preboot', reclaimable: true, reason: 'acquired_before_current_boot' };
  }

  if (isLockRecordV2(record)
    && probe.currentBootId
    && !bootIdentitiesMatch(record.boot_id, probe.currentBootId)) {
    return { state: 'preboot', reclaimable: true, reason: 'boot_identity_changed' };
  }

  if (probe.processLiveness === 'dead') {
    return { state: 'dead', reclaimable: false, reason: 'pid_not_running_manual_recovery_required' };
  }
  if (probe.processLiveness === 'unknown') {
    return { state: 'unknown', reclaimable: false, reason: 'pid_liveness_unknown' };
  }

  // Legacy records cannot distinguish a live holder from PID reuse. Preserve
  // the old record, fail closed, and let an operator use the doctor/recover path.
  if (!isLockRecordV2(record)) {
    return { state: 'live_owner', reclaimable: false, reason: 'legacy_live_pid' };
  }

  if (!probe.currentBootId) {
    return { state: 'unknown', reclaimable: false, reason: 'current_boot_identity_unavailable' };
  }
  if (!probe.currentProcessStartedAt) {
    return { state: 'unknown', reclaimable: false, reason: 'process_start_identity_unavailable' };
  }
  if (record.process_started_at !== probe.currentProcessStartedAt) {
    return { state: 'pid_reused', reclaimable: true, reason: 'process_start_identity_changed' };
  }
  return { state: 'live_owner', reclaimable: false, reason: 'owner_identity_matches' };
}

function getLockDir(dataDir: string | undefined): string {
  return dataDir ? join(dataDir, LOCK_DIR_NAME) : '';
}

/** Map signal-0 failures into the three-state liveness contract. */
export function livenessFromKillError(error: unknown): ProcessLiveness {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === 'ESRCH' ? 'dead' : 'unknown';
}

function processLiveness(pid: number): ProcessLiveness {
  try {
    process.kill(pid, 0);
    return 'alive';
  } catch (error) {
    return livenessFromKillError(error);
  }
}

/** Read a stable identity for the current OS boot. */
export function readBootIdentity(): string | undefined {
  try {
    if (process.platform === 'linux') {
      const bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
      return bootId ? `linux:${bootId}` : undefined;
    }
    if (process.platform === 'darwin') {
      const raw = execFileSync('/usr/sbin/sysctl', ['-n', 'kern.boottime'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const match = raw.match(/sec\s*=\s*(\d+)\s*,\s*usec\s*=\s*(\d+)/);
      return match ? `darwin:${match[1]}` : undefined;
    }
  } catch {
    // Identity evidence is optional at acquisition time and fail-closed later.
  }
  return undefined;
}

/** Read the current boot's epoch-millisecond start time for legacy locks. */
export function readBootStartedAt(): number | undefined {
  try {
    if (process.platform === 'linux') {
      const line = readFileSync('/proc/stat', 'utf8')
        .split('\n')
        .find(value => value.startsWith('btime '));
      const seconds = line ? Number(line.slice('btime '.length).trim()) : Number.NaN;
      return Number.isFinite(seconds) ? seconds * 1000 : undefined;
    }
    if (process.platform === 'darwin') {
      const raw = execFileSync('/usr/sbin/sysctl', ['-n', 'kern.boottime'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const match = raw.match(/sec\s*=\s*(\d+)\s*,\s*usec\s*=\s*(\d+)/);
      if (!match) return undefined;
      return Number(match[1]) * 1000 + Math.floor(Number(match[2]) / 1000);
    }
  } catch {
    // Missing boot-time evidence remains unknown and therefore fail-closed.
  }
  return undefined;
}

/** Read a stable process-start identity for PID reuse detection. */
export function readProcessStartIdentity(pid: number): string | undefined {
  if (!isPositivePid(pid)) return undefined;
  try {
    if (process.platform === 'linux') {
      const raw = readFileSync(`/proc/${pid}/stat`, 'utf8').trim();
      const closeParen = raw.lastIndexOf(')');
      if (closeParen < 0) return undefined;
      // Fields following comm start at field 3; starttime is field 22.
      const fields = raw.slice(closeParen + 1).trim().split(/\s+/);
      const startTicks = fields[19];
      return startTicks ? `linux-ticks:${startTicks}` : undefined;
    }

    const psPath = existsSync('/bin/ps') ? '/bin/ps' : '/usr/bin/ps';
    const raw = execFileSync(psPath, ['-o', 'lstart=', '-p', String(pid)], {
      encoding: 'utf8',
      env: { ...process.env, LC_ALL: 'C', LANG: 'C', TZ: 'UTC' },
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim().replace(/\s+/g, ' ');
    return raw ? `${process.platform}-lstart:${raw}` : undefined;
  } catch {
    return undefined;
  }
}

function ownerFingerprint(record: unknown): string | undefined {
  if (isLockRecordV2(record)) return `v2:${record.owner_id}`;
  if (isLegacyLockRecord(record)) return `legacy:${record.pid}:${record.acquired_at}`;
  return undefined;
}

function readParsedLock(lockPath: string): unknown {
  return JSON.parse(readFileSync(lockPath, 'utf8'));
}

function probeRecord(record: unknown): LockProbeSnapshot {
  if (!isLegacyLockRecord(record) && !isLockRecordV2(record)) {
    return {
      processLiveness: 'unknown',
      currentBootId: readBootIdentity(),
      currentBootStartedAt: readBootStartedAt(),
    };
  }
  const liveness = processLiveness(record.pid);
  return {
    currentBootId: readBootIdentity(),
    currentBootStartedAt: readBootStartedAt(),
    processLiveness: liveness,
    currentProcessStartedAt: liveness === 'alive' ? readProcessStartIdentity(record.pid) : undefined,
  };
}

/** Restore a claim without ever replacing a canonical lock created by another actor. */
function restoreClaimWithoutClobber(lockPath: string, claimPath: string): boolean {
  try {
    linkSync(claimPath, lockPath);
    unlinkSync(claimPath);
    return true;
  } catch {
    // EEXIST means another canonical owner appeared. Leave the claim in place
    // and fail closed rather than replacing either piece of ownership evidence.
    return false;
  }
}

/**
 * Atomically claim the canonical record while the lock directory remains in
 * place, then remove the directory only after ownership and canonical absence
 * are proven. Keeping the directory occupied prevents a new mkdir owner from
 * appearing in the former fingerprint-read -> rm race window.
 */
function claimAndRemoveLockDir(
  lockDir: string,
  expectedFingerprint: string,
  afterClaimForTest?: (lockPath: string, claimPath: string) => void,
): boolean {
  const lockPath = join(lockDir, LOCK_FILE);
  const claimPath = join(lockDir, `.claim-${process.pid}-${newOwnerId()}`);
  let claimed = false;
  try {
    renameSync(lockPath, claimPath);
    claimed = true;
    afterClaimForTest?.(lockPath, claimPath);
    const claimedRecord = readParsedLock(claimPath);
    if (ownerFingerprint(claimedRecord) !== expectedFingerprint) return false;
    if (existsSync(lockPath)) return false;
    rmSync(lockDir, { recursive: true, force: true });
    return !existsSync(lockDir);
  } catch {
    return false;
  } finally {
    if (claimed && existsSync(lockDir) && existsSync(claimPath)) {
      restoreClaimWithoutClobber(lockPath, claimPath);
    }
  }
}

/** Reap only if the exact record we classified can be atomically claimed. */
function reapIfUnchanged(lockDir: string, expectedRecord: unknown): boolean {
  const expected = ownerFingerprint(expectedRecord);
  return expected ? claimAndRemoveLockDir(lockDir, expected) : false;
}

/** Test seam for deterministic ownership-replacement race coverage. */
export const __testing = {
  claimAndRemoveLockDir,
  ownerFingerprint,
  refreshLockWithHook: refreshClaimedLock,
  restoreClaimWithoutClobber,
};

function newOwnerId(): string {
  try {
    return randomUUID();
  } catch {
    return randomBytes(16).toString('hex');
  }
}

function currentCommandName(): string {
  return basename(process.argv[1] || process.execPath || 'gbrain');
}

/** Refresh a record only after atomically claiming the canonical lock file. */
function refreshClaimedLock(
  lock: LockHandle,
  afterClaimForTest?: (lockPath: string, claimPath: string) => void,
): boolean {
  if (!lock.lockPath || !lock.ownerId) return false;
  const claimPath = join(lock.lockDir, `.claim-heartbeat-${process.pid}-${newOwnerId()}`);
  let claimed = false;
  try {
    renameSync(lock.lockPath, claimPath);
    claimed = true;
    afterClaimForTest?.(lock.lockPath, claimPath);
    const record = readParsedLock(claimPath);
    if (!isLockRecordV2(record) || record.owner_id !== lock.ownerId) return false;
    record.refreshed_at = Date.now();
    writeFileSync(claimPath, JSON.stringify(record), { mode: 0o600 });
    return restoreClaimWithoutClobber(lock.lockPath, claimPath);
  } catch {
    return false;
  } finally {
    if (claimed && existsSync(claimPath)) {
      restoreClaimWithoutClobber(lock.lockPath, claimPath);
    }
  }
}

/** Refresh once, but only when the atomically claimed owner_id still matches. */
export function refreshLock(lock: LockHandle): boolean {
  return refreshClaimedLock(lock);
}

function startHeartbeat(lock: LockHandle): ReturnType<typeof setInterval> {
  const timer = setInterval(() => {
    if (!refreshLock(lock)) clearInterval(timer);
  }, HEARTBEAT_INTERVAL_MS);
  (timer as { unref?: () => void }).unref?.();
  return timer;
}

function formatTimeout(lockDir: string, record: unknown, classification: LockClassification): Error {
  if (isLegacyLockRecord(record)) {
    const since = Number.isFinite(record.acquired_at)
      ? new Date(record.acquired_at).toISOString()
      : 'unknown';
    return new Error(
      `GBrain: Timed out waiting for PGLite lock. PID ${record.pid} has held it since ${since} `
      + `(state: ${classification.state}, reason: ${classification.reason}). `
      + `Run the read-only runtime doctor before recovering ${lockDir}.`,
    );
  }
  return new Error(
    `GBrain: Timed out waiting for PGLite lock (state: ${classification.state}, `
    + `reason: ${classification.reason}). Run the read-only runtime doctor before recovering ${lockDir}.`,
  );
}

/**
 * Attempt to acquire an exclusive lock on the PGLite data directory.
 * Pre-boot and same-boot PID-reuse records are reclaimed only after an atomic
 * ownership claim. Same-boot dead, live, malformed, or unknown records are
 * never removed automatically; dead records require approval-gated recovery.
 */
export async function acquireLock(
  dataDir: string | undefined,
  opts?: { timeoutMs?: number },
): Promise<LockHandle> {
  const lockDir = getLockDir(dataDir);
  if (!lockDir) return { lockDir: '', acquired: true };

  mkdirSync(dataDir as string, { recursive: true });
  const timeoutMs = opts?.timeoutMs ?? 30_000;
  const startedAt = Date.now();
  let lastRecord: unknown;
  let lastClassification: LockClassification = {
    state: 'unknown',
    reclaimable: false,
    reason: 'not_yet_observed',
  };

  while (true) {
    let shouldTryMkdir = !existsSync(lockDir);
    if (!shouldTryMkdir) {
      const lockPath = join(lockDir, LOCK_FILE);
      try {
        lastRecord = readParsedLock(lockPath);
        lastClassification = classifyLockRecord(lastRecord, probeRecord(lastRecord));
        shouldTryMkdir = lastClassification.reclaimable
          ? reapIfUnchanged(lockDir, lastRecord)
          : false;
      } catch {
        // Missing, unreadable, or malformed evidence is fail-closed. It may be
        // a holder between mkdir and lock-file write, so never remove it here.
        lastRecord = undefined;
        lastClassification = {
          state: 'unknown',
          reclaimable: false,
          reason: 'lock_record_unreadable',
        };
      }
    }

    if (shouldTryMkdir) {
      const ownerId = newOwnerId();
      let createdLockDir = false;
      try {
        mkdirSync(lockDir, { recursive: false, mode: 0o700 });
        createdLockDir = true;
        const now = Date.now();
        const bootId = readBootIdentity();
        const processStartedAt = readProcessStartIdentity(process.pid);
        if (!bootId || !processStartedAt) {
          throw new Error('GBrain: cannot establish boot/process identity for PGLite lock v2');
        }
        const lockPath = join(lockDir, LOCK_FILE);
        const record: LockRecordV2 = {
          version: 2,
          owner_id: ownerId,
          pid: process.pid,
          process_started_at: processStartedAt,
          boot_id: bootId,
          acquired_at: now,
          refreshed_at: now,
          command: currentCommandName(),
        };
        writeFileSync(lockPath, JSON.stringify(record), { mode: 0o600 });
        const handle: LockHandle = {
          lockDir,
          acquired: true,
          lockPath,
          ownerId,
          ownerToken: ownerId,
        };
        handle.heartbeat = startHeartbeat(handle);
        return handle;
      } catch (error) {
        // If mkdir succeeded but v2 identity/write failed, this owner never
        // became valid. Remove only the directory we just created.
        if (createdLockDir && existsSync(lockDir)) {
          try {
            rmSync(lockDir, { recursive: true, force: true });
          } catch { /* leave ambiguous state fail-closed */ }
        }
        if (error instanceof Error && error.message.startsWith('GBrain: cannot establish')) {
          throw error;
        }
      }
    }

    const elapsed = Date.now() - startedAt;
    if (elapsed >= timeoutMs) throw formatTimeout(lockDir, lastRecord, lastClassification);
    await new Promise(resolve => setTimeout(resolve, Math.min(RETRY_INTERVAL_MS, timeoutMs - elapsed)));
  }
}

/** Release a lock only when its v2 owner_id is still ours. */
export async function releaseLock(lock: LockHandle): Promise<void> {
  if (lock.heartbeat) {
    clearInterval(lock.heartbeat);
    lock.heartbeat = undefined;
  }
  if (!lock.lockDir || !lock.acquired || !lock.ownerId) return;

  try {
    claimAndRemoveLockDir(lock.lockDir, `v2:${lock.ownerId}`);
  } catch {
    // Unreadable/absent evidence is fail-closed. Never delete an ambiguous lock.
  }
}
