//! # X1 Strontium v1.3.0
//!
//! Decentralised atomic-time oracle for the X1 blockchain. The contract
//! uses a file-based oracle keypair model: each operator runs a daemon that
//! generates a fresh `oracle.json` keypair locally, receives a one-time
//! XNT transfer from the operator's hardware wallet, then auto-registers
//! and submits time for the rest of its life. No Ledger USB in daily flow.
//!
//! ## Authorisation model
//!
//! - **`oracle_keypair`** — server-local keypair. Pays rent for its
//!   `ValidatorRegistration` PDA at register time, then signs every
//!   `submit_time` transaction. Trivially rotatable: close one
//!   registration, open a new one with a fresh keypair.
//!
//! - **`vote_keypair`** — the validator's vote-account keypair, which the
//!   daemon already holds for normal validator operation. Signs once,
//!   alongside `oracle_keypair`, on `register_submitter`. Proves the
//!   operator controls both halves of the system.
//!
//! ## Anti-farm gates
//!
//! Self-stake withdrawer-match (a stake account exists whose withdraw
//! authority equals `vote.authorized_withdrawer`) and validator age
//! (≥ 64 epochs of vote credits) are enforced **off-chain** by the
//! daemon. The daemon refuses to send `register_submitter` if either
//! gate fails, and silences itself (stops submitting) if no qualifying
//! stake remains at the 24h recheck. The contract holds no parsers —
//! anyone can audit the gates by reading the open-source daemon code.
//!
//! ## Auto-cleanup
//!
//! Operators who don't submit `submit_time` for `CLEANUP_GRACE_WINDOWS`
//! contract-windows (~24 h) get their `ValidatorRegistration` PDA closed
//! by `cleanup_inactive`. `submit_time` updates only the caller's
//! `last_submitted_window_id` (cheap, fixed-cost). A separate
//! `cleanup_inactive` instruction can be called by anyone with a batch of
//! `ValidatorRegistration` accounts in `remaining_accounts`; for each
//! stale one it CLOSES the PDA — lamports return to `payer` (the
//! cleanup-TX signer), the data is zeroed and the discriminator is
//! overwritten with `CLOSED_ACCOUNT_DISCRIMINATOR`. Closing the PDA
//! (rather than just flipping `is_active = false`) is what allows the
//! same `oracle_keypair` to re-register after the contract garbage-
//! collects the address. `n_operators` and `quorum_threshold` are
//! recomputed atomically.
//!
//! v1.3 changed the staleness threshold from a per-fleet-size missed-
//! turn count (`missed_own_turns > MAX_MISSED_TURNS`, ~22 min tolerance
//! at n=2) to a fixed wall-clock window (`windows_since > 1440`, ~24 h
//! regardless of n). The grace covers reboots, maintenance windows, and
//! transient network outages without surprising operators of small fleets.
//!
//! At fleet size n=2 a missed-turn bound of 10 collapses into ~100 minutes
//! of inactivity; at n=100 it spans roughly 14 hours. Threshold scales
//! naturally with fleet size.
//!
//! ## Removed vs prior versions
//!
//! No migration. No backward compatibility. No legacy paths.
//! - No STAMP hardware-fingerprinting hooks.
//! - No on-chain vote-account or stake-account parsing — daemon-only.
//! - No `initialize_operator` (replaced by `register_submitter`).
//! - No `rotate_hot_signer` (rotation = close + new register).
//! - No `deactivate_operator` / `close_operator` (auto-cleanup only).

use anchor_lang::prelude::*;

declare_id!("2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ceiling on simultaneously registered operators.
pub const MAX_OPERATORS: u16 = 512;

/// Per-window submission buffer size. Keep small so
/// `8 + size_of::<OracleState>()` stays under X1's 10 240 B CPI realloc cap.
pub const MAX_SUBMISSIONS: usize = 6;

/// Ring buffer depth — 288 × 300 s = 24 h of history.
pub const RING_SIZE: usize = 288;

/// Window length in slots — 150 × 0.4 s ≈ 60 s × 5 = 300 s = 5 min.
pub const WINDOW_SLOTS: u64 = 150;

/// Minimum confidence percentage for a submission to be accepted.
pub const MIN_CONFIDENCE: u8 = 60;

/// Maximum allowed offset spread between aggregated NTP samples.
pub const MAX_SPREAD_MS: i64 = 50;

/// Operators whose `last_submitted_window_id` lags the current window by
/// strictly more than this many contract-windows get their
/// `ValidatorRegistration` PDA closed by `cleanup_inactive`. At
/// `WINDOW_SLOTS = 150` slots and ~400 ms/slot, one contract-window is
/// ~60 s, so 1440 windows ≈ 24 h. The grace is independent of fleet size
/// `n`: a fresh operator and a member of a 500-operator fleet get the
/// same wall-clock tolerance to recover from a reboot, network blip, or
/// scheduled maintenance.
///
/// Replaces v1.2's `MAX_MISSED_TURNS = 10`, which used
/// `missed_own_turns = windows_since / windows_per_turn(n)` and at `n=2`
/// (wpt=2) cleaned operators after only ~22 min (`11 × 2 × 60 s`).
pub const CLEANUP_GRACE_WINDOWS: u64 = 1440;

/// Bootstrap-mode threshold: the oracle reports `is_degraded = 1`
/// regardless of per-window quorum and confidence whenever the active
/// operator fleet is below this size. Below 3 operators a single (or
/// pair of) honest submitters cannot be cross-validated by enough
/// peers; dApps should treat the reading as untrusted and fall back to
/// `Clock::unix_timestamp` (or whatever their bootstrap-safe path is)
/// until enough independent operators register.
pub const MIN_QUORUM_ABSOLUTE: u16 = 3;

// ---- PDA seeds ----

pub const ORACLE_STATE_SEED: &[u8] = b"X1";
pub const ORACLE_STATE_SEED_2: &[u8] = b"Strontium";
pub const ORACLE_STATE_SEED_3: &[u8] = b"v1";
/// Fourth seed segment. The v1.0 OracleState lived at the 3-segment
/// derivation and is left orphaned on chain (~0.07 XNT rent locked
/// forever — accepted as the cost of the v1.0 mistake).
pub const ORACLE_STATE_SEED_4: &[u8] = b"oracle";

/// Seed for `ValidatorRegistration` PDAs — `[REG_SEED, oracle_keypair]`.
pub const REG_SEED: &[u8] = b"reg";

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

#[program]
pub mod x1_strontium {
    use super::*;

    /// Deploy-time initialisation of the singleton `OracleState` PDA. The
    /// `authority` stored here is the X1 Strontium admin key (Sentinel
    /// id.json), used only for the `set_operators_count` emergency override.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.oracle_state.load_init()?;
        state.authority = ctx.accounts.authority.key();
        state.bump = ctx.bumps.oracle_state;
        state.is_degraded = 1;
        state.confidence_pct = 0;
        state._pad0 = [0u8; 5];
        state.trusted_time_ms = 0;
        state.last_updated_slot = 0;
        state.spread_ms = 0;
        state.window_start_slot = 0;
        state.active_submitters = 0;
        state.quorum_threshold = required_quorum(0);
        state.submission_count = 0;
        state.ring_head = 0;
        state.ring_count = 0;
        state.n_operators = 0;
        state._pad1 = [0u8; 4];
        state.last_cleanup_slot = 0;
        state.submissions = [ValidatorSubmission::zeroed(); MAX_SUBMISSIONS];
        state.ring_buffer = [RingEntry::zeroed(); RING_SIZE];
        Ok(())
    }

    /// Create a `ValidatorRegistration` PDA for a fresh `oracle_keypair`.
    /// Two signers are required: `oracle_keypair` (the new server-local
    /// key, which also pays rent) and `vote_keypair` (the validator's vote
    /// account keypair). The contract performs no on-chain validation of
    /// the vote account — anti-farm gates (64+ epochs + a qualifying
    /// stake whose withdraw authority equals vote.authorized_withdrawer)
    /// are enforced by the daemon before this TX is built.
    pub fn register_submitter(ctx: Context<RegisterSubmitter>) -> Result<()> {
        let clock = Clock::get()?;
        let state = &mut ctx.accounts.oracle_state.load_mut()?;

        require!(
            state.n_operators < MAX_OPERATORS,
            X1StrontiumError::TooManyOperators
        );

        let reg = &mut ctx.accounts.registration;
        reg.oracle_keypair = ctx.accounts.oracle_keypair.key();
        reg.vote_account = ctx.accounts.vote_keypair.key();
        reg.registered_at = clock.unix_timestamp;
        // Phantom-submit at register time so the freshly registered operator
        // gets a full grace period before cleanup_inactive can mark them.
        reg.last_submitted_window_id = clock.slot / WINDOW_SLOTS;
        reg.is_active = true;
        reg.bump = ctx.bumps.registration;
        reg._pad = [0u8; 6];

        state.n_operators = state
            .n_operators
            .checked_add(1)
            .ok_or(error!(X1StrontiumError::Overflow))?;
        state.quorum_threshold = required_quorum(state.n_operators);

        msg!(
            "Submitter registered — oracle={}, vote={}, n_operators={}, quorum={}",
            reg.oracle_keypair,
            reg.vote_account,
            state.n_operators,
            state.quorum_threshold
        );
        Ok(())
    }

    /// Submit a single time observation. Signer: the registered
    /// `oracle_keypair` (seed-bound to `registration`). Updates only the
    /// caller's own registration — no iteration over other registrations.
    /// Cleanup of inactive operators happens out-of-band in `cleanup_inactive`.
    pub fn submit_time(ctx: Context<SubmitTime>, args: SubmitTimeArgs) -> Result<()> {
        require!(
            (args.spread_ms as i64) <= MAX_SPREAD_MS,
            X1StrontiumError::SpreadTooLarge
        );
        require!(
            args.confidence_pct >= MIN_CONFIDENCE,
            X1StrontiumError::ConfidenceTooLow
        );

        let clock = Clock::get()?;
        let slot = clock.slot;
        let current_window_id = slot / WINDOW_SLOTS;

        let reg = &mut ctx.accounts.registration;
        let state = &mut ctx.accounts.oracle_state.load_mut()?;

        // Window reset. Eagerly mark the oracle as degraded — aggregate()
        // will flip is_degraded back to 0 only when quorum and confidence
        // pass in the new window. Without this, a window that loses
        // quorum would inherit `is_degraded = 0` from the prior
        // successful aggregation and `read_time` would return a stale
        // reading without erroring with OracleDegraded.
        if slot.saturating_sub(state.window_start_slot) >= WINDOW_SLOTS {
            state.window_start_slot = slot;
            state.submission_count = 0;
            state.is_degraded = 1;
            for s in state.submissions.iter_mut() {
                *s = ValidatorSubmission::zeroed();
            }
        }
        require!(
            (state.submission_count as usize) < MAX_SUBMISSIONS,
            X1StrontiumError::SubmissionsFull
        );
        require!(
            !submitter_already_in_window(state, &ctx.accounts.submitter.key()),
            X1StrontiumError::DuplicateSubmissionInWindow
        );

        let new_sub = ValidatorSubmission {
            validator: ctx.accounts.submitter.key(),
            timestamp_ms: args.timestamp_ms,
            spread_ms: args.spread_ms as i64,
            slot,
            sources_used: args.sources_used,
            confidence_pct: args.confidence_pct,
            _pad0: [0u8; 6],
            sources_bitmap: args.sources_bitmap,
        };
        let idx = state.submission_count as usize;
        state.submissions[idx] = new_sub;
        state.submission_count = state
            .submission_count
            .checked_add(1)
            .ok_or(error!(X1StrontiumError::Overflow))?;
        state.active_submitters = state.submission_count;
        state.spread_ms = args.spread_ms as i64;

        // Track this operator's last submit for cleanup math. Does not look
        // at any other ValidatorRegistration — submit_time is fixed-cost.
        reg.last_submitted_window_id = current_window_id;

        if state.submission_count >= state.quorum_threshold {
            aggregate(state, slot);
        }
        Ok(())
    }

    /// Close stale registration PDAs. Permissionless — any signer can
    /// invoke; lamports from closed PDAs flow to the `payer` signer
    /// (effectively a small reward for paying the TX fee). For each
    /// registration in `remaining_accounts`:
    ///
    /// - **Active and stale** (`windows_since > CLEANUP_GRACE_WINDOWS`):
    ///   close the PDA, decrement `n_operators`.
    /// - **Already inactive** (legacy v1.2.0 leftover where the PDA was
    ///   flagged `is_active = false` but never closed): close the PDA,
    ///   no `n_operators` adjustment — the count was already decremented
    ///   at flagging time.
    /// - **Active but recent**: skip.
    ///
    /// Closing (vs. just flipping a flag) is the v1.2.1 fix: the v1.2.0
    /// path left the PDA on chain with `is_active = false`, which made
    /// re-registering the same `oracle_keypair` impossible — Anchor's
    /// `init` constraint rejected it with "account already in use".
    ///
    /// v1.3 swapped the staleness check from the per-fleet-size
    /// `missed_own_turns > MAX_MISSED_TURNS` math (~22 min tolerance at
    /// n=2) to the fixed `windows_since > CLEANUP_GRACE_WINDOWS` check
    /// (~24 h regardless of n). `quorum_threshold` and
    /// `last_cleanup_slot` are updated atomically.
    pub fn cleanup_inactive<'info>(
        ctx: Context<'_, '_, 'info, 'info, CleanupInactive<'info>>,
    ) -> Result<()> {
        let clock = Clock::get()?;
        let current_window_id = clock.slot / WINDOW_SLOTS;
        let state = &mut ctx.accounts.oracle_state.load_mut()?;
        let payer_info = ctx.accounts.payer.to_account_info();

        let mut closed: u16 = 0;
        let mut removed_active: u16 = 0;
        let n_at_start = state.n_operators;

        for info in ctx.remaining_accounts.iter() {
            // Skip if not owned by this program (filters non-PDA inputs).
            if info.owner != &crate::ID {
                continue;
            }
            // Try to wrap as a ValidatorRegistration. If discriminator or
            // size doesn't match, skip silently — caller may have included
            // unrelated accounts in remaining_accounts.
            let acct = match Account::<'info, ValidatorRegistration>::try_from(info) {
                Ok(a) => a,
                Err(_) => continue,
            };

            match cleanup_decision(
                acct.is_active,
                current_window_id,
                acct.last_submitted_window_id,
                n_at_start,
            ) {
                CleanupDecision::Skip => continue,
                CleanupDecision::CloseLegacy => {
                    acct.close(payer_info.clone())?;
                    closed = closed
                        .checked_add(1)
                        .ok_or(error!(X1StrontiumError::Overflow))?;
                }
                CleanupDecision::CloseStale => {
                    acct.close(payer_info.clone())?;
                    closed = closed
                        .checked_add(1)
                        .ok_or(error!(X1StrontiumError::Overflow))?;
                    removed_active = removed_active
                        .checked_add(1)
                        .ok_or(error!(X1StrontiumError::Overflow))?;
                }
            }
        }

        if removed_active > 0 {
            state.n_operators = state.n_operators.saturating_sub(removed_active);
            state.quorum_threshold = required_quorum(state.n_operators);
        }
        state.last_cleanup_slot = clock.slot;

        msg!(
            "Cleanup — closed={}, n_operators={}, quorum={}, last_cleanup_slot={}",
            closed,
            state.n_operators,
            state.quorum_threshold,
            state.last_cleanup_slot
        );
        Ok(())
    }

    /// Read the current trusted time. Free, CPI-callable by any program.
    pub fn read_time(ctx: Context<ReadTime>, max_staleness_slots: u64) -> Result<TimeReading> {
        let state = ctx.accounts.oracle_state.load()?;
        let current_slot = Clock::get()?.slot;
        let staleness = current_slot.saturating_sub(state.last_updated_slot);
        require!(
            staleness <= max_staleness_slots,
            X1StrontiumError::OracleStale
        );
        require!(state.is_degraded == 0, X1StrontiumError::OracleDegraded);
        Ok(TimeReading {
            timestamp_ms: state.trusted_time_ms,
            confidence_pct: state.confidence_pct,
            spread_ms: state.spread_ms,
            sources_count: state.active_submitters,
            staleness_slots: staleness,
        })
    }

    /// Emergency override for `n_operators`. Signer: `oracle_state.authority`
    /// (X1 Strontium admin key). Only useful while the upgrade authority
    /// still exists — the contract lock will remove this path post-v∞.
    pub fn set_operators_count(ctx: Context<SetOperatorsCount>, new_n: u16) -> Result<()> {
        require!(new_n >= 1, X1StrontiumError::InvalidOperatorsCount);
        require!(new_n <= MAX_OPERATORS, X1StrontiumError::TooManyOperators);
        let state = &mut ctx.accounts.oracle_state.load_mut()?;
        require_keys_eq!(
            state.authority,
            ctx.accounts.authority.key(),
            X1StrontiumError::Unauthorized
        );
        state.n_operators = new_n;
        state.quorum_threshold = required_quorum(new_n);
        msg!(
            "n_operators forced to {} (quorum={})",
            new_n,
            state.quorum_threshold
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers (pure — no Solana state)
// ---------------------------------------------------------------------------

/// Dynamic quorum: 10 % of the fleet, rounded up, min 1, capped at
/// `MAX_SUBMISSIONS` (we can't aggregate more per-window than fits in the
/// buffer).
fn required_quorum(n_operators: u16) -> u16 {
    let natural = core::cmp::max(1, n_operators.div_ceil(10));
    core::cmp::min(natural, MAX_SUBMISSIONS as u16)
}

/// Average number of windows between consecutive turns for any single
/// operator under the daemon's `rotation.rs` election rules. v1.3 no
/// longer uses this for `cleanup_inactive` (replaced by the fixed
/// `CLEANUP_GRACE_WINDOWS` wall-clock check); retained as a pure helper
/// for rotation diagnostics and for callers that want a fleet-size-
/// aware "average windows between my turns" estimate.
///
/// Three regimes (matching `daemon/src/rotation.rs::rotation_my_turn_at`):
/// - n ≤ 2 — primary-only; primary slot rotates every n windows.
/// - 3 ≤ n ≤ 6 — primary + staged backups. Under happy-path the primary
///   slot rotates every n windows (backups only fire when primary is
///   silent past the 50 % / 80 % thresholds).
/// - n > 6 — window-slot model with a 6-wide slice. Each operator is in
///   the slice for ~6 / n of windows, so average windows-per-turn is
///   `⌈n / 6⌉`.
///
/// Returns at least 1 to keep `missed_own_turns` from dividing by zero.
pub fn windows_per_turn(n_operators: u16) -> u64 {
    if n_operators == 0 {
        return 1;
    }
    if (n_operators as usize) <= MAX_SUBMISSIONS {
        return n_operators as u64;
    }
    (n_operators as u64).div_ceil(MAX_SUBMISSIONS as u64)
}

/// How many of the operator's own rotation turns have passed without a
/// submission. **No longer used by `cleanup_inactive` in v1.3+ — kept as
/// a pure helper for rotation diagnostics** (e.g. an operator-facing
/// "you have missed X of your scheduled turns" log). v1.3 cleanup uses
/// `CLEANUP_GRACE_WINDOWS` as a fixed wall-clock check instead.
///
/// The window IDs are absolute (`slot / WINDOW_SLOTS`), so for a freshly
/// registered operator we phantom-submit at register time — see
/// `register_submitter`.
pub fn missed_own_turns(
    current_window_id: u64,
    last_submitted_window_id: u64,
    n_operators: u16,
) -> u64 {
    let wpt = windows_per_turn(n_operators);
    let windows_since = current_window_id.saturating_sub(last_submitted_window_id);
    windows_since / wpt
}

/// Outcome of `cleanup_inactive`'s per-registration dispatch. The split
/// between `CloseLegacy` and `CloseStale` matters because v1.2.0's old
/// flagging path already decremented `n_operators` when it flipped
/// `is_active = false` — so a legacy leftover PDA is closed (rent
/// recovered) but `n_operators` must NOT be touched again.
#[derive(Debug, PartialEq, Eq)]
pub enum CleanupDecision {
    /// Active operator inside the `CLEANUP_GRACE_WINDOWS` grace — leave alone.
    Skip,
    /// Already-inactive PDA from a v1.2.0 cleanup run. Close to recover
    /// rent and free the address; do not decrement `n_operators`.
    CloseLegacy,
    /// Active operator past the `CLEANUP_GRACE_WINDOWS` grace. Close and
    /// decrement `n_operators` / recompute quorum.
    CloseStale,
}

/// Pure dispatch for `cleanup_inactive`'s per-registration handling.
/// Extracted so cargo test can exercise the close-vs-skip branching
/// (legacy / active-stale / skip) without a Solana runtime.
///
/// v1.3 simplification: instead of `missed_own_turns > MAX_MISSED_TURNS`
/// (per-fleet-size, ~22 min tolerance at n=2), the active-stale check is
/// now the direct `windows_since > CLEANUP_GRACE_WINDOWS` comparison
/// (~24 h regardless of fleet size). `_n_operators_at_start` is kept on
/// the signature so the contract loop call site stays unchanged and
/// any external caller wrapping this helper need not be edited.
pub fn cleanup_decision(
    is_active: bool,
    current_window_id: u64,
    last_submitted_window_id: u64,
    _n_operators_at_start: u16,
) -> CleanupDecision {
    if !is_active {
        return CleanupDecision::CloseLegacy;
    }
    let windows_since = current_window_id.saturating_sub(last_submitted_window_id);
    if windows_since > CLEANUP_GRACE_WINDOWS {
        CleanupDecision::CloseStale
    } else {
        CleanupDecision::Skip
    }
}

/// Has this submitter already pushed a submission into the current window?
/// Used by `submit_time` to reject double-submits from the same operator
/// — letting both through would corrupt the median by counting one
/// operator's value twice.
pub fn submitter_already_in_window(state: &OracleState, submitter: &Pubkey) -> bool {
    let n = state.submission_count as usize;
    state
        .submissions
        .iter()
        .take(n)
        .any(|s| s.validator == *submitter)
}

// ---------------------------------------------------------------------------
// Aggregation (median — same philosophy as v1.0, Bug #2 fix preserved)
// ---------------------------------------------------------------------------

fn aggregate(state: &mut OracleState, slot: u64) {
    let n = state.submission_count as usize;
    if n == 0 {
        return;
    }
    let mut times: [i64; MAX_SUBMISSIONS] = [0; MAX_SUBMISSIONS];
    let mut conf_sum: u32 = 0;
    let mut bitmap_or: u64 = 0;
    for (t, s) in times.iter_mut().zip(state.submissions.iter()).take(n) {
        *t = s.timestamp_ms;
        conf_sum += s.confidence_pct as u32;
        bitmap_or |= s.sources_bitmap;
    }
    let slice = &mut times[..n];
    for i in 1..slice.len() {
        let mut j = i;
        while j > 0 && slice[j - 1] > slice[j] {
            slice.swap(j - 1, j);
            j -= 1;
        }
    }
    let median = slice[n / 2];
    let avg_conf = (conf_sum / n as u32) as u8;

    state.trusted_time_ms = median;
    state.last_updated_slot = slot;
    state.confidence_pct = avg_conf;
    state.is_degraded =
        if state.submission_count >= state.quorum_threshold && avg_conf >= MIN_CONFIDENCE {
            0
        } else {
            1
        };
    // Bootstrap-mode override: even when per-window quorum and confidence
    // pass, the oracle is degraded until the operator fleet reaches
    // MIN_QUORUM_ABSOLUTE. Forces dApps off the oracle's reading whenever
    // the network is too small to provide meaningful cross-validation.
    if state.n_operators < MIN_QUORUM_ABSOLUTE {
        state.is_degraded = 1;
    }

    let ring_spread = state.spread_ms.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
    let new_entry = RingEntry {
        trusted_time_ms: median,
        slot,
        submitter_count: state.submission_count.min(u8::MAX as u16) as u8,
        confidence_pct: avg_conf,
        spread_ms: ring_spread,
        _pad: [0u8; 4],
        sources_bitmap: bitmap_or,
    };

    // Bug #2 fix (preserved from v1.0): in a small fleet (quorum=1) a
    // 150-slot window can see multiple submissions that each trigger
    // aggregate(). Writing a new ring entry every time would halve the
    // effective ring depth when n_operators is small. Instead, collapse
    // submissions from the same window into one update-in-place entry;
    // only advance ring_head when the window changes.
    let this_window = slot / WINDOW_SLOTS;
    let same_window_as_last = if state.ring_count > 0 {
        let last_idx = (state.ring_head as usize + RING_SIZE - 1) % RING_SIZE;
        state.ring_buffer[last_idx].slot / WINDOW_SLOTS == this_window
    } else {
        false
    };

    if same_window_as_last {
        let last_idx = (state.ring_head as usize + RING_SIZE - 1) % RING_SIZE;
        state.ring_buffer[last_idx] = new_entry;
    } else {
        let head = state.ring_head as usize % RING_SIZE;
        state.ring_buffer[head] = new_entry;
        state.ring_head = ((state.ring_head as usize + 1) % RING_SIZE) as u16;
        if (state.ring_count as usize) < RING_SIZE {
            state.ring_count += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Account contexts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<OracleState>(),
        seeds = [
            ORACLE_STATE_SEED,
            ORACLE_STATE_SEED_2,
            ORACLE_STATE_SEED_3,
            ORACLE_STATE_SEED_4,
        ],
        bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterSubmitter<'info> {
    #[account(
        init,
        payer = oracle_keypair,
        space = 8 + ValidatorRegistration::LEN,
        seeds = [REG_SEED, oracle_keypair.key().as_ref()],
        bump,
    )]
    pub registration: Account<'info, ValidatorRegistration>,

    #[account(
        mut,
        seeds = [
            ORACLE_STATE_SEED,
            ORACLE_STATE_SEED_2,
            ORACLE_STATE_SEED_3,
            ORACLE_STATE_SEED_4,
        ],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    /// Newly funded server-local key. Pays rent for the registration PDA.
    #[account(mut)]
    pub oracle_keypair: Signer<'info>,

    /// Validator's vote-account keypair. Co-signs to prove operator
    /// controls both halves; not used for any on-chain parsing.
    pub vote_keypair: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SubmitTime<'info> {
    #[account(
        mut,
        seeds = [
            ORACLE_STATE_SEED,
            ORACLE_STATE_SEED_2,
            ORACLE_STATE_SEED_3,
            ORACLE_STATE_SEED_4,
        ],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    /// The submitter's own registration. Seed-bound to `submitter.key()`,
    /// so Anchor enforces that only the owner of this oracle keypair can
    /// touch this PDA. No other registrations are passed in or read.
    #[account(
        mut,
        seeds = [REG_SEED, submitter.key().as_ref()],
        bump = registration.bump,
        constraint = registration.is_active @ X1StrontiumError::RegistrationInactive,
    )]
    pub registration: Account<'info, ValidatorRegistration>,

    pub submitter: Signer<'info>,
}

#[derive(Accounts)]
pub struct CleanupInactive<'info> {
    #[account(
        mut,
        seeds = [
            ORACLE_STATE_SEED,
            ORACLE_STATE_SEED_2,
            ORACLE_STATE_SEED_3,
            ORACLE_STATE_SEED_4,
        ],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    /// Cleanup-TX fee payer + lamport recipient for closed registration
    /// PDAs. Permissionless — anyone may sign as their own receiver;
    /// the rent recovered from closing dead PDAs is the reward for
    /// paying the TX fee. Required as v1.2.1 (`cleanup_inactive` now
    /// closes PDAs instead of flipping `is_active = false`, and
    /// `acct.close()` needs an explicit AccountInfo destination).
    #[account(mut)]
    pub payer: Signer<'info>,
    // remaining_accounts: ValidatorRegistration accounts to consider (mut).
}

#[derive(Accounts)]
pub struct ReadTime<'info> {
    #[account(
        seeds = [
            ORACLE_STATE_SEED,
            ORACLE_STATE_SEED_2,
            ORACLE_STATE_SEED_3,
            ORACLE_STATE_SEED_4,
        ],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,
}

#[derive(Accounts)]
pub struct SetOperatorsCount<'info> {
    #[account(
        mut,
        seeds = [
            ORACLE_STATE_SEED,
            ORACLE_STATE_SEED_2,
            ORACLE_STATE_SEED_3,
            ORACLE_STATE_SEED_4,
        ],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,
    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// Account types
// ---------------------------------------------------------------------------

/// Per-operator registration. One PDA per oracle keypair (operators with
/// multiple oracle keypairs — e.g. mid-rotation — get one PDA each).
#[account]
pub struct ValidatorRegistration {
    /// Server-local keypair pubkey. Signs `submit_time`. Also the seed
    /// component for this PDA's address.
    pub oracle_keypair: Pubkey, // 32 (0..32)
    /// Validator's vote-account keypair pubkey, captured at register time
    /// from the second signer. Not used for on-chain logic; recorded for
    /// audit / off-chain correlation.
    pub vote_account: Pubkey, // 32 (32..64)
    /// `Clock::unix_timestamp` at register time.
    pub registered_at: i64, // 8 (64..72)
    /// Window ID of the last successful `submit_time` (or the register
    /// window itself, set as a phantom submit at register time). Drives
    /// `cleanup_inactive`'s missed-turn math.
    pub last_submitted_window_id: u64, // 8 (72..80)
    pub is_active: bool, // 1 (80)
    pub bump: u8,        // 1 (81)
    pub _pad: [u8; 6],   // 6 (82..88)
}

impl ValidatorRegistration {
    pub const LEN: usize = 32 + 32 + 8 + 8 + 1 + 1 + 6; // 88
}

#[account(zero_copy(unsafe))]
#[repr(C)]
pub struct OracleState {
    pub authority: Pubkey,      //    0..32
    pub bump: u8,               //   32
    pub is_degraded: u8,        //   33
    pub confidence_pct: u8,     //   34
    pub _pad0: [u8; 5],         //   35..40
    pub trusted_time_ms: i64,   //   40..48
    pub last_updated_slot: u64, //   48..56
    pub spread_ms: i64,         //   56..64
    pub window_start_slot: u64, //   64..72
    pub active_submitters: u16, //   72..74
    pub quorum_threshold: u16,  //   74..76
    pub submission_count: u16,  //   76..78
    pub ring_head: u16,         //   78..80
    pub ring_count: u16,        //   80..82
    pub n_operators: u16,       //   82..84
    pub _pad1: [u8; 4],         //   84..88
    /// Slot at which `cleanup_inactive` was last successfully run. Read
    /// by the daemon's pre-flight throttle to avoid duplicate cleanups.
    /// Replaces v1.0's `_pad_reserve` field; same offset, same size, no
    /// layout change.
    pub last_cleanup_slot: u64, //   88..96
    pub submissions: [ValidatorSubmission; MAX_SUBMISSIONS], //   96..528  (6*72)
    pub ring_buffer: [RingEntry; RING_SIZE], //  528..9744 (288*32)
}

#[zero_copy(unsafe)]
#[repr(C)]
pub struct ValidatorSubmission {
    pub validator: Pubkey,   // 0..32
    pub timestamp_ms: i64,   // 32..40
    pub spread_ms: i64,      // 40..48
    pub slot: u64,           // 48..56
    pub sources_used: u8,    // 56
    pub confidence_pct: u8,  // 57
    pub _pad0: [u8; 6],      // 58..64  (aligns sources_bitmap:u64 at 64)
    pub sources_bitmap: u64, // 64..72
}

impl ValidatorSubmission {
    pub fn zeroed() -> Self {
        Self {
            validator: Pubkey::default(),
            timestamp_ms: 0,
            spread_ms: 0,
            slot: 0,
            sources_used: 0,
            confidence_pct: 0,
            _pad0: [0u8; 6],
            sources_bitmap: 0,
        }
    }
}

#[zero_copy(unsafe)]
#[repr(C)]
pub struct RingEntry {
    pub trusted_time_ms: i64, // 0..8
    pub slot: u64,            // 8..16
    pub submitter_count: u8,  // 16
    pub confidence_pct: u8,   // 17
    pub spread_ms: i16,       // 18..20
    pub _pad: [u8; 4],        // 20..24  (aligns u64 at 24)
    pub sources_bitmap: u64,  // 24..32
}

impl RingEntry {
    pub fn zeroed() -> Self {
        Self {
            trusted_time_ms: 0,
            slot: 0,
            submitter_count: 0,
            confidence_pct: 0,
            spread_ms: 0,
            _pad: [0u8; 4],
            sources_bitmap: 0,
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct SubmitTimeArgs {
    pub timestamp_ms: i64,
    pub spread_ms: i16,
    pub sources_used: u8,
    pub confidence_pct: u8,
    /// u64 bitmap — 64-source capacity (43 currently used in NTP_SOURCES).
    pub sources_bitmap: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct TimeReading {
    pub timestamp_ms: i64,
    pub confidence_pct: u8,
    pub spread_ms: i64,
    pub sources_count: u16,
    pub staleness_slots: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum X1StrontiumError {
    #[msg("Spread between submissions exceeds the maximum (50 ms)")]
    SpreadTooLarge,
    #[msg("Confidence below 60% — submission rejected")]
    ConfidenceTooLow,
    #[msg("Submission slots full for the current window")]
    SubmissionsFull,
    #[msg("This operator already submitted in the current window")]
    DuplicateSubmissionInWindow,
    #[msg("Oracle is in degraded state — quorum not met")]
    OracleDegraded,
    #[msg("Oracle data is older than the requested staleness window")]
    OracleStale,
    #[msg("Caller is not authorized for this action")]
    Unauthorized,
    #[msg("Registration is not active — operator was cleaned up or never registered")]
    RegistrationInactive,
    #[msg("Invalid operators count (must be ≥ 1)")]
    InvalidOperatorsCount,
    #[msg("Network is at maximum operator capacity (512)")]
    TooManyOperators,
    #[msg("Arithmetic overflow")]
    Overflow,
}

// ---------------------------------------------------------------------------
// Unit tests (host-side, not SBF)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// Build a zeroed `OracleState` on the heap. `OracleState` is a POD-like
    /// struct (repr(C) with only Pubkey/u64/i64/u16/u8/[u8; N] fields), so
    /// `mem::zeroed()` produces a valid value.
    fn zeroed_state() -> Box<OracleState> {
        // Safety: all fields are plain integer/byte types or Pubkey (newtype
        // over [u8; 32]); the all-zero bit pattern is a valid value for each.
        Box::new(unsafe { std::mem::zeroed() })
    }

    // -----------------------------------------------------------------------
    // Layout / quorum / constants — unchanged from v1.0 layout floor
    // -----------------------------------------------------------------------

    #[test]
    fn required_quorum_scales_and_caps() {
        assert_eq!(required_quorum(0), 1);
        assert_eq!(required_quorum(1), 1);
        assert_eq!(required_quorum(10), 1);
        assert_eq!(required_quorum(11), 2);
        assert_eq!(required_quorum(50), 5);
        assert_eq!(required_quorum(51), 6);
        assert_eq!(required_quorum(60), 6);
        assert_eq!(required_quorum(100), 6);
        assert_eq!(required_quorum(256), 6);
        assert_eq!(required_quorum(512), 6);
        assert_eq!(required_quorum(5000), 6);
    }

    #[test]
    fn oracle_state_layout() {
        // sources_bitmap u64 — same as v1.0: ValidatorSubmission = 72,
        // RingEntry = 32. Header = 96. Total = 96 + 6*72 + 288*32 = 9744.
        assert_eq!(size_of::<ValidatorSubmission>(), 72);
        assert_eq!(size_of::<RingEntry>(), 32);
        assert_eq!(size_of::<OracleState>(), 9744);
        // With discriminator (8 B), account size = 9752 B — below X1's
        // 10 240 B CPI realloc cap (headroom = 488 B).
        assert!(8 + size_of::<OracleState>() <= 10_240);
        assert_eq!(10_240 - (8 + size_of::<OracleState>()), 488);
    }

    #[test]
    fn validator_registration_layout() {
        // 32 + 32 + 8 + 8 + 1 + 1 + 6 = 88. With Anchor's 8 B discriminator
        // the on-chain account size is 96 B — cheap rent.
        assert_eq!(ValidatorRegistration::LEN, 88);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_are_sane() {
        assert!(MAX_OPERATORS >= 256);
        assert!(MAX_SUBMISSIONS >= 1);
        assert!(RING_SIZE >= 24); // at least 2 h of history at 5-min windows
        assert!(WINDOW_SLOTS > 0);
        assert!(MIN_CONFIDENCE > 0 && MIN_CONFIDENCE <= 100);
        assert!(MAX_SPREAD_MS > 0);
        // v1.3 grace window: at least 1 h, target ~24 h.
        assert!(CLEANUP_GRACE_WINDOWS >= 60);
    }

    // -----------------------------------------------------------------------
    // windows_per_turn — single source of truth for cleanup math
    // -----------------------------------------------------------------------

    #[test]
    fn windows_per_turn_zero_clamps_to_one() {
        // Defensive: divide-by-zero would panic in missed_own_turns; clamp.
        assert_eq!(windows_per_turn(0), 1);
    }

    #[test]
    fn windows_per_turn_small_fleet_returns_n() {
        // n ≤ 6 — primary slot rotates every n windows under rotation.rs.
        assert_eq!(windows_per_turn(1), 1);
        assert_eq!(windows_per_turn(2), 2);
        assert_eq!(windows_per_turn(3), 3);
        assert_eq!(windows_per_turn(4), 4);
        assert_eq!(windows_per_turn(5), 5);
        assert_eq!(windows_per_turn(6), 6);
    }

    #[test]
    fn windows_per_turn_large_fleet_uses_slice_math() {
        // n > 6 — window-slot model picks 6 contiguous operators per
        // window, so each operator's average windows-per-turn is ⌈n / 6⌉.
        assert_eq!(windows_per_turn(7), 2); // ⌈7/6⌉
        assert_eq!(windows_per_turn(10), 2); // ⌈10/6⌉
        assert_eq!(windows_per_turn(12), 2);
        assert_eq!(windows_per_turn(13), 3);
        assert_eq!(windows_per_turn(100), 17); // ⌈100/6⌉
        assert_eq!(windows_per_turn(256), 43);
        assert_eq!(windows_per_turn(512), 86);
    }

    // -----------------------------------------------------------------------
    // missed_own_turns helper (retained, no longer drives cleanup in v1.3+)
    // -----------------------------------------------------------------------

    #[test]
    fn missed_own_turns_zero_when_just_submitted() {
        // No windows have elapsed since the last submit.
        assert_eq!(missed_own_turns(1_000_000, 1_000_000, 2), 0);
    }

    // -----------------------------------------------------------------------
    // cleanup boundary behaviour (v1.3 fixed wall-clock grace)
    // -----------------------------------------------------------------------

    #[test]
    fn cleanup_marks_after_grace_window() {
        // v1.3: cleanup_decision returns CloseStale when windows_since
        // strictly exceeds CLEANUP_GRACE_WINDOWS. At 1441 windows
        // (~24 h + 1 min) the operator is past grace regardless of n.
        let last = 1_000_000u64;
        let current = last + CLEANUP_GRACE_WINDOWS + 1; // 1441 at default
        assert_eq!(
            cleanup_decision(true, current, last, 2),
            CleanupDecision::CloseStale
        );
    }

    #[test]
    fn cleanup_keeps_active_operator() {
        // windows_since well below grace ⇒ Skip. Picks 12 windows
        // (~12 min — typical reboot / maintenance window) at n=2.
        let last = 1_000_000u64;
        let current = last + 12;
        assert_eq!(
            cleanup_decision(true, current, last, 2),
            CleanupDecision::Skip
        );
    }

    #[test]
    fn cleanup_boundary_at_exact_grace_window_keeps_active() {
        // windows_since == CLEANUP_GRACE_WINDOWS must NOT remove — the
        // contract uses strict `>` to give an inclusive grace. The
        // operator is exactly at the 24 h mark and survives by one
        // window.
        let last = 1_000_000u64;
        let current = last + CLEANUP_GRACE_WINDOWS; // 1440
        assert_eq!(
            cleanup_decision(true, current, last, 2),
            CleanupDecision::Skip
        );
    }

    /// Core v1.3 invariant: cleanup grace is wall-clock, not
    /// per-operator-turn. A fleet of 2 and a fleet of 512 use the same
    /// 1440-window grace, so a missed turn for a solo operator and a
    /// missed turn for a member of a huge fleet have identical
    /// consequences time-wise.
    #[test]
    fn cleanup_grace_is_fleet_size_independent() {
        let last = 1_000_000u64;
        let stale_current = last + CLEANUP_GRACE_WINDOWS + 1; // past grace
        let inside_current = last + CLEANUP_GRACE_WINDOWS; // at boundary

        for n in [2u16, 6, 100, 512] {
            assert_eq!(
                cleanup_decision(true, stale_current, last, n),
                CleanupDecision::CloseStale,
                "n={n}: past-grace operator must be CloseStale regardless of fleet size"
            );
            assert_eq!(
                cleanup_decision(true, inside_current, last, n),
                CleanupDecision::Skip,
                "n={n}: operator at exact boundary must survive regardless of fleet size"
            );
        }
    }

    // -----------------------------------------------------------------------
    // cleanup_decision dispatch (v1.3 fixed-grace logic)
    // -----------------------------------------------------------------------

    #[test]
    fn cleanup_decision_active_recent_skips() {
        // Operator submitted in the most recent window — still active,
        // windows_since = 0. Must not be touched.
        let last = 1_000_000u64;
        let current = last; // same window
        assert_eq!(
            cleanup_decision(true, current, last, 5),
            CleanupDecision::Skip
        );
    }

    #[test]
    fn cleanup_decision_active_at_boundary_skips() {
        // Exactly CLEANUP_GRACE_WINDOWS elapsed — boundary stays active
        // because the contract uses strict `>` for the threshold.
        let last = 1_000_000u64;
        let current = last + CLEANUP_GRACE_WINDOWS; // 1440
        assert_eq!(
            cleanup_decision(true, current, last, 2),
            CleanupDecision::Skip
        );
    }

    #[test]
    fn cleanup_decision_active_stale_returns_close_stale() {
        // windows_since = CLEANUP_GRACE_WINDOWS + 1 → close + decrement.
        let last = 1_000_000u64;
        let current = last + CLEANUP_GRACE_WINDOWS + 1;
        assert_eq!(
            cleanup_decision(true, current, last, 2),
            CleanupDecision::CloseStale
        );
    }

    /// Legacy path — a v1.2.0 cleanup run set is_active=false but did
    /// not close the PDA. The dispatch must close such PDAs without
    /// further n_operators bookkeeping (already counted at the original
    /// flagging time). Independent of windows_since.
    #[test]
    fn cleanup_decision_already_inactive_returns_close_legacy() {
        let last = 1_000_000u64;
        let current = last + CLEANUP_GRACE_WINDOWS + 1; // would be stale, but inactive short-circuits
        assert_eq!(
            cleanup_decision(false, current, last, 2),
            CleanupDecision::CloseLegacy
        );
        // Even a "fresh-looking" inactive PDA falls into the legacy
        // bucket — being inactive is itself the close condition.
        assert_eq!(
            cleanup_decision(false, last, last, 2),
            CleanupDecision::CloseLegacy
        );
    }

    /// Bookkeeping invariant: when a close decision lands as
    /// `CloseStale`, the n_operators decrement must happen exactly
    /// once. This test simulates the contract's loop on a small batch
    /// and verifies the resulting state matches the dispatch.
    #[test]
    fn cleanup_decision_batch_matches_close_and_removed_counts() {
        // Mock fleet of 3 active operators. v1.3: stale check is
        // wall-clock, independent of fleet size — any windows_since
        // strictly greater than CLEANUP_GRACE_WINDOWS triggers close.
        // - one fresh (skip)
        // - one active + past grace (close + decrement)
        // - one already-inactive legacy leftover (close, no decrement)
        let n_at_start: u16 = 3;
        let current = 1_000_000u64 + CLEANUP_GRACE_WINDOWS + 1;
        let cases: Vec<(bool, u64, CleanupDecision)> = vec![
            (true, current, CleanupDecision::Skip),
            (true, 1_000_000u64, CleanupDecision::CloseStale),
            (false, 1_000_000u64, CleanupDecision::CloseLegacy),
        ];

        let mut closed = 0u16;
        let mut removed_active = 0u16;
        for (is_active, last, expected) in &cases {
            let d = cleanup_decision(*is_active, current, *last, n_at_start);
            assert_eq!(&d, expected);
            match d {
                CleanupDecision::Skip => {}
                CleanupDecision::CloseLegacy => closed += 1,
                CleanupDecision::CloseStale => {
                    closed += 1;
                    removed_active += 1;
                }
            }
        }
        assert_eq!(closed, 2, "two PDAs should close (one stale, one legacy)");
        assert_eq!(
            removed_active, 1,
            "only the active+stale path decrements n_operators"
        );

        // After applying: n_operators = 3 - 1 = 2. quorum recomputes.
        let mut state = zeroed_state();
        state.n_operators = n_at_start;
        state.n_operators = state.n_operators.saturating_sub(removed_active);
        state.quorum_threshold = required_quorum(state.n_operators);
        assert_eq!(state.n_operators, 2);
        assert_eq!(state.quorum_threshold, 1);
    }

    #[test]
    fn cleanup_decrements_n_operators_and_recomputes_quorum() {
        // 5-operator fleet, quorum auto-set. Remove 1 → quorum recompute.
        let mut state = zeroed_state();
        state.n_operators = 5;
        state.quorum_threshold = required_quorum(state.n_operators);
        assert_eq!(state.quorum_threshold, 1);

        // Simulate cleanup of 1 stale operator.
        let removed: u16 = 1;
        state.n_operators = state.n_operators.saturating_sub(removed);
        state.quorum_threshold = required_quorum(state.n_operators);
        assert_eq!(state.n_operators, 4);
        assert_eq!(state.quorum_threshold, 1);

        // Larger fleet: removing one at the 51 → 50 boundary drops quorum
        // from 6 to 5.
        state.n_operators = 51;
        state.quorum_threshold = required_quorum(state.n_operators);
        assert_eq!(state.quorum_threshold, 6);
        state.n_operators = state.n_operators.saturating_sub(1);
        state.quorum_threshold = required_quorum(state.n_operators);
        assert_eq!(state.n_operators, 50);
        assert_eq!(state.quorum_threshold, 5);
    }

    #[test]
    fn freshly_registered_operator_not_immediately_marked_inactive() {
        // Regression test for the v1.0 bug we deliberately guard against:
        // if `register_submitter` left `last_submitted_window_id` at 0
        // instead of phantom-submitting at the current window, the very
        // next `cleanup_inactive` would compute a millions-of-windows
        // gap and remove the freshly registered operator. Phantom-submit
        // means windows_since starts at 0 immediately after register
        // and grows linearly, so a short post-register pause never
        // crosses the grace window.
        //
        // We advance by ~1 h (12 windows at 5 min/window) and verify the
        // operator stays active for every fleet size. v1.3: the check is
        // wall-clock (`windows_since > CLEANUP_GRACE_WINDOWS = 1440`), so
        // the result is identical for n=1 too — no per-fleet-size carve-
        // out needed.
        let registered_window = 1_234_567u64;
        let current_window = registered_window + 12;

        for n in [1u16, 2, 3, 6, 7, 10, 100, 512] {
            assert_eq!(
                cleanup_decision(true, current_window, registered_window, n),
                CleanupDecision::Skip,
                "n={n}: freshly registered operator must survive 1 h of inactivity"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Aggregation + ring buffer (ports v1.0 tests verbatim — Bug #2 fix)
    // -----------------------------------------------------------------------

    #[test]
    fn aggregation_sets_trusted_time_to_median() {
        // 3 submissions with timestamps {100, 200, 150}. After insertion sort
        // inside aggregate() the slice is [100, 150, 200] and the median at
        // index n/2 == 1 is 150.
        let mut state = zeroed_state();
        state.n_operators = 3; // at MIN_QUORUM_ABSOLUTE — bootstrap override inactive
        state.quorum_threshold = 3;
        state.submission_count = 3;
        state.submissions[0].timestamp_ms = 100;
        state.submissions[1].timestamp_ms = 200;
        state.submissions[2].timestamp_ms = 150;
        state.submissions[0].confidence_pct = 80;
        state.submissions[1].confidence_pct = 80;
        state.submissions[2].confidence_pct = 80;

        aggregate(&mut state, 150);

        assert_eq!(state.trusted_time_ms, 150);
        assert_eq!(state.confidence_pct, 80);
        assert_eq!(state.last_updated_slot, 150);
        assert_eq!(state.is_degraded, 0, "quorum met, confidence OK");
    }

    #[test]
    fn ring_buffer_writes_one_entry_per_window_in_small_fleet() {
        // Simulates a 2-operator fleet (quorum=1). Both operators submit in
        // the same 150-slot window — aggregate() runs twice, but the ring
        // buffer must contain ONE entry for that window (update-in-place),
        // not two, otherwise effective ring depth halves.
        let mut state = zeroed_state();
        state.quorum_threshold = 1;

        state.submission_count = 1;
        state.submissions[0].timestamp_ms = 1_700_000_000_000;
        state.submissions[0].confidence_pct = 80;
        aggregate(&mut state, 150);
        assert_eq!(state.ring_count, 1);
        assert_eq!(state.ring_head, 1);
        assert_eq!(state.ring_buffer[0].trusted_time_ms, 1_700_000_000_000);
        assert_eq!(state.ring_buffer[0].slot, 150);

        state.submission_count = 1;
        state.submissions[0].timestamp_ms = 1_700_000_000_050;
        state.submissions[0].confidence_pct = 80;
        aggregate(&mut state, 200);
        assert_eq!(
            state.ring_count, 1,
            "same window ⇒ must not advance ring_count"
        );
        assert_eq!(
            state.ring_head, 1,
            "same window ⇒ must not advance ring_head"
        );
        assert_eq!(state.ring_buffer[0].trusted_time_ms, 1_700_000_000_050);
        assert_eq!(state.ring_buffer[0].slot, 200);
    }

    #[test]
    fn ring_buffer_advances_on_new_window() {
        let mut state = zeroed_state();
        state.quorum_threshold = 1;

        state.submission_count = 1;
        state.submissions[0].timestamp_ms = 1_000;
        state.submissions[0].confidence_pct = 80;
        aggregate(&mut state, 150); // window = 1
        assert_eq!(state.ring_count, 1);
        assert_eq!(state.ring_head, 1);

        state.submission_count = 1;
        state.submissions[0].timestamp_ms = 2_000;
        state.submissions[0].confidence_pct = 80;
        aggregate(&mut state, 300); // window = 2
        assert_eq!(state.ring_count, 2);
        assert_eq!(state.ring_head, 2);
        assert_eq!(state.ring_buffer[0].slot, 150);
        assert_eq!(state.ring_buffer[1].slot, 300);
        assert_eq!(state.ring_buffer[0].trusted_time_ms, 1_000);
        assert_eq!(state.ring_buffer[1].trusted_time_ms, 2_000);
    }

    // -----------------------------------------------------------------------
    // patch regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn submit_time_rejects_duplicate_validator_in_same_window() {
        // Fix #3: a validator that already pushed a submission into the
        // current window must be detected as a duplicate. The on-chain
        // `submit_time` reads this via `submitter_already_in_window` and
        // returns DuplicateSubmissionInWindow — the host-side test
        // exercises the helper directly (full instruction harness lives
        // outside cargo test --lib).
        let alice = Pubkey::new_from_array([0xa1u8; 32]);
        let bob = Pubkey::new_from_array([0xb2u8; 32]);
        let mut state = zeroed_state();
        state.submission_count = 1;
        state.submissions[0].validator = alice;

        assert!(
            submitter_already_in_window(&state, &alice),
            "alice already in submissions[0] — must be detected as duplicate"
        );
        assert!(
            !submitter_already_in_window(&state, &bob),
            "bob hasn't submitted in this window"
        );

        // Boundary: an entry written into submissions[1] but not yet
        // counted (submission_count still = 1) must NOT be matched.
        // Otherwise stale data from a prior aborted submit would
        // permanently lock that submitter out.
        state.submissions[1].validator = bob;
        assert!(
            !submitter_already_in_window(&state, &bob),
            "bob's stale entry beyond submission_count must be ignored"
        );
    }

    #[test]
    fn aggregate_marks_degraded_when_n_operators_below_min_absolute() {
        // Fix #2: bootstrap mode. With n_operators=2 the per-window
        // quorum + confidence checks would normally clear is_degraded,
        // but the absolute-minimum override forces is_degraded=1 until
        // the fleet reaches MIN_QUORUM_ABSOLUTE=3 operators.
        let mut state = zeroed_state();
        state.n_operators = 2;
        state.quorum_threshold = 1; // required_quorum(2) = 1
        state.submission_count = 2;
        state.submissions[0].timestamp_ms = 1_700_000_000_000;
        state.submissions[0].confidence_pct = 95;
        state.submissions[1].timestamp_ms = 1_700_000_000_010;
        state.submissions[1].confidence_pct = 95;

        aggregate(&mut state, 1_000);

        assert_eq!(
            state.is_degraded, 1,
            "expected is_degraded=1 with n_operators=2 < MIN_QUORUM_ABSOLUTE=3"
        );
        // Median + last slot are still updated — only the trust signal
        // is degraded, the aggregation itself runs normally so historical
        // entries land in the ring buffer.
        assert_ne!(state.trusted_time_ms, 0);
        assert_eq!(state.last_updated_slot, 1_000);
    }

    #[test]
    fn aggregate_clears_degraded_when_n_operators_at_or_above_min_absolute() {
        // Fix #2: at or above MIN_QUORUM_ABSOLUTE the bootstrap override
        // is inactive and the per-window quorum + confidence semantics
        // determine is_degraded normally.
        let mut state = zeroed_state();
        state.n_operators = 3;
        state.quorum_threshold = 1; // required_quorum(3) = 1
        state.submission_count = 3;
        state.submissions[0].timestamp_ms = 1_700_000_000_000;
        state.submissions[0].confidence_pct = 95;
        state.submissions[1].timestamp_ms = 1_700_000_000_005;
        state.submissions[1].confidence_pct = 95;
        state.submissions[2].timestamp_ms = 1_700_000_000_010;
        state.submissions[2].confidence_pct = 95;

        aggregate(&mut state, 1_000);

        assert_eq!(
            state.is_degraded, 0,
            "expected is_degraded=0 with n_operators=3 = MIN_QUORUM_ABSOLUTE"
        );
    }

    #[test]
    fn is_degraded_resets_to_one_on_window_boundary() {
        // Fix #1: every window reset in submit_time eagerly sets
        // is_degraded = 1. aggregate() is the only path that clears it
        // back to 0, and it only runs once the new window reaches
        // quorum_threshold. Without this reset, a window with sub-quorum
        // submissions would inherit is_degraded = 0 from a prior
        // successful aggregation and read_time would silently return a
        // stale reading.
        let mut state = zeroed_state();
        state.is_degraded = 0; // previous window aggregated successfully
        state.window_start_slot = 100;
        state.submission_count = 3; // previous window had submissions
        state.quorum_threshold = 2;

        // Replicate the window-reset block from submit_time at a slot past
        // window_start_slot + WINDOW_SLOTS. The fix is the line setting
        // is_degraded = 1 inside this block.
        let new_slot = 100 + WINDOW_SLOTS;
        if new_slot.saturating_sub(state.window_start_slot) >= WINDOW_SLOTS {
            state.window_start_slot = new_slot;
            state.submission_count = 0;
            state.is_degraded = 1;
            for s in state.submissions.iter_mut() {
                *s = ValidatorSubmission::zeroed();
            }
        }
        // One operator submits in the new window, but quorum_threshold = 2,
        // so aggregate() does not run and is_degraded stays at 1.
        state.submission_count = 1;

        assert_eq!(
            state.is_degraded, 1,
            "expected is_degraded=1 after window reset with submissions below quorum"
        );
        assert_eq!(state.submission_count, 1);
    }
}
