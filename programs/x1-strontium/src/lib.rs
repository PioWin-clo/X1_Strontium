//! # X1 Strontium v1.0
//!
//! Decentralised atomic-time oracle for the X1 blockchain. v1.0 is a clean
//! re-release (new Program ID, new seeds `["X1", "Strontium", "v1"]`) that
//! removes the v0.5 STAMP hardware-fingerprinting feature and fixes two
//! bugs described in the project README (self-stake threshold alignment
//! between daemon and contract, and ring-buffer update-in-window).
//!
//! ## Authorisation model
//!
//! Every operator has two keys with sharply different operational roles:
//!
//! - **`authority` (Ledger)** — the cold key that is the validator vote
//!   account's `authorized_withdrawer`. Used only for rare admin ops:
//!   `initialize_operator`, `rotate_hot_signer`, `deactivate_operator`,
//!   `close_operator`. Lives in a drawer / safe; funded with ~5–10 XNT for
//!   occasional fees.
//!
//! - **`hot_signer` (server-local keypair)** — the hot key that signs
//!   `submit_time` every ~5 minutes. Freshly generated per node; rotatable.
//!
//! The on-chain proof of operator ownership over a validator is the
//! identity `authority == vote_account.authorized_withdrawer`. There is no
//! separate "node identity" signer — the withdrawer role is higher-privilege
//! and subsumes any identity claim.
//!
//! ## Gates checked at `initialize_operator`
//!
//! 1. Vote account is real (owned by the vote program, `data.len() >= 1000`).
//! 2. `authorized_withdrawer == authority.key()` — operator controls the
//!    validator. This is the single most important check.
//! 3. Validator has been producing — `epoch_credits` has exactly 64 entries
//!    (= Solana's `MAX_EPOCH_CREDITS_HISTORY`), no gaps, no more than 6
//!    epochs below `MIN_CREDITS_PER_EPOCH`, and total credits across all 64
//!    epochs ≥ `MIN_TOTAL_CREDITS_WINDOW`.
//! 4. Self-stake via `remaining_accounts`: sum of stake accounts delegated
//!    to this vote with `withdrawer == authority`, active ≥ 2 epochs, not
//!    deactivating — must be ≥ 128 XNT.
//!
//! ## Gates checked at `submit_time`
//!
//! - Hot signer matches the registered one (constraint in derive).
//! - Operator is active (constraint).
//! - Liveness: vote account size ≥ 1000 B.
//! - Every ~24 h (`STAKE_RECHECK_INTERVAL_SLOTS`), self-stake is rechecked
//!   using `remaining_accounts`; falling below 128 XNT rejects the TX.
//! - Epoch-credits is **not** rechecked in `submit_time` (cost + complexity
//!   trade-off; daemon's liveness alerts cover ongoing vote quality).
//!
//! ## Removed vs prior versions
//!
//! No migration. No backward compatibility. No legacy paths.
//! - No `register_submitter` (folded into `initialize_operator`).
//! - No `verify_validator_health` (daemon alerts replace it).
//! - No `deregister_submitter` (replaced by `deactivate_operator`).
//! - No `close_registration` (replaced by `close_operator`).
//! - No `force_close_legacy_registration` — nothing to salvage.
//! - No STAMP hardware-fingerprinting hooks anywhere.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{stake, vote};

declare_id!("2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Operator must commit ≥ 128 XNT of self-stake (withdrawer == Ledger).
pub const MIN_SELF_STAKE_LAMPORTS: u64 = 128_000_000_000;

/// Stake must be active for ≥ 2 epochs before it counts as self-stake.
pub const MIN_STAKE_AGE_EPOCHS: u64 = 2;

/// Exact length expected in `VoteState.epoch_credits` (= Solana's
/// `MAX_EPOCH_CREDITS_HISTORY`). Validators younger than 64 epochs are
/// rejected with `InsufficientEpochHistory`.
pub const MIN_EPOCH_HISTORY: u64 = 64;

/// Any single epoch contributing fewer than this many credits counts as a
/// "bad epoch". Calibrated at ~58 % of the X1 TVC maximum (16 credits × 216
/// 000 slots = 3 456 000 credits/epoch).
pub const MIN_CREDITS_PER_EPOCH: u64 = 2_000_000;

/// Tolerance — at most this many of the 64 epochs may be below
/// `MIN_CREDITS_PER_EPOCH`. Absorbs occasional load tests / short outages.
pub const MAX_BAD_EPOCHS_IN_WINDOW: u64 = 6;

/// Aggregate floor across the 64-epoch window. Detects chronically
/// underperforming validators even when no single epoch is egregiously bad.
pub const MIN_TOTAL_CREDITS_WINDOW: u64 = 150_000_000;

/// Ceiling on simultaneously registered operators.
pub const MAX_OPERATORS: u16 = 512;

/// How often (in slots) `submit_time` must re-verify self-stake. ~24 h at
/// 400 ms/slot.
pub const STAKE_RECHECK_INTERVAL_SLOTS: u64 = 216_000;

// ---- Submission / aggregation ----

/// Size of the per-window submission buffer. Keep small so
/// `8 + size_of::<OracleState>()` stays under X1's 10 240 B CPI realloc cap.
pub const MAX_SUBMISSIONS: usize = 6;

/// Ring buffer depth — 288 × 300 s = 24 h of history.
pub const RING_SIZE: usize = 288;

pub const WINDOW_SLOTS: u64 = 150;
pub const MIN_CONFIDENCE: u8 = 60;
pub const MAX_SPREAD_MS: i64 = 50;

/// Cheap liveness heuristic at `submit_time`: vote accounts that have never
/// voted are ~60 B; actively voting ones are 3000 B+.
pub const MIN_VOTE_ACCOUNT_SIZE: usize = 1000;

// ---- PDA seeds ----

pub const ORACLE_STATE_SEED: &[u8] = b"X1";
pub const ORACLE_STATE_SEED_2: &[u8] = b"Strontium";
pub const ORACLE_STATE_SEED_3: &[u8] = b"v1";
pub const OPERATOR_SEED: &[u8] = b"operator";

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

#[program]
pub mod x1_strontium {
    use super::*;

    /// Deploy-time initialisation of the singleton `OracleState` PDA. The
    /// `authority` stored here is the X1 Strontium admin key, unrelated to
    /// any individual operator — used only for the `set_operators_count`
    /// emergency override.
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
        state._pad_reserve = [0u8; 8];
        state.submissions = [ValidatorSubmission::zeroed(); MAX_SUBMISSIONS];
        state.ring_buffer = [RingEntry::zeroed(); RING_SIZE];
        Ok(())
    }

    /// Create an `OperatorPDA` after enforcing all four gates:
    /// (1) authority = vote.authorized_withdrawer,
    /// (2) vote account size ≥ 1000 B (has voted),
    /// (3) 64-epoch-credit window with bad-epoch + total-credit floors,
    /// (4) ≥ 128 XNT self-stake with withdrawer = authority.
    ///
    /// Signer: `authority` (Ledger), also fee-payer and rent-payer.
    pub fn initialize_operator(ctx: Context<InitializeOperator>, hot_signer: Pubkey) -> Result<()> {
        let clock = Clock::get()?;
        let state = &mut ctx.accounts.oracle_state.load_mut()?;

        // Cap check before the expensive parsing work.
        require!(
            state.n_operators < MAX_OPERATORS,
            X1StrontiumError::TooManyOperators
        );

        // Pre-read liveness length check — cheap, catches empty / fake vote
        // accounts immediately.
        {
            let vote_data = ctx.accounts.vote_account.try_borrow_data()?;
            require!(
                vote_data.len() >= MIN_VOTE_ACCOUNT_SIZE,
                X1StrontiumError::ValidatorNeverVoted
            );
        }

        // Parse + validate vote state. Returns node_pubkey +
        // authorized_withdrawer *only if* the epoch-credits window passes.
        let vote_header = {
            let vote_data = ctx.accounts.vote_account.try_borrow_data()?;
            parse_and_validate_vote(&vote_data)?
        };

        // Proof of operator control: Ledger is the cold withdrawer.
        require_keys_eq!(
            vote_header.authorized_withdrawer,
            ctx.accounts.authority.key(),
            X1StrontiumError::InvalidAuthorizedWithdrawer
        );

        // Self-stake proof (remaining_accounts = stake accounts).
        let total_self_stake = sum_qualifying_self_stake(
            ctx.remaining_accounts,
            &ctx.accounts.vote_account.key(),
            &ctx.accounts.authority.key(),
            clock.epoch,
        )?;
        require!(
            total_self_stake >= MIN_SELF_STAKE_LAMPORTS,
            X1StrontiumError::InsufficientSelfStake
        );

        // Write OperatorPDA.
        let op = &mut ctx.accounts.operator_pda;
        op.authority = ctx.accounts.authority.key();
        op.hot_signer = hot_signer;
        op.vote_account = ctx.accounts.vote_account.key();
        op.validator_identity = vote_header.node_pubkey;
        op.registered_at = clock.unix_timestamp;
        op.last_stake_check_slot = clock.slot;
        op.self_stake_amount = total_self_stake;
        op.active = true;
        op.bump = ctx.bumps.operator_pda;
        op._pad = [0u8; 6];

        // Auto-scale operators count + recompute quorum.
        state.n_operators = state
            .n_operators
            .checked_add(1)
            .ok_or(error!(X1StrontiumError::Overflow))?;
        state.quorum_threshold = required_quorum(state.n_operators);

        msg!(
            "Operator initialised — self-stake {} XNT, n_operators={}, quorum={}",
            total_self_stake / 1_000_000_000,
            state.n_operators,
            state.quorum_threshold
        );
        Ok(())
    }

    /// Hot-signer-driven submission. Signer: `hot_signer`. Occasional 24 h
    /// recheck reuses `remaining_accounts` for self-stake re-verification.
    pub fn submit_time(ctx: Context<SubmitTime>, args: SubmitTimeArgs) -> Result<()> {
        require!(
            (args.spread_ms as i64) <= MAX_SPREAD_MS,
            X1StrontiumError::SpreadTooLarge
        );
        require!(
            args.confidence_pct >= MIN_CONFIDENCE,
            X1StrontiumError::ConfidenceTooLow
        );

        // Cheap liveness heuristic.
        {
            let vote_data = ctx.accounts.vote_account.try_borrow_data()?;
            require!(
                vote_data.len() >= MIN_VOTE_ACCOUNT_SIZE,
                X1StrontiumError::ValidatorNeverVoted
            );
        }

        let clock = Clock::get()?;
        let op = &mut ctx.accounts.operator_pda;

        // Daily self-stake recheck gate. Deliberately does NOT re-validate
        // epoch_credits — that check is only at init, per spec.
        let slots_since_check = clock.slot.saturating_sub(op.last_stake_check_slot);
        if slots_since_check > STAKE_RECHECK_INTERVAL_SLOTS {
            require!(
                !ctx.remaining_accounts.is_empty(),
                X1StrontiumError::StakeRecheckRequired
            );
            let total = sum_qualifying_self_stake(
                ctx.remaining_accounts,
                &op.vote_account,
                &op.authority,
                clock.epoch,
            )?;
            require!(
                total >= MIN_SELF_STAKE_LAMPORTS,
                X1StrontiumError::InsufficientSelfStakeAtRecheck
            );
            op.self_stake_amount = total;
            op.last_stake_check_slot = clock.slot;
            msg!(
                "Daily recheck OK — self-stake {} XNT",
                total / 1_000_000_000
            );
        }

        let slot = clock.slot;
        let state = &mut ctx.accounts.oracle_state.load_mut()?;

        // Window reset.
        if slot.saturating_sub(state.window_start_slot) >= WINDOW_SLOTS {
            state.window_start_slot = slot;
            state.submission_count = 0;
            for s in state.submissions.iter_mut() {
                *s = ValidatorSubmission::zeroed();
            }
        }
        require!(
            (state.submission_count as usize) < MAX_SUBMISSIONS,
            X1StrontiumError::SubmissionsFull
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

        if state.submission_count >= state.quorum_threshold {
            aggregate(state, slot);
        }
        Ok(())
    }

    /// Swap the hot signer tied to this operator (e.g. after a server
    /// compromise). Signer: `authority` (Ledger). Does NOT retrigger gates.
    pub fn rotate_hot_signer(ctx: Context<RotateHotSigner>, new_hot_signer: Pubkey) -> Result<()> {
        ctx.accounts.operator_pda.hot_signer = new_hot_signer;
        msg!("Hot signer rotated to {}", new_hot_signer);
        Ok(())
    }

    /// Suspend the operator without closing the PDA (history preserved).
    /// Signer: `authority` (Ledger).
    pub fn deactivate_operator(ctx: Context<DeactivateOperator>) -> Result<()> {
        let op = &mut ctx.accounts.operator_pda;
        if op.active {
            let state = &mut ctx.accounts.oracle_state.load_mut()?;
            state.n_operators = state.n_operators.saturating_sub(1);
            state.quorum_threshold = required_quorum(state.n_operators);
        }
        op.active = false;
        msg!("Operator deactivated");
        Ok(())
    }

    /// Close the `OperatorPDA`, refunding rent to `authority`. Signer:
    /// `authority` (Ledger). Auto-decrements `n_operators` if still active.
    pub fn close_operator(ctx: Context<CloseOperator>) -> Result<()> {
        if ctx.accounts.operator_pda.active {
            let state = &mut ctx.accounts.oracle_state.load_mut()?;
            state.n_operators = state.n_operators.saturating_sub(1);
            state.quorum_threshold = required_quorum(state.n_operators);
        }
        Ok(())
    }

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
    /// (X1 Strontium admin key).
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
// Helpers
// ---------------------------------------------------------------------------

/// Dynamic quorum: 10 % of the fleet, rounded up, min 1, capped at
/// `MAX_SUBMISSIONS` (we can't aggregate more per-window than fits in the
/// buffer).
fn required_quorum(n_operators: u16) -> u16 {
    let natural = core::cmp::max(1, n_operators.div_ceil(10));
    core::cmp::min(natural, MAX_SUBMISSIONS as u16)
}

/// Exposed `pub` only so the live-mainnet integration test in `tests/`
/// (a separate crate) can consume it. Not part of the stable on-chain
/// API; no compatibility guarantees across minor versions.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct ParsedVoteHeader {
    pub node_pubkey: Pubkey,
    pub authorized_withdrawer: Pubkey,
}

/// Walk a vote account body (bincode `VoteStateVersions::Current`). On
/// success returns `(node_pubkey, authorized_withdrawer)` AND has verified:
/// - tag == 2 (Current variant),
/// - 64 entries in `epoch_credits` (no more, no less),
/// - epochs are consecutive (no gaps),
/// - at most 6 entries with `this_epoch_credits < MIN_CREDITS_PER_EPOCH`,
/// - sum of `this_epoch_credits` across all 64 ≥ `MIN_TOTAL_CREDITS_WINDOW`.
///
/// The byte-offset layout was validated against live X1 mainnet using
/// `solana-program`'s reference bincode deserializer — see
/// `programs/x1-strontium/tests/account_parse_integration.rs`.
///
/// Note: the last epoch_credits entry is the current (in-progress) epoch
/// and its `this_epoch_credits` monotonically grows during the epoch. This
/// parser deliberately does NOT special-case it — the bad-epoch tolerance
/// of 6 is large enough that one in-progress entry being "bad" early in an
/// epoch still leaves room for actual completed bad epochs.
///
/// Exposed `pub` only so the live-mainnet integration test can call it;
/// not part of the stable on-chain API.
#[doc(hidden)]
pub fn parse_and_validate_vote(data: &[u8]) -> Result<ParsedVoteHeader> {
    // Fixed prefix: tag + node_pubkey + authorized_withdrawer + commission.
    if data.len() < 69 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }
    let tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if tag != 2 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }
    let mut node_bytes = [0u8; 32];
    node_bytes.copy_from_slice(&data[4..36]);
    let mut withdraw_bytes = [0u8; 32];
    withdraw_bytes.copy_from_slice(&data[36..68]);

    // Walk variable-length sections until we reach epoch_credits.
    let mut off = 69usize;

    // votes: VecDeque<LandedVote> — u64 len + len × 13
    if data.len() < off + 8 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }
    let votes_len = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as usize;
    off = off
        .checked_add(8)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    let votes_bytes = votes_len
        .checked_mul(13)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    off = off
        .checked_add(votes_bytes)
        .ok_or(error!(X1StrontiumError::Overflow))?;

    // root_slot: Option<Slot>
    if data.len() < off + 1 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }
    let root_tag = data[off];
    off = off
        .checked_add(1)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    if root_tag == 1 {
        off = off
            .checked_add(8)
            .ok_or(error!(X1StrontiumError::Overflow))?;
    } else if root_tag != 0 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }

    // authorized_voters: BTreeMap<Epoch, Pubkey> — u64 len + len × 40
    if data.len() < off + 8 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }
    let av_len = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as usize;
    off = off
        .checked_add(8)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    let av_bytes = av_len
        .checked_mul(40)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    off = off
        .checked_add(av_bytes)
        .ok_or(error!(X1StrontiumError::Overflow))?;

    // prior_voters: CircBuf<(Pubkey, Epoch, Epoch), 32> — fixed 1545 B
    //   buf: 32 × (32+8+8) = 1536  +  idx (usize→u64 = 8)  +  is_empty (u8 = 1)
    off = off
        .checked_add(1545)
        .ok_or(error!(X1StrontiumError::Overflow))?;

    // epoch_credits: Vec<(Epoch, u64, u64)> — u64 len + len × 24
    if data.len() < off + 8 {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }
    let ec_len = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off = off
        .checked_add(8)
        .ok_or(error!(X1StrontiumError::Overflow))?;

    if ec_len < MIN_EPOCH_HISTORY {
        return err!(X1StrontiumError::InsufficientEpochHistory);
    }
    let ec_bytes = (ec_len as usize)
        .checked_mul(24)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    let ec_end = off
        .checked_add(ec_bytes)
        .ok_or(error!(X1StrontiumError::Overflow))?;
    if data.len() < ec_end {
        return err!(X1StrontiumError::InvalidVoteAccount);
    }

    let mut bad_epochs: u64 = 0;
    let mut total_credits: u64 = 0;
    let mut prev_epoch: Option<u64> = None;
    for i in 0..(ec_len as usize) {
        let base = off + i * 24;
        let epoch_i = u64::from_le_bytes(data[base..base + 8].try_into().unwrap());
        let credits = u64::from_le_bytes(data[base + 8..base + 16].try_into().unwrap());
        let prev_cr = u64::from_le_bytes(data[base + 16..base + 24].try_into().unwrap());

        if let Some(prev) = prev_epoch {
            if epoch_i != prev.saturating_add(1) {
                return err!(X1StrontiumError::EpochGapDetected);
            }
        }
        prev_epoch = Some(epoch_i);

        let this_epoch = credits.saturating_sub(prev_cr);
        if this_epoch < MIN_CREDITS_PER_EPOCH {
            bad_epochs = bad_epochs.saturating_add(1);
        }
        total_credits = total_credits
            .checked_add(this_epoch)
            .ok_or(error!(X1StrontiumError::Overflow))?;
    }

    if bad_epochs > MAX_BAD_EPOCHS_IN_WINDOW {
        return err!(X1StrontiumError::TooManyBadEpochs);
    }
    if total_credits < MIN_TOTAL_CREDITS_WINDOW {
        return err!(X1StrontiumError::InsufficientTotalCredits);
    }

    Ok(ParsedVoteHeader {
        node_pubkey: Pubkey::new_from_array(node_bytes),
        authorized_withdrawer: Pubkey::new_from_array(withdraw_bytes),
    })
}

/// Parsed fields of a `StakeStateV2::Stake` variant. `None` is returned for
/// non-Stake variants (Uninitialized, Initialized, RewardsPool) by the
/// caller — those contribute 0 stake and are skipped silently.
///
/// Exposed `pub` only so the live-mainnet integration test can assert its
/// fields match `solana-program`'s reference parser; not part of the
/// stable on-chain API.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedStake {
    pub voter_pubkey: Pubkey,
    pub withdrawer: Pubkey,
    pub stake_amount: u64,
    pub activation_epoch: u64,
    pub deactivation_epoch: u64,
}

/// Parse a stake account's raw bytes. Returns `Ok(None)` if the account is
/// a valid stake account but not in the `Stake` variant (disc != 2).
/// Returns `Err` only for genuinely malformed data (too short).
///
/// Byte offsets (validated against `solana-program`'s
/// `StakeStateV2::deserialize` on live X1 mainnet in
/// `tests/account_parse_integration.rs`):
///   0..4     u32 enum tag (0=Uninit, 1=Init, 2=Stake, 3=RewardsPool)
///   44..76   Meta.authorized.withdrawer
///   124..156 Stake.delegation.voter_pubkey
///   156..164 Stake.delegation.stake (u64)
///   164..172 Stake.delegation.activation_epoch (u64)
///   172..180 Stake.delegation.deactivation_epoch (u64)
///
/// Exposed `pub` only so the live-mainnet integration test can call it;
/// not part of the stable on-chain API.
#[doc(hidden)]
pub fn parse_stake_state(data: &[u8]) -> Result<Option<ParsedStake>> {
    if data.len() < 4 {
        return err!(X1StrontiumError::InvalidStakeAccount);
    }
    let disc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if disc != 2 {
        return Ok(None);
    }
    if data.len() < 180 {
        return err!(X1StrontiumError::InvalidStakeAccount);
    }
    let mut withdrawer = [0u8; 32];
    withdrawer.copy_from_slice(&data[44..76]);
    let mut voter = [0u8; 32];
    voter.copy_from_slice(&data[124..156]);
    let stake_amount = u64::from_le_bytes(data[156..164].try_into().unwrap());
    let activation_epoch = u64::from_le_bytes(data[164..172].try_into().unwrap());
    let deactivation_epoch = u64::from_le_bytes(data[172..180].try_into().unwrap());
    Ok(Some(ParsedStake {
        voter_pubkey: Pubkey::new_from_array(voter),
        withdrawer: Pubkey::new_from_array(withdrawer),
        stake_amount,
        activation_epoch,
        deactivation_epoch,
    }))
}

/// Does this parsed stake contribute to the operator's self-stake total?
/// Filters (all must pass):
///   - voter_pubkey == expected vote account,
///   - withdrawer == operator authority (Ledger),
///   - active ≥ MIN_STAKE_AGE_EPOCHS epochs (accounts activated < 2 epochs
///     ago are excluded, preventing "stake now, initialize operator, unstake"),
///   - deactivation_epoch == u64::MAX (not currently unstaking).
///
/// Exposed `pub` only so the live-mainnet integration test can reuse the
/// exact filtering the contract applies; not part of the stable on-chain
/// API.
#[doc(hidden)]
pub fn stake_is_qualifying(
    stake: &ParsedStake,
    vote_pubkey: &Pubkey,
    authority: &Pubkey,
    current_epoch: u64,
) -> bool {
    if stake.voter_pubkey != *vote_pubkey {
        return false;
    }
    if stake.withdrawer != *authority {
        return false;
    }
    if current_epoch.saturating_sub(stake.activation_epoch) < MIN_STAKE_AGE_EPOCHS {
        return false;
    }
    if stake.deactivation_epoch != u64::MAX {
        return false;
    }
    true
}

/// Sum stake amounts from `remaining_accounts` that all pass:
///   (1) owner == stake program,
///   (2) `StakeStateV2::Stake` variant (disc == 2),
///   (3) `stake_is_qualifying` (voter/withdrawer/age/not-deactivating).
fn sum_qualifying_self_stake(
    accounts: &[AccountInfo],
    vote_pubkey: &Pubkey,
    authority: &Pubkey,
    current_epoch: u64,
) -> Result<u64> {
    let mut total: u64 = 0;
    for info in accounts.iter() {
        require_keys_eq!(
            *info.owner,
            stake::program::ID,
            X1StrontiumError::InvalidStakeAccount
        );
        let data = info.try_borrow_data()?;
        let Some(parsed) = parse_stake_state(&data)? else {
            continue;
        };
        if !stake_is_qualifying(&parsed, vote_pubkey, authority, current_epoch) {
            continue;
        }
        total = total
            .checked_add(parsed.stake_amount)
            .ok_or(error!(X1StrontiumError::Overflow))?;
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Aggregation (median — same philosophy as v0.4)
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

    // v1.0 Bug #2 fix: in a small fleet (quorum=1) a 150-slot window can see
    // multiple submissions that each trigger aggregate(). Writing a new ring
    // entry every time would halve the effective ring depth when n_operators
    // is small. Instead, collapse submissions from the same window into one
    // update-in-place entry; only advance ring_head when the window changes.
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
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeOperator<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + OperatorPDA::LEN,
        seeds = [OPERATOR_SEED, vote_account.key().as_ref()],
        bump,
    )]
    pub operator_pda: Account<'info, OperatorPDA>,

    #[account(
        mut,
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    /// CHECK: owner-validated; parsed manually in the instruction body.
    #[account(owner = vote::program::ID @ X1StrontiumError::InvalidVoteAccount)]
    pub vote_account: UncheckedAccount<'info>,

    /// Ledger (cold key) = vote account's authorized_withdrawer.
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
    // remaining_accounts: stake accounts (self-stake proof)
}

#[derive(Accounts)]
pub struct SubmitTime<'info> {
    #[account(
        mut,
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    #[account(
        mut,
        seeds = [OPERATOR_SEED, vote_account.key().as_ref()],
        bump = operator_pda.bump,
        constraint = operator_pda.active @ X1StrontiumError::OperatorInactive,
        constraint = operator_pda.hot_signer == submitter.key()
            @ X1StrontiumError::WrongHotSigner,
    )]
    pub operator_pda: Account<'info, OperatorPDA>,

    /// CHECK: seed-bound to operator_pda; owner-validated.
    #[account(owner = vote::program::ID @ X1StrontiumError::InvalidVoteAccount)]
    pub vote_account: UncheckedAccount<'info>,

    pub submitter: Signer<'info>,
    // remaining_accounts: stake accounts (only when daily recheck is due)
}

#[derive(Accounts)]
pub struct RotateHotSigner<'info> {
    #[account(
        mut,
        seeds = [OPERATOR_SEED, vote_account.key().as_ref()],
        bump = operator_pda.bump,
        has_one = authority @ X1StrontiumError::Unauthorized,
    )]
    pub operator_pda: Account<'info, OperatorPDA>,

    /// CHECK: seed source only — not dereferenced.
    pub vote_account: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DeactivateOperator<'info> {
    #[account(
        mut,
        seeds = [OPERATOR_SEED, vote_account.key().as_ref()],
        bump = operator_pda.bump,
        has_one = authority @ X1StrontiumError::Unauthorized,
    )]
    pub operator_pda: Account<'info, OperatorPDA>,

    #[account(
        mut,
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    /// CHECK: seed source only.
    pub vote_account: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseOperator<'info> {
    #[account(
        mut,
        seeds = [OPERATOR_SEED, vote_account.key().as_ref()],
        bump = operator_pda.bump,
        has_one = authority @ X1StrontiumError::Unauthorized,
        close = authority,
    )]
    pub operator_pda: Account<'info, OperatorPDA>,

    #[account(
        mut,
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,

    /// CHECK: seed source only.
    pub vote_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReadTime<'info> {
    #[account(
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,
}

#[derive(Accounts)]
pub struct SetOperatorsCount<'info> {
    #[account(
        mut,
        seeds = [ORACLE_STATE_SEED, ORACLE_STATE_SEED_2, ORACLE_STATE_SEED_3],
        bump = oracle_state.load()?.bump,
    )]
    pub oracle_state: AccountLoader<'info, OracleState>,
    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// Account types
// ---------------------------------------------------------------------------

#[account]
pub struct OperatorPDA {
    /// Ledger pubkey = vote account's `authorized_withdrawer`. Signs admin
    /// ops (init, rotate, deactivate, close).
    pub authority: Pubkey, // 32 (0..32)
    /// Hot key on the operator's server. Signs `submit_time`.
    pub hot_signer: Pubkey, // 32 (32..64)
    /// Vote account this operator is bound to (PDA seed).
    pub vote_account: Pubkey, // 32 (64..96)
    /// `node_pubkey` parsed from the vote account at init — recorded for
    /// audit / daemon sanity checks; not used on chain post-init.
    pub validator_identity: Pubkey, // 32 (96..128)
    pub registered_at: i64,         //  8 (128..136)
    pub last_stake_check_slot: u64, //  8 (136..144)
    pub self_stake_amount: u64,     //  8 (144..152)
    pub active: bool,               //  1 (152)
    pub bump: u8,                   //  1 (153)
    pub _pad: [u8; 6],              //  6 (154..160)
}

impl OperatorPDA {
    pub const LEN: usize = 32 * 4 + 8 * 3 + 1 + 1 + 6; // 160
}

#[account(zero_copy(unsafe))]
#[repr(C)]
pub struct OracleState {
    pub authority: Pubkey,                                   //    0..32
    pub bump: u8,                                            //   32
    pub is_degraded: u8,                                     //   33
    pub confidence_pct: u8,                                  //   34
    pub _pad0: [u8; 5],                                      //   35..40
    pub trusted_time_ms: i64,                                //   40..48
    pub last_updated_slot: u64,                              //   48..56
    pub spread_ms: i64,                                      //   56..64
    pub window_start_slot: u64,                              //   64..72
    pub active_submitters: u16,                              //   72..74
    pub quorum_threshold: u16,                               //   74..76
    pub submission_count: u16,                               //   76..78
    pub ring_head: u16,                                      //   78..80
    pub ring_count: u16,                                     //   80..82
    pub n_operators: u16,                                    //   82..84
    pub _pad1: [u8; 4],                                      //   84..88
    pub _pad_reserve: [u8; 8],                               //   88..96
    pub submissions: [ValidatorSubmission; MAX_SUBMISSIONS], //   96..528  (6*72)
    pub ring_buffer: [RingEntry; RING_SIZE],                 //  528..9744 (288*32)
}

#[zero_copy(unsafe)]
#[repr(C)]
pub struct ValidatorSubmission {
    pub validator: Pubkey,  // 0..32
    pub timestamp_ms: i64,  // 32..40
    pub spread_ms: i64,     // 40..48
    pub slot: u64,          // 48..56
    pub sources_used: u8,   // 56
    pub confidence_pct: u8, // 57
    pub _pad0: [u8; 6],     // 58..64  (grown from 2→6 B to naturally
    //          align sources_bitmap:u64 at 64)
    pub sources_bitmap: u64, // 64..72  (u64 bitmap — FAZA B capacity 64)
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
    pub _pad: [u8; 4],        // 20..24  (explicit — aligns u64 at 24)
    pub sources_bitmap: u64,  // 24..32  (u64 bitmap — FAZA B capacity 64)
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
    /// u64 bitmap (FAZA B) — upgraded from u32 to accommodate the expanded
    /// 43-entry NTP_SOURCES list. Wire encoding: 8 bytes little-endian.
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
    #[msg("Oracle is in degraded state — quorum not met")]
    OracleDegraded,
    #[msg("Oracle data is older than the requested staleness window")]
    OracleStale,
    #[msg("Caller is not authorized for this action")]
    Unauthorized,
    #[msg("Operator PDA is not active")]
    OperatorInactive,
    #[msg("Submitter signer does not match the operator's registered hot_signer")]
    WrongHotSigner,
    #[msg("Invalid operators count (must be ≥ 1)")]
    InvalidOperatorsCount,
    #[msg("authority must equal the vote account's authorized_withdrawer")]
    InvalidAuthorizedWithdrawer,
    #[msg("Vote account has fewer than 64 epoch_credits entries — validator too young")]
    InsufficientEpochHistory,
    #[msg("Gap detected in epoch_credits — epochs must be consecutive")]
    EpochGapDetected,
    #[msg("Too many epochs below MIN_CREDITS_PER_EPOCH in the 64-epoch window")]
    TooManyBadEpochs,
    #[msg("Total credits across 64-epoch window below MIN_TOTAL_CREDITS_WINDOW")]
    InsufficientTotalCredits,
    #[msg(
        "Self-stake below 128 XNT (filter: withdrawer=authority, age≥2 epochs, not deactivating)"
    )]
    InsufficientSelfStake,
    #[msg("Self-stake dropped below 128 XNT at daily recheck")]
    InsufficientSelfStakeAtRecheck,
    #[msg("Daily stake recheck required but no stake accounts in remaining_accounts")]
    StakeRecheckRequired,
    #[msg("Invalid stake account (wrong owner, too small, or bad discriminant)")]
    InvalidStakeAccount,
    #[msg("Invalid vote account (wrong owner, too small, or unknown VoteStateVersions tag)")]
    InvalidVoteAccount,
    #[msg("Vote account too small — validator never voted")]
    ValidatorNeverVoted,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Network is at maximum operator capacity (512)")]
    TooManyOperators,
}

// ---------------------------------------------------------------------------
// Unit tests (host-side, not SBF)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    // -----------------------------------------------------------------------
    // Helpers — synthesise minimal valid Solana account bodies so unit tests
    // can exercise the manual parsers without hitting the network. All byte
    // offsets match the bincode serialisation rules validated in FAZA 0.
    // -----------------------------------------------------------------------

    /// Build a bincode-style `VoteStateVersions::Current` blob that walks
    /// end-to-end through `parse_and_validate_vote`. Contains no votes, no
    /// root_slot, no authorized_voters — only the fields the parser reads
    /// (tag, node, withdrawer, commission, and epoch_credits after the
    /// fixed-length prior_voters CircBuf).
    fn make_vote_blob(
        node: [u8; 32],
        withdrawer: [u8; 32],
        epoch_credits: &[(u64, u64, u64)],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(1700 + epoch_credits.len() * 24);
        data.extend_from_slice(&2u32.to_le_bytes()); // tag = Current
        data.extend_from_slice(&node);
        data.extend_from_slice(&withdrawer);
        data.push(0); // commission
        data.extend_from_slice(&0u64.to_le_bytes()); // votes VecDeque len = 0
        data.push(0); // root_slot Option tag = None
        data.extend_from_slice(&0u64.to_le_bytes()); // authorized_voters BTreeMap len = 0
        data.extend_from_slice(&[0u8; 1545]); // prior_voters CircBuf (fixed)
        data.extend_from_slice(&(epoch_credits.len() as u64).to_le_bytes());
        for (e, c, p) in epoch_credits {
            data.extend_from_slice(&e.to_le_bytes());
            data.extend_from_slice(&c.to_le_bytes());
            data.extend_from_slice(&p.to_le_bytes());
        }
        data
    }

    /// 64 consecutive epochs starting at `start_epoch`, each contributing
    /// `credits_per_epoch` credits. Well above `MIN_CREDITS_PER_EPOCH` =
    /// 2 000 000 by default.
    fn clean_64_epoch_credits(start_epoch: u64, credits_per_epoch: u64) -> Vec<(u64, u64, u64)> {
        let mut out = Vec::with_capacity(64);
        let mut running = 1_000_000_000u64; // arbitrary baseline
        for i in 0..64 {
            let prev = running;
            running += credits_per_epoch;
            out.push((start_epoch + i, running, prev));
        }
        out
    }

    /// Build a `StakeStateV2::Stake` blob (disc=2) with only the offsets the
    /// parser reads set to meaningful values. Fields we don't parse
    /// (rent_exempt_reserve, staker, lockup, warmup_cooldown, credits_observed,
    /// StakeFlags) are zeroed.
    fn make_stake_blob(
        withdrawer: [u8; 32],
        voter: [u8; 32],
        stake_amount: u64,
        activation_epoch: u64,
        deactivation_epoch: u64,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // disc = Stake
        data[44..76].copy_from_slice(&withdrawer);
        data[124..156].copy_from_slice(&voter);
        data[156..164].copy_from_slice(&stake_amount.to_le_bytes());
        data[164..172].copy_from_slice(&activation_epoch.to_le_bytes());
        data[172..180].copy_from_slice(&deactivation_epoch.to_le_bytes());
        data
    }

    /// Assert that an Anchor error is the expected `X1StrontiumError` variant.
    /// Anchor's `#[error_code]` derives `From<X1StrontiumError> for u32`
    /// returning `6000 + variant_index`, and puts that number into
    /// `AnchorError::error_code_number`.
    fn assert_anchor_error(err: anchor_lang::error::Error, expected: X1StrontiumError) {
        let expected_code: u32 = expected.into();
        match err {
            anchor_lang::error::Error::AnchorError(ae) => {
                assert_eq!(
                    ae.error_code_number, expected_code,
                    "expected {:?} (code {}), got {} (code {})",
                    expected, expected_code, ae.error_name, ae.error_code_number
                );
            }
            other => panic!("expected AnchorError, got {:?}", other),
        }
    }

    /// Build a zeroed `OracleState` on the heap. `OracleState` is a POD-like
    /// struct (repr(C) with only Pubkey/u64/i64/u16/u8/[u8; N] fields), so
    /// `mem::zeroed()` produces a valid value. Used by the ring-buffer and
    /// aggregation tests below.
    fn zeroed_state() -> Box<OracleState> {
        // Safety: all fields of OracleState are plain integer/byte types or
        // Pubkey (which is a newtype over [u8; 32]); the all-zero bit pattern
        // is a valid initialised value for each.
        Box::new(unsafe { std::mem::zeroed() })
    }

    // -----------------------------------------------------------------------
    // Existing — sanity checks on fixed constants and layouts
    // -----------------------------------------------------------------------

    #[test]
    fn required_quorum_scales_and_caps() {
        assert_eq!(required_quorum(0), 1);
        assert_eq!(required_quorum(1), 1);
        assert_eq!(required_quorum(10), 1);
        assert_eq!(required_quorum(11), 2);
        assert_eq!(required_quorum(50), 5);
        assert_eq!(required_quorum(51), 6);
        // MAX_OPERATORS = 512; natural quorum at 512 would be 52 → capped at 6.
        assert_eq!(required_quorum(60), 6);
        assert_eq!(required_quorum(100), 6);
        assert_eq!(required_quorum(256), 6);
        assert_eq!(required_quorum(512), 6);
        // Sanity: even well above MAX_OPERATORS the cap holds.
        assert_eq!(required_quorum(5000), 6);
    }

    #[test]
    fn oracle_state_layout() {
        // FAZA B: sources_bitmap u32→u64 grows both wrapper structs by 8 B
        // each (u64 alignment forces 4 bytes of structural padding in
        // addition to the 4-byte field growth — empirically verified).
        assert_eq!(size_of::<ValidatorSubmission>(), 72);
        assert_eq!(size_of::<RingEntry>(), 32);
        // Header (96) + submissions (6×72 = 432) + ring (288×32 = 9216) = 9744.
        assert_eq!(size_of::<OracleState>(), 9744);
        // With discriminator (8 B), account size = 9752 B — below X1's
        // 10 240 B CPI realloc cap (headroom = 488 B).
        assert!(8 + size_of::<OracleState>() <= 10_240);
        assert_eq!(10_240 - (8 + size_of::<OracleState>()), 488);
    }

    #[test]
    fn operator_pda_layout() {
        assert_eq!(OperatorPDA::LEN, 160);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_are_sane() {
        // Quick consistency checks to catch typos at review time. These are
        // all const-vs-const comparisons — `#[allow]` silences clippy's
        // `assertions_on_constants` since the intent is deliberate:
        // fail loudly at test time rather than bury the check in a hard-
        // to-read const block.
        assert_eq!(MIN_SELF_STAKE_LAMPORTS, 128 * 1_000_000_000);
        assert_eq!(MIN_EPOCH_HISTORY, 64);
        assert!(MAX_BAD_EPOCHS_IN_WINDOW < MIN_EPOCH_HISTORY);
        assert!(MIN_TOTAL_CREDITS_WINDOW > MIN_CREDITS_PER_EPOCH * MAX_BAD_EPOCHS_IN_WINDOW);
        assert!(MAX_OPERATORS >= 256);
    }

    // -----------------------------------------------------------------------
    // Vote parser — parse_and_validate_vote
    // -----------------------------------------------------------------------

    #[test]
    fn vote_parser_accepts_clean_64_epochs_and_returns_header() {
        let node = [11u8; 32];
        let withdrawer = [22u8; 32];
        let ec = clean_64_epoch_credits(100, 3_000_000);
        let data = make_vote_blob(node, withdrawer, &ec);

        let header = parse_and_validate_vote(&data).expect("clean vote blob should pass");
        assert_eq!(header.node_pubkey.to_bytes(), node);
        assert_eq!(header.authorized_withdrawer.to_bytes(), withdrawer);
    }

    #[test]
    fn vote_parser_rejects_under_64_entries() {
        // 63 epochs — one short of the 64-entry requirement.
        let ec: Vec<(u64, u64, u64)> = (0..63)
            .map(|i| (i, (i + 1) * 3_000_000, i * 3_000_000))
            .collect();
        let data = make_vote_blob([0; 32], [0; 32], &ec);

        let err = parse_and_validate_vote(&data).expect_err("should reject <64 entries");
        assert_anchor_error(err, X1StrontiumError::InsufficientEpochHistory);
    }

    #[test]
    fn vote_parser_rejects_epoch_gap() {
        let mut ec = clean_64_epoch_credits(100, 3_000_000);
        // Introduce a gap: bump epoch[32] from 132 to 133, breaking
        // consecutiveness between entries [31] and [32].
        ec[32].0 = 133;
        let data = make_vote_blob([0; 32], [0; 32], &ec);

        let err = parse_and_validate_vote(&data).expect_err("should reject epoch gap");
        assert_anchor_error(err, X1StrontiumError::EpochGapDetected);
    }

    #[test]
    fn vote_parser_tolerates_exactly_max_bad_epochs() {
        // 6 bad epochs (= MAX_BAD_EPOCHS_IN_WINDOW) + 58 good ones.
        // Total credits comfortably above MIN_TOTAL_CREDITS_WINDOW.
        let mut ec: Vec<(u64, u64, u64)> = Vec::with_capacity(64);
        let mut running = 1_000_000_000u64;
        for i in 0..64 {
            let this = if i < 6 { 1_500_000 } else { 3_000_000 };
            let prev = running;
            running += this;
            ec.push((i, running, prev));
        }
        let data = make_vote_blob([1; 32], [2; 32], &ec);
        parse_and_validate_vote(&data).expect("6 bad epochs should be tolerated");
    }

    #[test]
    fn vote_parser_rejects_seven_bad_epochs() {
        let mut ec: Vec<(u64, u64, u64)> = Vec::with_capacity(64);
        let mut running = 1_000_000_000u64;
        for i in 0..64 {
            let this = if i < 7 { 1_500_000 } else { 3_000_000 };
            let prev = running;
            running += this;
            ec.push((i, running, prev));
        }
        let data = make_vote_blob([0; 32], [0; 32], &ec);

        let err = parse_and_validate_vote(&data).expect_err("7 bad epochs should reject");
        assert_anchor_error(err, X1StrontiumError::TooManyBadEpochs);
    }

    #[test]
    fn vote_parser_rejects_low_total_credits() {
        // 64 epochs, every epoch just above the per-epoch floor
        // (2_000_000 + 1) so none count as "bad", but the total is
        // 64 * ~2_000_001 ≈ 128 M — below MIN_TOTAL_CREDITS_WINDOW = 150 M.
        let mut ec: Vec<(u64, u64, u64)> = Vec::with_capacity(64);
        let mut running = 1_000_000_000u64;
        let per_epoch = MIN_CREDITS_PER_EPOCH + 1;
        for i in 0..64 {
            let prev = running;
            running += per_epoch;
            ec.push((i, running, prev));
        }
        // Sanity-check our arithmetic: 64 * 2_000_001 = 128_000_064 < 150_000_000.
        assert!(64 * per_epoch < MIN_TOTAL_CREDITS_WINDOW);
        let data = make_vote_blob([0; 32], [0; 32], &ec);

        let err = parse_and_validate_vote(&data).expect_err("low total credits should reject");
        assert_anchor_error(err, X1StrontiumError::InsufficientTotalCredits);
    }

    #[test]
    fn vote_parser_rejects_wrong_tag() {
        let ec = clean_64_epoch_credits(0, 3_000_000);
        let mut data = make_vote_blob([0; 32], [0; 32], &ec);
        // Flip tag from 2 (Current) to 1 (V1_14_11 — not supported).
        data[0..4].copy_from_slice(&1u32.to_le_bytes());

        let err = parse_and_validate_vote(&data).expect_err("non-Current tag should reject");
        assert_anchor_error(err, X1StrontiumError::InvalidVoteAccount);
    }

    #[test]
    fn vote_parser_rejects_short_data() {
        // Anything below the fixed prefix (4+32+32+1 = 69 B) must reject.
        for len in [0, 1, 68] {
            let data = vec![0u8; len];
            let err = parse_and_validate_vote(&data)
                .expect_err(&format!("data of length {len} should reject"));
            assert_anchor_error(err, X1StrontiumError::InvalidVoteAccount);
        }
    }

    // -----------------------------------------------------------------------
    // Stake parser — parse_stake_state + stake_is_qualifying
    // -----------------------------------------------------------------------

    #[test]
    fn stake_parser_extracts_all_fields_correctly() {
        let withdrawer = [0xa1u8; 32];
        let voter = [0xb2u8; 32];
        let data = make_stake_blob(withdrawer, voter, 500_000_000_000, 170, u64::MAX);

        let parsed = parse_stake_state(&data)
            .expect("valid bytes")
            .expect("Stake variant");
        assert_eq!(parsed.withdrawer.to_bytes(), withdrawer);
        assert_eq!(parsed.voter_pubkey.to_bytes(), voter);
        assert_eq!(parsed.stake_amount, 500_000_000_000);
        assert_eq!(parsed.activation_epoch, 170);
        assert_eq!(parsed.deactivation_epoch, u64::MAX);
    }

    #[test]
    fn stake_parser_returns_none_for_non_stake_variants() {
        for non_stake_disc in [0u32, 1, 3] {
            let mut data = vec![0u8; 200];
            data[0..4].copy_from_slice(&non_stake_disc.to_le_bytes());
            let result = parse_stake_state(&data).expect("short-enough data is fine");
            assert!(
                result.is_none(),
                "disc {non_stake_disc} should return None (non-Stake variant)"
            );
        }
    }

    #[test]
    fn stake_parser_rejects_stake_variant_with_truncated_data() {
        // disc=2 (Stake) but data too short to hold the Stake body.
        let mut data = vec![0u8; 180 - 1];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let err = parse_stake_state(&data).expect_err("short Stake body should reject");
        assert_anchor_error(err, X1StrontiumError::InvalidStakeAccount);
    }

    #[test]
    fn stake_parser_rejects_zero_length_data() {
        let err = parse_stake_state(&[]).expect_err("empty data should reject");
        assert_anchor_error(err, X1StrontiumError::InvalidStakeAccount);
    }

    #[test]
    fn stake_qualifies_when_all_filters_pass() {
        let vote = Pubkey::new_from_array([1u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let stake = ParsedStake {
            voter_pubkey: vote,
            withdrawer: authority,
            stake_amount: 200_000_000_000,
            activation_epoch: 100,
            deactivation_epoch: u64::MAX,
        };
        // current_epoch=105 → age = 5 ≥ MIN_STAKE_AGE_EPOCHS (2).
        assert!(stake_is_qualifying(&stake, &vote, &authority, 105));
    }

    #[test]
    fn stake_filter_rejects_wrong_voter() {
        // Self-stake delegated to someone ELSE's vote — must not count.
        let vote = Pubkey::new_from_array([1u8; 32]);
        let other_vote = Pubkey::new_from_array([99u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let stake = ParsedStake {
            voter_pubkey: other_vote,
            withdrawer: authority,
            stake_amount: 200_000_000_000,
            activation_epoch: 100,
            deactivation_epoch: u64::MAX,
        };
        assert!(!stake_is_qualifying(&stake, &vote, &authority, 105));
    }

    #[test]
    fn stake_filter_rejects_wrong_withdrawer() {
        // Foundation delegation: withdrawer is the X1 Labs treasury key,
        // not the operator's Ledger. Must NOT count as operator self-stake.
        let vote = Pubkey::new_from_array([1u8; 32]);
        let ledger_authority = Pubkey::new_from_array([2u8; 32]);
        let foundation_withdrawer = Pubkey::new_from_array([0xffu8; 32]);
        let stake = ParsedStake {
            voter_pubkey: vote,
            withdrawer: foundation_withdrawer,
            stake_amount: 500_000_000_000,
            activation_epoch: 100,
            deactivation_epoch: u64::MAX,
        };
        assert!(!stake_is_qualifying(&stake, &vote, &ledger_authority, 105));
    }

    #[test]
    fn stake_filter_rejects_too_young() {
        // Stake activated at epoch 100, queried at epoch 101 → age 1 <
        // MIN_STAKE_AGE_EPOCHS. Prevents the "stake, init operator,
        // immediately unstake" pattern.
        let vote = Pubkey::new_from_array([1u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let stake = ParsedStake {
            voter_pubkey: vote,
            withdrawer: authority,
            stake_amount: 200_000_000_000,
            activation_epoch: 100,
            deactivation_epoch: u64::MAX,
        };
        assert!(!stake_is_qualifying(&stake, &vote, &authority, 101));
    }

    #[test]
    fn stake_filter_rejects_deactivating() {
        // Same stake, but deactivation has been scheduled — must not count
        // even if the lamports are still on the account right now.
        let vote = Pubkey::new_from_array([1u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let stake = ParsedStake {
            voter_pubkey: vote,
            withdrawer: authority,
            stake_amount: 200_000_000_000,
            activation_epoch: 100,
            deactivation_epoch: 110,
        };
        assert!(!stake_is_qualifying(&stake, &vote, &authority, 120));
    }

    #[test]
    fn stake_filter_accepts_at_exactly_min_age() {
        // Boundary: current_epoch - activation_epoch == MIN_STAKE_AGE_EPOCHS.
        let vote = Pubkey::new_from_array([1u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let stake = ParsedStake {
            voter_pubkey: vote,
            withdrawer: authority,
            stake_amount: 200_000_000_000,
            activation_epoch: 100,
            deactivation_epoch: u64::MAX,
        };
        assert!(stake_is_qualifying(
            &stake,
            &vote,
            &authority,
            100 + MIN_STAKE_AGE_EPOCHS
        ));
    }

    // -----------------------------------------------------------------------
    // v1.0 new — aggregation + ring-buffer behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn aggregation_sets_trusted_time_to_median() {
        // 3 submissions with timestamps {100, 200, 150}. After insertion sort
        // inside aggregate() the slice is [100, 150, 200] and the median at
        // index n/2 == 1 is 150.
        let mut state = zeroed_state();
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

        // First submitter at slot 150 (window = 1).
        state.submission_count = 1;
        state.submissions[0].timestamp_ms = 1_700_000_000_000;
        state.submissions[0].confidence_pct = 80;
        aggregate(&mut state, 150);
        assert_eq!(state.ring_count, 1);
        assert_eq!(state.ring_head, 1);
        assert_eq!(state.ring_buffer[0].trusted_time_ms, 1_700_000_000_000);
        assert_eq!(state.ring_buffer[0].slot, 150);

        // Second submitter at slot 200 (still window = 1 since 200/150 == 1).
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
        // The entry we just wrote reflects the second submission's median.
        assert_eq!(state.ring_buffer[0].trusted_time_ms, 1_700_000_000_050);
        assert_eq!(state.ring_buffer[0].slot, 200);
    }

    #[test]
    fn ring_buffer_advances_on_new_window() {
        // Two aggregations in distinct windows → two ring entries, head
        // advanced twice, count == 2.
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
}
