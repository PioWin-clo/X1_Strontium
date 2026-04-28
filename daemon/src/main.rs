mod config;
mod consensus;
mod ntp_client;
mod rotation;
mod status;
mod submitter;

use crate::config::X1StrontiumConfig;
use crate::consensus::{run_consensus_cycle, ConsensusRejection, ConsensusResult, MAX_SPREAD_MS};
use crate::ntp_client::{discover_sources, get_system_clock_ms, to_source_status};
use crate::rotation::{rotation_my_turn, window_has_submission, RotationState};
use crate::status::{DaemonStatus, SilentReason};
use crate::submitter::{
    base64_encode, build_initialize_transaction, build_submit_transaction_signed,
    derive_operator_pda, estimate_days_remaining, lamports_to_xnt, load_keypair, RpcClient,
    SubmitParams, COST_PER_TX_XNT,
};
use std::env;
use std::process;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MIN_BALANCE_WARN: f64 = 1.0;
const MIN_BALANCE_STOP: f64 = 0.05;
const REDISCOVER_SECS: i64 = 3600;
const READINESS_MAX_TRIES: u32 = 20;

// Cadence for the two off-chain background tasks run inside the main cycle
// loop (both gated by elapsed wall-clock time, reset after each run).
const PEERS_REFETCH_SECS: i64 = 15 * 60;
const SELF_STAKE_CHECK_SECS: i64 = 15 * 60;

// Slot-count threshold at which the daemon starts attaching stake accounts to
// the submit TX so the contract's daily stake recheck can succeed. The
// contract demands a recheck after 216_000 slots (~24 h); we pre-empt by ~1 h
// at 200_000 slots so a TX failure doesn't strand the operator at the edge.
const STAKE_CHECK_WARN_THRESHOLD_SLOTS: u64 = 200_000;

/// Bug #1 fix (v1.0): aligned with the on-chain contract's
/// `MIN_SELF_STAKE_LAMPORTS = 128_000_000_000` (128 XNT). v0.5 had 100 XNT
/// here and 128 XNT on chain, so operators never got an off-chain warning
/// before the on-chain daily recheck started rejecting their TXs.
///
/// **MUST match `programs/x1-strontium/src/lib.rs` `MIN_SELF_STAKE_LAMPORTS`**.
/// The `min_self_stake_matches_contract_value` unit test below is a tripwire
/// that fails if this literal drifts from 128 XNT — if you intentionally
/// change the contract's threshold, update both places and the test.
const MIN_SELF_STAKE_LAMPORTS: u64 = 128_000_000_000;

fn print_help() {
    println!(
        "\
X1 Strontium — Decentralized Time Oracle for X1 Blockchain (v1.0)

USAGE:
  x1-strontium <command> [options]
  x1sr <command> [options]            (symlink installed by `install`)

COMMANDS:
  start [--dry-run]     Start the daemon (--dry-run: compute only, no TX)
  stop                  Stop the running daemon and reap zombie processes
  status                Show daemon status, last TX, spread, confidence
  sources               Show NTP source table with RTT and offsets
  balance               Show hot-signer keypair balance and runway
  config show           Show current configuration
  config set <k> <v>    Set a config value
  read [--last N]       Decode Oracle PDA ring buffer (default: last 10)
  init [--authority <keypair>]
                        Initialize Oracle State PDA (one-time setup after deploy)
  install               Install as systemd service (requires sudo)
  uninstall             Remove systemd service (requires sudo)
  update                Pull, rebuild, restart (git + cargo + systemctl)

NOTE: operator on/off-boarding (initialize_operator, rotate_hot_signer,
deactivate_operator, close_operator) is done via `solana` CLI + Ledger
out-of-band — see docs/OPERATOR_ONBOARDING.md. The daemon only signs
`submit_time` TXs.

CONFIG KEYS:
  hot_signer_keypair, vote_account, ledger_derivation_path, rpc, interval,
  memo, dry_run, alert_webhook, alert_balance, tier_threshold,
  rotation_peers, program_id, oracle_pda

ORACLE PDA (v1.0):
  EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        process::exit(1);
    }
    match args[1].as_str() {
        "start" => {
            let mut config = X1StrontiumConfig::load();
            if args.iter().any(|a| a == "--dry-run") {
                config.dry_run = true;
            }
            // If another daemon is already running (stale pidfile, manual
            // duplicate run, systemd + manual race), terminate it first.
            // Otherwise the two instances would race on the rotation window
            // and could double-submit.
            let existing = list_other_daemon_pids();
            if !existing.is_empty() {
                eprintln!(
                    "x1-strontium already running (pids: {existing:?}); stopping before restart"
                );
                kill_pids(&existing, 3);
            }
            if let Err(e) = run_daemon(config) {
                eprintln!("daemon error: {e}");
                process::exit(1);
            }
        }
        "stop" => cmd_stop(),
        "status" => cmd_status(),
        "sources" => cmd_sources(),
        "balance" => cmd_balance(),
        "config" => cmd_config(&args[2..]),
        "install" => cmd_install(),
        "uninstall" => cmd_uninstall(),
        "update" => cmd_update(),
        "read" => cmd_read(&args[2..]),
        "init" => cmd_init(&args[2..]),
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("unknown subcommand: {other}");
            print_help();
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon main loop
// ---------------------------------------------------------------------------

fn run_daemon(config: X1StrontiumConfig) -> Result<(), String> {
    // The daemon only ever holds the hot-signer keypair. Admin ops
    // (initialize_operator, rotate_hot_signer, deactivate, close) are
    // Ledger-signed out-of-band via `solana` CLI.
    let hot_signer_path = config.hot_signer_keypair_path.as_ref().ok_or_else(|| {
        "config.hot_signer_keypair_path is not set — run \
             `x1-strontium config set hot_signer_keypair <path>`"
            .to_string()
    })?;
    let vote_account_b58 = config.vote_account.as_ref().ok_or_else(|| {
        "config.vote_account is not set — the vote account pubkey is required. Run: \
             `x1-strontium config set vote_account <vote-account-pubkey>`"
            .to_string()
    })?;

    let hot_signer_keypair = load_keypair(hot_signer_path)?;
    let hot_signer_bytes: [u8; 32] = hot_signer_keypair.verifying_key().to_bytes();
    let hot_signer_pubkey_b58 = bs58::encode(hot_signer_bytes).into_string();

    let vote_account_raw = bs58::decode(vote_account_b58)
        .into_vec()
        .map_err(|e| format!("invalid vote_account: {e}"))?;
    if vote_account_raw.len() != 32 {
        return Err(format!(
            "vote_account length {} != 32",
            vote_account_raw.len()
        ));
    }
    let mut vote_account: [u8; 32] = [0u8; 32];
    vote_account.copy_from_slice(&vote_account_raw);

    let program_raw = bs58::decode(&config.program_id)
        .into_vec()
        .map_err(|e| format!("invalid program_id: {e}"))?;
    if program_raw.len() != 32 {
        return Err(format!("program_id length {} != 32", program_raw.len()));
    }
    let mut program_id = [0u8; 32];
    program_id.copy_from_slice(&program_raw);

    let oracle_pda_raw = bs58::decode(&config.oracle_pda)
        .into_vec()
        .map_err(|e| format!("invalid oracle_pda: {e}"))?;
    if oracle_pda_raw.len() != 32 {
        return Err(format!("oracle_pda length {} != 32", oracle_pda_raw.len()));
    }
    let mut oracle_pda = [0u8; 32];
    oracle_pda.copy_from_slice(&oracle_pda_raw);

    // operator_pda seeds are [b"operator", vote_account.as_ref()] — bound to
    // the validator, not to any daemon-side keypair.
    let operator_pda = derive_operator_pda(&vote_account, &program_id);

    println!("X1 Strontium daemon starting (v1.0)");
    println!("  hot_signer:      {hot_signer_pubkey_b58}");
    println!("  vote_account:    {vote_account_b58}");
    println!("  program id:      {}", config.program_id);
    println!("  oracle pda:      {}", config.oracle_pda);
    println!(
        "  operator pda:    {}",
        bs58::encode(operator_pda).into_string()
    );
    println!(
        "  interval:        {}s  dry-run: {}",
        config.interval_s, config.dry_run
    );

    readiness_check();

    let mut status = DaemonStatus::load();
    status.oracle_pubkey = hot_signer_pubkey_b58.clone();
    status.interval_s = config.interval_s;
    status.dry_run = config.dry_run;
    status.pid = Some(process::id());
    status.running = true;
    // `silent_cycles` and `silent_reason` are per-run counters. A previous
    // session may have accumulated thousands of silent cycles — leaking that
    // into a fresh start triggers phantom alerts on every cycle because
    // `silent_cycles.is_multiple_of(10)` matches immediately. Reset so the
    // new run starts from a clean slate.
    status.silent_cycles = 0;
    status.silent_reason = None;
    status.save();

    let mut rpc = RpcClient::new(config.rpc_urls.clone());

    // Initial balance check.
    match rpc.get_balance(&hot_signer_pubkey_b58) {
        Ok(lamports) => {
            let bal = lamports_to_xnt(lamports);
            status.balance_xnt = bal;
            status.days_remaining = estimate_days_remaining(bal, config.interval_s);
            status.balance_warning = bal < MIN_BALANCE_WARN;
            status.save();
            if bal < MIN_BALANCE_STOP {
                status.set_silent_reason(SilentReason::InsufficientBalance);
                status.save();
                return Err(format!(
                    "balance {bal:.6} XNT below stop threshold {MIN_BALANCE_STOP:.4} XNT — fund the oracle and retry"
                ));
            }
        }
        Err(e) => {
            eprintln!("[startup] balance check failed: {e}");
        }
    }

    // Initial NTP discovery.
    let mut last_discovery = get_unix_secs();
    let mut sources = discover_sources(3);
    println!("  initial sources: {} healthy", sources.len());
    for s in &sources {
        println!(
            "    {:<32} {:<10} rtt={:>4}ms offset={:>5}ms stratum={}",
            s.host,
            s.tier.label(),
            s.rtt_ms,
            s.offset_ms,
            s.stratum
        );
    }

    // Rotation tracks hot_signer pubkeys — that's the identity each daemon
    // signs `submit_time` with, and the natural "which operator am I" key.
    let mut rotation = RotationState::from_peers(&config.rotation_peers, &hot_signer_bytes);
    let mut my_index = rotation.my_index(&hot_signer_bytes);
    let mut n_oracles = rotation.n_oracles();
    println!("  rotation:        index={my_index} of n={n_oracles}");

    // Cache authorized_withdrawer on startup. The contract's init already
    // enforces authorized_withdrawer == operator_pda.authority (Ledger) — so
    // the daemon can filter stake accounts by this withdrawer to match what
    // the daily recheck will count on chain. There is no local node identity
    // key — hot_signer is unrelated to the validator's withdrawer.
    let authorized_withdrawer_opt: Option<[u8; 32]> = match rpc.fetch_account_info(vote_account_b58)
    {
        Ok(data) if data.len() >= 68 => {
            let mut w = [0u8; 32];
            w.copy_from_slice(&data[36..68]);
            println!(
                "  authorized_withdrawer: {}  (must equal operator_pda.authority = Ledger)",
                bs58::encode(w).into_string()
            );
            Some(w)
        }
        Ok(data) => {
            eprintln!(
                "[startup] vote account data too short ({} bytes) — did the validator ever vote?",
                data.len()
            );
            None
        }
        Err(e) => {
            eprintln!(
                    "[startup] cannot fetch vote account — daily recheck will be skipped until next restart: {e}"
                );
            None
        }
    };

    let mut last_peers_refetch: i64 = get_unix_secs();
    let mut last_self_stake_check: i64 = get_unix_secs();

    // Align the first cycle to the next wall-clock window boundary (e.g. :00,
    // :05, :10 at the default 300 s interval) so memo timestamps are
    // predictable for downstream dApps. Subsequent cycles hold the alignment
    // via the natural sleep(interval_s) at the end of each loop iteration.
    wait_until_next_window_boundary(config.interval_s);

    loop {
        let cycle_started = get_unix_secs();
        status.last_attempt_ts = Some(cycle_started);

        // a. Balance check
        match rpc.get_balance(&hot_signer_pubkey_b58) {
            Ok(lamports) => {
                let bal = lamports_to_xnt(lamports);
                status.balance_xnt = bal;
                status.days_remaining = estimate_days_remaining(bal, config.interval_s);
                let was_warning = status.balance_warning;
                status.balance_warning = bal < MIN_BALANCE_WARN;
                if bal < MIN_BALANCE_STOP {
                    status.set_silent_reason(SilentReason::InsufficientBalance);
                    status.silent_cycles += 1;
                    status.save();
                    eprintln!("balance {bal:.6} XNT below stop threshold — exiting");
                    return Err("insufficient balance".to_string());
                }
                if status.balance_warning && !was_warning {
                    if let Some(url) = &config.alert_webhook {
                        send_alert_webhook(
                            url,
                            &format!("x1-strontium: balance dropped to {bal:.4} XNT (warn threshold {MIN_BALANCE_WARN:.2} XNT)"),
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("[balance] {e}");
            }
        }

        // b1. Auto-refetch active operator list from chain every 15 min.
        //     Hot-reloads rotation state without restart.
        if cycle_started - last_peers_refetch >= PEERS_REFETCH_SECS {
            match rpc.fetch_active_operators(&program_id) {
                Ok(peers) => {
                    let new_rotation = RotationState::from_peers_raw(&peers, &hot_signer_bytes);
                    let new_n = new_rotation.n_oracles();
                    if new_n != n_oracles {
                        println!(
                            "[peers] fleet changed: n={} → n={} (rotation reloaded)",
                            n_oracles, new_n
                        );
                    }
                    rotation = new_rotation;
                    my_index = rotation.my_index(&hot_signer_bytes);
                    n_oracles = rotation.n_oracles();
                    last_peers_refetch = cycle_started;
                }
                Err(e) => {
                    eprintln!("[peers] refetch failed (keeping previous list): {e}");
                    // Still update the timestamp so we don't hammer a broken RPC.
                    last_peers_refetch = cycle_started;
                }
            }
        }

        // b2. Off-chain self-stake early warning every 15 min. If qualifying
        //     self-stake drops below 128 XNT (Bug #1 fix — aligned with the
        //     contract), the on-chain daily recheck WILL fail. Warn the
        //     operator before they get silent.
        if cycle_started - last_self_stake_check >= SELF_STAKE_CHECK_SECS {
            if let Some(withdrawer) = authorized_withdrawer_opt {
                match compute_self_stake_off_chain(&mut rpc, &vote_account, &withdrawer) {
                    Ok(stake) => {
                        if stake < MIN_SELF_STAKE_LAMPORTS {
                            eprintln!(
                                "⚠️  self-stake {} XNT < 128 XNT — next daily recheck will FAIL",
                                stake / 1_000_000_000
                            );
                            if let Some(url) = &config.alert_webhook {
                                send_alert_webhook(
                                    url,
                                    &format!(
                                        "x1-strontium: self-stake dropped to {} XNT — will be deregistered at next daily recheck",
                                        stake / 1_000_000_000
                                    ),
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("[self-stake check] {e}"),
                }
            }
            last_self_stake_check = cycle_started;
        }

        // c. Periodic NTP rediscovery.
        if cycle_started - last_discovery >= REDISCOVER_SECS {
            sources = discover_sources(3);
            last_discovery = cycle_started;
            println!("[discovery] refreshed: {} sources", sources.len());
        }

        // d. Query the chosen sources in parallel.
        let results = query_selected_sources(&sources);
        if results.is_empty() {
            update_status_silent(&mut status, &config, SilentReason::NoValidSources);
            sleep(Duration::from_secs(config.interval_s));
            continue;
        }
        status.ntp_sources = to_source_status(&results);

        // e. Print cycle measurements.
        println!(
            "[cycle] {} sources responded — best RTT {} ms",
            results.len(),
            results.iter().map(|r| r.rtt_ms).min().unwrap_or(0)
        );

        // f. Run consensus.
        let consensus = match run_consensus_cycle(&results, config.tier_consensus_threshold_ms) {
            Ok(c) => c,
            Err(reason) => {
                // Print the exact rejection reason so the operator can tell
                // "spread 170ms" (timestamps, wrong) from "spread 15ms"
                // (offsets, below limit) at a glance.
                eprintln!("[consensus] rejected: {}", reason.label());
                let silent = match reason {
                    ConsensusRejection::InsufficientSources { .. }
                    | ConsensusRejection::IqrTooMany { .. } => SilentReason::NoValidSources,
                    ConsensusRejection::LowConfidence { .. } => SilentReason::LowConfidence,
                    ConsensusRejection::LeapSecondSmear { .. }
                    | ConsensusRejection::SpreadTooHigh { .. }
                    | ConsensusRejection::NoCrossTierAgreement { .. } => {
                        SilentReason::SpreadTooHigh
                    }
                };
                update_status_silent(&mut status, &config, silent);
                sleep(Duration::from_secs(config.interval_s));
                continue;
            }
        };

        // g. Print consensus.
        print_consensus(&consensus);
        status.consensus_ms = Some(consensus.timestamp_ms);
        status.spread_ms = Some(consensus.spread_ms);
        status.confidence = Some(consensus.confidence);
        status.sources_bitmap = Some(consensus.sources_bitmap);

        // h. Dry-run early exit.
        if config.dry_run {
            update_status_dry_run(&mut status);
            sleep(Duration::from_secs(config.interval_s));
            continue;
        }

        // i. Rotation election (n=1 always returns true).
        let (my_turn, window_id, secs_to_next) =
            rotation_my_turn(my_index, n_oracles, config.interval_s);
        status.rotation_window_id = Some(window_id);
        status.rotation_is_my_turn = Some(my_turn);

        if !my_turn {
            update_status_silent(&mut status, &config, SilentReason::NotElected);
            let nap = secs_to_next.min(config.interval_s).max(1);
            sleep(Duration::from_secs(nap));
            continue;
        }

        if window_has_submission(status.last_submit_ts, config.interval_s) {
            // Already submitted in this window (process restart). Just sleep.
            let nap = secs_to_next.min(config.interval_s).max(1);
            sleep(Duration::from_secs(nap));
            continue;
        }

        // j. Outlier check vs SYSTEM clock (NOT chain clock — chain drifts ~14s).
        let local_now_ms = get_system_clock_ms();
        if (consensus.timestamp_ms - local_now_ms).abs() > 5000 {
            update_status_silent(&mut status, &config, SilentReason::TimestampOutlier);
            sleep(Duration::from_secs(config.interval_s));
            continue;
        }

        // Start the TSC stopwatch BEFORE the heavy chain pipeline (chain_time
        // RPC, blockhash RPC, optional stake recheck, TX build/sign). The
        // elapsed delta is added to consensus.timestamp_ms so the on-chain
        // instruction + memo reflect the moment the TX leaves the daemon, not
        // the moment NTP consensus completed ~100–2000 ms earlier. If the
        // pipeline takes longer than MAX_SPREAD_MS, we fall back to the raw
        // consensus time so the TX can never trip the contract's spread
        // budget.
        let consensus_time_ms = consensus.timestamp_ms;
        let tsc_anchor = Instant::now();

        // k. Best-effort chain time for memo.
        let chain_time_ms = rpc.get_chain_time_ms();

        // l. Recent blockhash.
        let blockhash = match rpc.get_recent_blockhash() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[blockhash] {e}");
                update_status_silent(&mut status, &config, SilentReason::NoHealthyRpc);
                sleep(Duration::from_secs(config.interval_s));
                continue;
            }
        };

        // l'. Daily recheck gate — if we're within ~1 h of the 24 h stake
        //     recheck deadline, fetch + filter stake accounts and attach them
        //     as remaining_accounts so the contract's mandatory recheck
        //     succeeds. Outside the window we pass an empty slice.
        let stake_accounts_for_tx: Vec<[u8; 32]> = if let Some(withdrawer) =
            authorized_withdrawer_opt
        {
            match rpc.fetch_operator(&operator_pda) {
                Ok(reg) => {
                    let current_slot = rpc
                        .get_epoch_info()
                        .map(|e| e.absolute_slot)
                        .unwrap_or(reg.last_stake_check_slot);
                    let slots_since = current_slot.saturating_sub(reg.last_stake_check_slot);
                    if slots_since > STAKE_CHECK_WARN_THRESHOLD_SLOTS {
                        match fetch_qualifying_stakes(&mut rpc, &vote_account, &withdrawer) {
                            Ok(stakes) => {
                                println!(
                                    "[recheck] attaching {} stake accounts (slots_since={})",
                                    stakes.len(),
                                    slots_since
                                );
                                stakes
                            }
                            Err(e) => {
                                eprintln!(
                                        "[recheck] cannot fetch stakes: {e} — submitting without; TX will fail if contract considers recheck due"
                                    );
                                Vec::new()
                            }
                        }
                    } else {
                        Vec::new()
                    }
                }
                Err(e) => {
                    eprintln!("[recheck] cannot fetch registration: {e}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // Measure elapsed since tsc_anchor. Anything over the contract's
        // MAX_SPREAD_MS budget triggers the safety fallback.
        let elapsed_ms = tsc_anchor.elapsed().as_millis() as i64;
        let precise_time_ms = apply_tsc_correction(consensus_time_ms, elapsed_ms);
        if elapsed_ms > MAX_SPREAD_MS {
            eprintln!(
                "[tsc] elapsed {elapsed_ms}ms > spread limit {MAX_SPREAD_MS}ms — using raw consensus time"
            );
        }

        // m. Build & sign.
        let params = SubmitParams {
            consensus: &consensus,
            window_id,
            memo_enabled: config.memo_enabled,
            chain_time_ms,
            precise_time_ms,
        };
        let tx = build_submit_transaction_signed(
            &hot_signer_keypair,
            &program_id,
            &oracle_pda,
            &operator_pda,
            &vote_account,
            &blockhash,
            &params,
            &stake_accounts_for_tx,
        );
        let tx_b64 = base64_encode(&tx);

        // n. Send.
        match rpc.send_transaction(&tx_b64) {
            Ok(sig) => {
                println!("✅ submit OK — tx: {sig}");
                update_status_ok(&mut status, &sig);
            }
            Err(e) => {
                eprintln!("❌ submit failed: {e}");
                status.last_error = Some(e);
                status.set_silent_reason(SilentReason::TxRejected);
                status.silent_cycles += 1;
                status.save();
                if status.silent_cycles == 3 || status.silent_cycles.is_multiple_of(10) {
                    if let Some(url) = &config.alert_webhook {
                        send_alert_webhook(
                            url,
                            &format!(
                                "x1-strontium: TX rejected for {} cycles in a row",
                                status.silent_cycles
                            ),
                        );
                    }
                }
            }
        }

        // o. Sleep.
        sleep(Duration::from_secs(config.interval_s));
    }
}

fn query_selected_sources(sources: &[ntp_client::NtpResult]) -> Vec<ntp_client::NtpResult> {
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel::<Option<ntp_client::NtpResult>>();
    let mut handles = Vec::with_capacity(sources.len());
    for src in sources {
        let host = src.host.clone();
        let tier = src.tier;
        let stratum = src.stratum;
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let res = ntp_client::query_ntp(&host, 123, tier, stratum);
            let _ = tx.send(res);
        }));
    }
    drop(tx);
    let collected: Vec<ntp_client::NtpResult> = rx.into_iter().flatten().collect();
    for h in handles {
        let _ = h.join();
    }
    collected
}

fn print_consensus(c: &ConsensusResult) {
    let secs = c.timestamp_ms / 1000;
    let ms = (c.timestamp_ms % 1000).unsigned_abs();
    println!(
        "[consensus] ts={}.{:03}s spread={}ms confidence={:.2} sources={} bitmap=0x{:016x} gps={}",
        secs, ms, c.spread_ms, c.confidence, c.sources_used, c.sources_bitmap, c.is_gps
    );
}

// ---------------------------------------------------------------------------
// Status update helpers
// ---------------------------------------------------------------------------

fn update_status_ok(status: &mut DaemonStatus, signature: &str) {
    let now = get_unix_secs();
    status.running = true;
    status.last_submit_ts = Some(now);
    status.last_submit_tx = Some(signature.to_string());
    status.last_error = None;
    status.silent_cycles = 0;
    status.silent_reason = None;
    status.save();
}

fn update_status_silent(
    status: &mut DaemonStatus,
    config: &X1StrontiumConfig,
    reason: SilentReason,
) {
    status.silent_cycles += 1;
    status.set_silent_reason(reason);
    status.save();
    if status.silent_cycles == 3 || status.silent_cycles.is_multiple_of(10) {
        if let Some(url) = &config.alert_webhook {
            send_alert_webhook(
                url,
                &format!(
                    "x1-strontium: silent for {} cycles ({})",
                    status.silent_cycles,
                    reason.label()
                ),
            );
        }
    }
}

fn update_status_dry_run(status: &mut DaemonStatus) {
    status.silent_cycles += 1;
    status.set_silent_reason(SilentReason::DryRun);
    status.save();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn readiness_check() {
    let url = "https://api.x1.xyz/v1/health";
    for attempt in 1..=READINESS_MAX_TRIES {
        match ureq::get(url).timeout(Duration::from_secs(5)).call() {
            Ok(resp) => {
                if let Ok(body) = resp.into_string() {
                    if body.contains("\"status\":\"ok\"") || body.contains("\"status\": \"ok\"") {
                        println!("[readiness] api.x1.xyz reports ok (attempt {attempt})");
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("[readiness] attempt {attempt}/{READINESS_MAX_TRIES}: {e}");
            }
        }
        sleep(Duration::from_secs(60));
    }
    eprintln!("[readiness] timed out — proceeding anyway");
}

/// HTTP POST to a Telegram/Discord/Slack-compatible webhook.
fn send_alert_webhook(url: &str, message: &str) {
    let body = serde_json::json!({ "text": message });
    if let Err(e) = ureq::post(url)
        .timeout(Duration::from_secs(8))
        .send_json(body)
    {
        eprintln!("[alert] webhook failed: {e}");
    }
}

/// Check whether a PID is alive and reachable by sending signal 0 — the
/// standard POSIX liveness probe. Returns false on ESRCH / EPERM / EINVAL.
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Return PIDs of every running `x1-strontium` process **except** our own.
/// Uses `pgrep -f x1-strontium` under the hood so the match is against the
/// full argv of each process. An empty Vec is returned if `pgrep` is
/// missing, errors out, or finds nothing (pgrep exits 1 on "no match").
fn list_other_daemon_pids() -> Vec<u32> {
    let current_pid = std::process::id();
    let Ok(output) = process::Command::new("pgrep")
        .args(["-f", "x1-strontium"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|&pid| pid != current_pid)
        .collect()
}

/// SIGTERM every PID in `pids`, poll for up to `grace_secs` seconds while
/// they shut down, then SIGKILL any stragglers. PIDs that are already gone
/// are silently skipped — this is the idiomatic kill-and-reap pattern.
fn kill_pids(pids: &[u32], grace_secs: u64) {
    if pids.is_empty() {
        return;
    }
    for &pid in pids {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(grace_secs);
    loop {
        let still: Vec<u32> = pids.iter().copied().filter(|&p| pid_alive(p)).collect();
        if still.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            for pid in still {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
            return;
        }
        sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_stop() {
    let mut status = DaemonStatus::load();
    if let Some(pid) = status.pid {
        unsafe {
            // SIGTERM = 15. Best-effort; ignore errors (process may already be dead).
            libc::kill(pid as i32, libc::SIGTERM);
        }
        println!("sent SIGTERM to pid {pid} (from status.json)");
    } else {
        println!("no pid recorded in status.json");
    }
    // Always sweep for any other `x1-strontium` processes, even when
    // status.json had a pid. Catches zombies left behind by crashes,
    // duplicate manual runs, or systemd restarts that never updated
    // status.json.
    let others = list_other_daemon_pids();
    if others.is_empty() {
        println!("no additional x1-strontium processes found");
    } else {
        println!(
            "found {} additional x1-strontium process(es): {others:?}",
            others.len()
        );
        kill_pids(&others, 3);
        println!("all x1-strontium processes terminated");
    }
    status.running = false;
    status.pid = None;
    status.save();
}

fn cmd_status() {
    let status = DaemonStatus::load();
    status.print();
}

fn cmd_sources() {
    let status = DaemonStatus::load();
    status.print_sources();
}

fn cmd_balance() {
    let config = X1StrontiumConfig::load();
    let keypair_path = match config.hot_signer_keypair_path.as_ref() {
        Some(p) => p,
        None => {
            eprintln!("config.hot_signer_keypair_path is not set");
            process::exit(1);
        }
    };
    let oracle_keypair = match load_keypair(keypair_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };
    let pubkey_b58 = bs58::encode(oracle_keypair.verifying_key().to_bytes()).into_string();
    let mut rpc = RpcClient::new(config.rpc_urls.clone());
    match rpc.get_balance(&pubkey_b58) {
        Ok(lamports) => {
            let bal = lamports_to_xnt(lamports);
            let runway = estimate_days_remaining(bal, config.interval_s);
            // Mirror estimate_days_remaining's assumptions for the banner.
            // Solo / no-rotation accounting: every window is mine, so this is
            // the conservative (worst-case) runway. With Prime+Sentinel
            // rotation each operator pays for half the windows → roughly 2x
            // the runway shown here.
            let tx_per_day = 86_400.0 / config.interval_s as f64;
            println!("oracle:  {pubkey_b58}");
            println!("balance: {bal:.3} XNT  (lamports {lamports})");
            println!(
                "runway:  ~{runway:.1} days  (@ {COST_PER_TX_XNT:.3} XNT × {tx_per_day:.0} TX/day)"
            );
        }
        Err(e) => {
            eprintln!("balance error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_config(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: x1-strontium config show | x1-strontium config set <key> <value>");
        process::exit(1);
    }
    match args[0].as_str() {
        "show" => X1StrontiumConfig::load().display(),
        "set" => {
            if args.len() != 3 {
                eprintln!("usage: x1-strontium config set <key> <value>");
                process::exit(1);
            }
            let mut c = X1StrontiumConfig::load();
            if let Err(e) = c.set(&args[1], &args[2]) {
                eprintln!("{e}");
                process::exit(1);
            }
            if let Err(e) = c.save() {
                eprintln!("{e}");
                process::exit(1);
            }
            println!("ok");
        }
        other => {
            eprintln!("unknown config subcommand: {other}");
            process::exit(1);
        }
    }
}

fn cmd_install() {
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot resolve current exe: {e}");
            process::exit(1);
        }
    };

    let bin_target = "/usr/local/bin/x1-strontium";
    let bin_tmp = "/usr/local/bin/x1-strontium.tmp";
    let symlink = "/usr/local/bin/x1sr";

    // If we're already running from the install target, skip the copy to
    // avoid ETXTBSY ("Text file busy") on Linux.
    let src_canon = std::fs::canonicalize(&exe).unwrap_or_else(|_| exe.clone());
    let dst_canon = std::fs::canonicalize(bin_target);
    let same_file = dst_canon.as_ref().is_ok_and(|d| *d == src_canon);

    if same_file {
        println!("binary already at {bin_target} — skipping copy");
    } else {
        // Atomic copy: write to a temporary file, then rename in place.
        // This avoids ETXTBSY when the target is currently being executed
        // by systemd (rename replaces the directory entry without opening
        // the running inode for writing).
        if let Err(e) = std::fs::copy(&exe, bin_tmp) {
            eprintln!("copy {exe:?} → {bin_tmp}: {e}");
            process::exit(1);
        }
        if let Err(e) = std::fs::rename(bin_tmp, bin_target) {
            eprintln!("rename {bin_tmp} → {bin_target}: {e}");
            let _ = std::fs::remove_file(bin_tmp);
            process::exit(1);
        }
        println!("binary installed: {bin_target}");
    }

    let _ = std::fs::remove_file(symlink);
    if let Err(e) = std::os::unix::fs::symlink(bin_target, symlink) {
        eprintln!("symlink {symlink}: {e}");
        process::exit(1);
    }

    let user = env::var("SUDO_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "nobody".to_string());
    let unit = format!(
        "\
[Unit]
Description=X1 Strontium time oracle daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin_target} start
Restart=on-failure
RestartSec=30
User={user}

[Install]
WantedBy=multi-user.target
"
    );
    let unit_path = "/etc/systemd/system/x1-strontium.service";
    if let Err(e) = std::fs::write(unit_path, &unit) {
        eprintln!("write {unit_path}: {e}");
        process::exit(1);
    }

    // Best-effort daemon-reload + enable — may fail if not running as root
    // or if systemd is not present (e.g. macOS dev box). Either way, the
    // binary and unit file are already in place.
    let _ = process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    let _ = process::Command::new("systemctl")
        .args(["enable", "x1-strontium"])
        .status();

    println!("installed:");
    println!("  binary:   {bin_target}");
    println!("  symlink:  {symlink}");
    println!("  systemd:  {unit_path}");
    println!("  user:     {user}");
    println!("next: sudo systemctl start x1-strontium");
}

fn cmd_uninstall() {
    let _ = std::fs::remove_file("/etc/systemd/system/x1-strontium.service");
    let _ = std::fs::remove_file("/usr/local/bin/x1sr");
    let _ = std::fs::remove_file("/usr/local/bin/x1-strontium");
    println!("removed: binary, symlink, systemd unit");
    println!("next:    sudo systemctl daemon-reload");
}

fn cmd_update() {
    // 1. Locate the git repo root by walking up from the *current working
    //    directory*. Using the binary's location (e.g. /usr/local/bin) is
    //    wrong — it isn't inside the repo. The user should run this from
    //    inside their checkout (typically ~/X1_Strontium).
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot get current directory: {e}");
            process::exit(1);
        }
    };
    let repo_root = match find_repo_root(&cwd) {
        Some(p) => p,
        None => {
            eprintln!("[update] not inside a git repo (cwd: {})", cwd.display());
            eprintln!("         run from X1_Strontium directory (or any subdirectory)");
            process::exit(1);
        }
    };
    println!("[update] repo: {repo_root}");

    // 2. git pull
    println!("[update] git pull ...");
    let pull = process::Command::new("git")
        .args(["-C", &repo_root, "pull"])
        .status();
    match pull {
        Ok(s) if s.success() => println!("[update] git pull ok"),
        Ok(s) => {
            eprintln!("[update] git pull failed (exit {})", s.code().unwrap_or(-1));
            process::exit(1);
        }
        Err(e) => {
            eprintln!("[update] git pull error: {e}");
            process::exit(1);
        }
    }

    // 3. cargo build --release  — must run as the original user so that
    //    `target/` and the registry cache stay in their `$HOME` (root's
    //    PATH won't even find cargo, and root's home would split the cache
    //    in two if it could). We resolve cargo from the original user's
    //    `~/.cargo/bin` and re-drop privileges via `sudo -u`.
    let cargo = find_cargo();
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "x1pio".to_string());
    println!("[update] cargo build --release -p x1-strontium-daemon  (as {user}, {cargo})");
    let build = process::Command::new("sudo")
        .arg("-u")
        .arg(&user)
        .arg(&cargo)
        .args(["build", "--release", "-p", "x1-strontium-daemon"])
        .current_dir(&repo_root)
        .status();
    match build {
        Ok(s) if s.success() => println!("[update] build ok"),
        Ok(s) => {
            eprintln!(
                "[update] cargo build failed (exit {})",
                s.code().unwrap_or(-1)
            );
            process::exit(1);
        }
        Err(e) => {
            eprintln!("[update] cargo build error: {e}");
            process::exit(1);
        }
    }

    // 4. Stop the running daemon
    println!("[update] stopping x1-strontium ...");
    let _ = process::Command::new("sudo")
        .args(["systemctl", "stop", "x1-strontium"])
        .status();

    // 5. Atomic binary swap: copy to .tmp, then rename over the live path.
    let built = format!("{repo_root}/target/release/x1-strontium");
    let bin_target = "/usr/local/bin/x1-strontium";
    let bin_tmp = "/usr/local/bin/x1-strontium.tmp";
    println!("[update] installing {built} → {bin_target}");
    if let Err(e) = std::fs::copy(&built, bin_tmp) {
        eprintln!("[update] copy → {bin_tmp}: {e}");
        process::exit(1);
    }
    if let Err(e) = std::fs::rename(bin_tmp, bin_target) {
        eprintln!("[update] rename {bin_tmp} → {bin_target}: {e}");
        let _ = std::fs::remove_file(bin_tmp);
        process::exit(1);
    }
    println!("[update] binary replaced");

    // 6. Start the daemon again
    println!("[update] starting x1-strontium ...");
    let _ = process::Command::new("sudo")
        .args(["systemctl", "start", "x1-strontium"])
        .status();
    println!("[update] done ✅");
}

// ---------------------------------------------------------------------------
// cmd_init — one-time `initialize` instruction for the Oracle State PDA
// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) {
    // Parse `--authority <path>` (defaults to config.hot_signer_keypair_path).
    let mut authority_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--authority" => {
                if i + 1 >= args.len() {
                    eprintln!("--authority requires a path");
                    process::exit(1);
                }
                authority_path = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                process::exit(1);
            }
        }
    }

    let config = X1StrontiumConfig::load();
    let kp_path = match authority_path.or_else(|| config.hot_signer_keypair_path.clone()) {
        Some(p) => p,
        None => {
            eprintln!(
                "[init] no authority keypair — pass --authority <path> or set \
                 `config.hot_signer_keypair_path`. Note: `init` creates the Oracle \
                 State PDA (X1 Strontium admin op) and is distinct from per-operator \
                 `initialize_operator` — the latter requires a Ledger, done via `solana` CLI."
            );
            process::exit(1);
        }
    };

    let authority = match load_keypair(&kp_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[init] {e}");
            process::exit(1);
        }
    };
    let auth_pubkey: [u8; 32] = authority.verifying_key().to_bytes();
    let auth_pubkey_b58 = bs58::encode(auth_pubkey).into_string();

    let mut program_id = [0u8; 32];
    match bs58::decode(&config.program_id).into_vec() {
        Ok(v) if v.len() == 32 => program_id.copy_from_slice(&v),
        _ => {
            eprintln!("[init] invalid program_id in config: {}", config.program_id);
            process::exit(1);
        }
    }

    let mut oracle_pda = [0u8; 32];
    match bs58::decode(&config.oracle_pda).into_vec() {
        Ok(v) if v.len() == 32 => oracle_pda.copy_from_slice(&v),
        _ => {
            eprintln!("[init] invalid oracle_pda in config: {}", config.oracle_pda);
            process::exit(1);
        }
    }

    // Local short-form helper for human-readable banners.
    let short = |s: &str| -> String {
        if s.len() <= 14 {
            s.to_string()
        } else {
            format!("{}...{}", &s[..8], &s[s.len() - 4..])
        }
    };

    println!("[init] Authority:  {}", short(&auth_pubkey_b58));
    println!("[init] Oracle PDA: {}", short(&config.oracle_pda));
    println!("[init] Program:    {}", short(&config.program_id));
    println!();
    println!("[init] Pre-flight:");
    println!("       Authority pubkey will pay for Oracle State rent (~0.06 XNT)");
    println!("       Expected Oracle PDA: {}", config.oracle_pda);
    println!("       If this PDA already exists, initialize() will fail");
    println!();
    println!("[init] Sending initialize() transaction...");

    let mut rpc = RpcClient::new(config.rpc_urls.clone());
    let blockhash = match rpc.get_recent_blockhash() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[init] blockhash error: {e}");
            process::exit(1);
        }
    };

    let tx = build_initialize_transaction(&authority, &program_id, &oracle_pda, &blockhash);
    let tx_b64 = base64_encode(&tx);

    match rpc.send_transaction(&tx_b64) {
        Ok(sig) => {
            println!("[init] ✅ Success — Signature: {sig}");
            println!("[init] Oracle State initialized:");
            println!("       n_operators:      0");
            println!("       quorum_threshold: 1 (auto from required_quorum)");
            println!("       ring_buffer:      empty (0 entries)");
        }
        Err(e) => {
            eprintln!("[init] ❌ failed: {e}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// cmd_read — decode the on-chain Oracle State PDA ring buffer
// ---------------------------------------------------------------------------
//
// Actual on-chain layout (see `programs/x1-strontium/src/lib.rs`).
// Anchor 0.30.1 with `AccountLoader<T>` for `zero_copy(unsafe)` accounts
// INCLUDES the 8-byte discriminator at the start of the raw account data
// returned by `getAccountInfo` — so every struct field's account offset =
// struct offset + 8.
//
//   discriminator        : bytes 0..8
//   OracleState struct   : bytes 8..9752
//     authority          : struct +0..32     -> account +8..40
//     bump               : struct +32        -> account +40
//     is_degraded        : struct +33        -> account +41
//     confidence_pct     : struct +34        -> account +42
//     _pad0 [5]          : struct +35..40    -> account +43..48
//     trusted_time_ms    : struct +40..48    -> account +48..56
//     last_updated_slot  : struct +48..56    -> account +56..64
//     spread_ms          : struct +56..64    -> account +64..72
//     window_start_slot  : struct +64..72    -> account +72..80
//     active_submitters  : struct +72..74    -> account +80..82
//     quorum_threshold   : struct +74..76    -> account +82..84
//     submission_count   : struct +76..78    -> account +84..86
//     ring_head  (u16 LE): struct +78..80    -> account +86..88
//     ring_count (u16 LE): struct +80..82    -> account +88..90
//     n_operators        : struct +82..84    -> account +90..92
//     _pad1 [4]          : struct +84..88    -> account +92..96
//     _pad_reserve [8]   : struct +88..96    -> account +96..104
//     submissions[6]     : struct +96..528   -> account +104..536   (6 × 72 B)
//     ring_buffer[288]   : struct +528..9744 -> account +536..9752  (288 × 32 B)
//
// Each RingEntry (32 bytes):
//   +0..8   trusted_time_ms i64 LE
//   +8..16  slot            u64 LE
//   +16     submitter_count u8
//   +17     confidence_pct  u8
//   +18..20 spread_ms       i16 LE
//   +20..24 _pad            (alignment)
//   +24..32 sources_bitmap  u64 LE

fn cmd_read(args: &[String]) {
    // Parse `--last N` (default 10).
    let mut n = 10usize;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--last" => {
                if i + 1 >= args.len() {
                    eprintln!("--last requires a number");
                    process::exit(1);
                }
                n = match args[i + 1].parse::<usize>() {
                    Ok(v) if v > 0 => v,
                    _ => {
                        eprintln!("--last: invalid number '{}'", args[i + 1]);
                        process::exit(1);
                    }
                };
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                process::exit(1);
            }
        }
    }

    let config = X1StrontiumConfig::load();
    let bytes = match fetch_oracle_account(&config) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read error: {e}");
            process::exit(1);
        }
    };

    const RING_SIZE: usize = 288;
    const RING_ENTRY: usize = 32;
    const HEAD_OFF: usize = 86;
    const COUNT_OFF: usize = 88;
    const RING_OFF: usize = 536;
    const NEEDED: usize = RING_OFF + RING_SIZE * RING_ENTRY;

    if bytes.len() < NEEDED {
        eprintln!(
            "account data too small: got {} bytes, expected ≥ {} for OracleState",
            bytes.len(),
            NEEDED
        );
        process::exit(1);
    }

    let head = u16::from_le_bytes([bytes[HEAD_OFF], bytes[HEAD_OFF + 1]]) as usize % RING_SIZE;
    let count = u16::from_le_bytes([bytes[COUNT_OFF], bytes[COUNT_OFF + 1]]) as usize;
    let to_show = n.min(count);

    println!();
    println!("X1 Strontium — Oracle Ring Buffer  (288 slots, ~24h history)");
    println!();
    println!("  #   │ UTC Time                   │ Spread │  Conf │ Slot");
    println!("──────┼────────────────────────────┼────────┼───────┼──────────────");

    let mut sum_spread: i64 = 0;
    let mut sum_conf: u32 = 0;
    let mut shown = 0usize;

    for j in 0..to_show {
        let idx = (head + RING_SIZE - 1 - j) % RING_SIZE;
        let off = RING_OFF + idx * RING_ENTRY;

        let ts_buf: [u8; 8] = bytes[off..off + 8].try_into().unwrap();
        let ts = i64::from_le_bytes(ts_buf);
        if ts == 0 {
            continue;
        }
        let slot_buf: [u8; 8] = bytes[off + 8..off + 16].try_into().unwrap();
        let slot = u64::from_le_bytes(slot_buf);

        let conf = bytes[off + 17];
        let spread = i16::from_le_bytes([bytes[off + 18], bytes[off + 19]]);

        let (date, time_str) = format_utc_ms(ts);
        println!("  {idx:>3} │ {date} {time_str:<11} │ {spread:>4} ms │ {conf:>4}% │ {slot}");

        sum_spread += spread as i64;
        sum_conf += conf as u32;
        shown += 1;
    }

    println!();
    if shown == 0 {
        println!("  (ring buffer empty — no aggregated submissions yet)");
    } else {
        let avg_spread = sum_spread as f64 / shown as f64;
        let avg_conf = sum_conf as f64 / shown as f64;
        println!(
            "  Entries: {shown}  │  Avg spread: {avg_spread:.1}ms  │  Avg confidence: {avg_conf:.0}%"
        );
    }
}

fn fetch_oracle_account(config: &X1StrontiumConfig) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            &config.oracle_pda,
            { "encoding": "base64", "commitment": "confirmed" }
        ]
    });
    let mut last_err = String::from("no RPC endpoints configured");
    for url in &config.rpc_urls {
        let resp: serde_json::Value = match ureq::post(url)
            .timeout(Duration::from_secs(10))
            .send_json(&body)
        {
            Ok(r) => match r.into_json() {
                Ok(v) => v,
                Err(e) => {
                    last_err = format!("{e}");
                    continue;
                }
            },
            Err(e) => {
                last_err = format!("{e}");
                continue;
            }
        };
        if let Some(val) = resp.pointer("/result/value") {
            if val.is_null() {
                return Err(format!(
                    "account {} does not exist on chain",
                    config.oracle_pda
                ));
            }
        }
        if let Some(s) = resp
            .pointer("/result/value/data/0")
            .and_then(|x| x.as_str())
        {
            return base64_decode(s).ok_or_else(|| "base64 decode failed".to_string());
        }
        last_err = format!("unexpected response shape: {resp}");
    }
    Err(last_err)
}

/// Minimal base64 decoder (standard alphabet). Ignores whitespace, accepts
/// trailing `=` padding. Returns `None` on invalid characters.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out: Vec<u8> = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        out.push((v0 << 2) | (v1 >> 4));
        if chunk.len() >= 3 && chunk[2] != b'=' {
            let v2 = b64_val(chunk[2])?;
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            if chunk.len() == 4 && chunk[3] != b'=' {
                let v3 = b64_val(chunk[3])?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }
    Some(out)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Format a millisecond timestamp into (date, `HH:MM:SS.mmm`) pair.
fn format_utc_ms(ts: i64) -> (String, String) {
    let secs = ts.div_euclid(1000);
    let ms = ts.rem_euclid(1000) as u64;
    let day_secs = secs.rem_euclid(86_400);
    let h = day_secs / 3600;
    let m = (day_secs / 60) % 60;
    let s = day_secs % 60;
    let days = secs.div_euclid(86_400);
    let (y, mon, d) = civil_from_days(days);
    (
        format!("{y:04}-{mon:02}-{d:02}"),
        format!("{h:02}:{m:02}:{s:02}.{ms:03}"),
    )
}

/// Days since 1970-01-01 → `(year, month 1-12, day 1-31)`.
/// Howard Hinnant's public-domain civil_from_days algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mon <= 2 { y + 1 } else { y };
    (y, mon as u32, d as u32)
}

/// Walk up from `start` looking for a `.git` directory (or file — git
/// worktrees use a `.git` *file* pointing at the worktree's gitdir). Returns
/// the absolute path of the first ancestor that contains it, or `None` if we
/// reach the filesystem root without finding one.
fn find_repo_root(start: &std::path::Path) -> Option<String> {
    let mut cur = start.to_path_buf();
    loop {
        if cur.join(".git").exists() {
            return Some(cur.display().to_string());
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// Locate a `cargo` binary that the original (pre-sudo) user can run. Under
/// `sudo` the secure_path stripped `$HOME/.cargo/bin` from `PATH`, so a bare
/// "cargo" lookup would fail. We probe the SUDO_USER's home first, then
/// `$HOME`, and finally fall back to the bare name (let exec resolve it).
fn find_cargo() -> String {
    if let Ok(user) = std::env::var("SUDO_USER") {
        let path = format!("/home/{user}/.cargo/bin/cargo");
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let path = format!("{home}/.cargo/bin/cargo");
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }
    "cargo".to_string()
}

// ---------------------------------------------------------------------------
// Off-chain self-stake helpers (shared by the main loop)
// ---------------------------------------------------------------------------

/// Fetch every stake account delegated to `vote_pubkey`, filter the way the
/// on-chain `initialize_operator` / `submit_time` daily recheck filters, and
/// sum the lamports. Returns 0 if RPC fetch fails or there are no qualifying
/// stakes (caller decides whether that's an alert condition).
fn compute_self_stake_off_chain(
    rpc: &mut RpcClient,
    vote_pubkey: &[u8; 32],
    authorized_withdrawer: &[u8; 32],
) -> Result<u64, String> {
    let stakes = rpc.fetch_stake_accounts_for_vote(vote_pubkey)?;
    let epoch = rpc.get_epoch_info()?.epoch;
    let total: u64 = stakes
        .iter()
        .filter(|s| s.voter == *vote_pubkey)
        .filter(|s| s.withdrawer == *authorized_withdrawer)
        .filter(|s| epoch.saturating_sub(s.activation_epoch) >= 2)
        .filter(|s| s.deactivation_epoch == u64::MAX)
        .map(|s| s.stake_amount)
        .sum();
    Ok(total)
}

/// Same filtering as `compute_self_stake_off_chain` but returns the pubkeys
/// of the qualifying stake accounts — the list the daemon attaches as
/// `remaining_accounts` on the daily-recheck TX.
fn fetch_qualifying_stakes(
    rpc: &mut RpcClient,
    vote_pubkey: &[u8; 32],
    authorized_withdrawer: &[u8; 32],
) -> Result<Vec<[u8; 32]>, String> {
    let stakes = rpc.fetch_stake_accounts_for_vote(vote_pubkey)?;
    let epoch = rpc.get_epoch_info()?.epoch;
    Ok(stakes
        .into_iter()
        .filter(|s| s.voter == *vote_pubkey)
        .filter(|s| s.withdrawer == *authorized_withdrawer)
        .filter(|s| epoch.saturating_sub(s.activation_epoch) >= 2)
        .filter(|s| s.deactivation_epoch == u64::MAX)
        .map(|s| s.pubkey)
        .collect())
}

// ---------------------------------------------------------------------------
// Wall-clock window alignment
// ---------------------------------------------------------------------------

/// Pure math: how many milliseconds to sleep so we wake up at the next
/// `interval_ms` boundary. If `now_ms` is already exactly on a boundary,
/// we still sleep the FULL interval (returning 0 would burn a window).
fn next_boundary_sleep_ms(now_ms: u64, interval_ms: u64) -> u64 {
    debug_assert!(interval_ms > 0, "interval must be > 0");
    let next_boundary_ms = ((now_ms / interval_ms) + 1) * interval_ms;
    next_boundary_ms - now_ms
}

/// Sleep until the next wall-clock window boundary at the configured
/// interval. After this, every cycle ends with a `sleep(interval_s)` so
/// the alignment is preserved (modulo per-cycle drift, which is small).
fn wait_until_next_window_boundary(interval_s: u64) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let interval_ms = interval_s.saturating_mul(1000).max(1);
    let sleep_ms = next_boundary_sleep_ms(now_ms, interval_ms);
    println!(
        "[align] waiting {}s {}ms for next wall-clock window boundary",
        sleep_ms / 1000,
        sleep_ms % 1000
    );
    sleep(Duration::from_millis(sleep_ms));
}

// ---------------------------------------------------------------------------
// TSC-corrected timestamp pure function
// ---------------------------------------------------------------------------

/// Add `elapsed_ms` to `consensus_ms` to get the timestamp the TX should
/// commit. If the elapsed time exceeds the contract's spread budget
/// (MAX_SPREAD_MS), fall back to the raw consensus value rather than risk
/// the contract rejecting the submission for being out of bounds.
fn apply_tsc_correction(consensus_ms: i64, elapsed_ms: i64) -> i64 {
    if (0..=MAX_SPREAD_MS).contains(&elapsed_ms) {
        consensus_ms + elapsed_ms
    } else {
        consensus_ms
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Bug #1 tripwire: self-stake threshold ----------

    /// If someone changes the on-chain contract's `MIN_SELF_STAKE_LAMPORTS`
    /// (currently 128 XNT) without updating this daemon's off-chain
    /// early-warning threshold to match, the daemon would let operators
    /// quietly drift below the on-chain floor and silently fail their next
    /// 24 h stake recheck. This test locks the daemon-side value to the
    /// literal 128 × 1e9 lamports. Keep in sync with
    /// `programs/x1-strontium/src/lib.rs` `MIN_SELF_STAKE_LAMPORTS`.
    #[test]
    fn min_self_stake_matches_contract_value() {
        assert_eq!(MIN_SELF_STAKE_LAMPORTS, 128_000_000_000);
        assert_eq!(MIN_SELF_STAKE_LAMPORTS, 128 * 1_000_000_000);
    }

    // ---------- next_boundary_sleep_ms math ----------

    #[test]
    fn next_boundary_math_at_various_times() {
        let interval_ms = 300_000; // 5 min

        // Exactly on a boundary → sleep the full interval (NOT zero — that
        // would let the daemon burn a window doing nothing).
        assert_eq!(next_boundary_sleep_ms(0, interval_ms), 300_000);
        assert_eq!(next_boundary_sleep_ms(300_000, interval_ms), 300_000);
        assert_eq!(next_boundary_sleep_ms(900_000, interval_ms), 300_000);

        // 1 ms after a boundary → almost the full interval.
        assert_eq!(next_boundary_sleep_ms(1, interval_ms), 299_999);
        assert_eq!(next_boundary_sleep_ms(300_001, interval_ms), 299_999);

        // 1 ms before a boundary → 1 ms sleep.
        assert_eq!(next_boundary_sleep_ms(299_999, interval_ms), 1);

        // Mid-window.
        assert_eq!(next_boundary_sleep_ms(150_000, interval_ms), 150_000);
        assert_eq!(next_boundary_sleep_ms(450_000, interval_ms), 150_000);

        // Different interval (60 s).
        assert_eq!(next_boundary_sleep_ms(0, 60_000), 60_000);
        assert_eq!(next_boundary_sleep_ms(45_000, 60_000), 15_000);
    }

    // ---------- apply_tsc_correction logic ----------

    #[test]
    fn tsc_correction_within_budget_adds_elapsed() {
        // 30 ms elapsed, budget 50 ms → add it.
        assert_eq!(apply_tsc_correction(1_000, 30), 1_030);
        assert_eq!(
            apply_tsc_correction(1_713_184_500_000, 17),
            1_713_184_500_017
        );
    }

    #[test]
    fn tsc_correction_at_exactly_budget_still_adds() {
        // Boundary case: elapsed == MAX_SPREAD_MS → add (only > triggers fallback).
        assert_eq!(apply_tsc_correction(1_000, 50), 1_050);
    }

    #[test]
    fn tsc_correction_above_budget_falls_back() {
        // 100 ms elapsed > 50 ms budget → use raw consensus.
        assert_eq!(apply_tsc_correction(1_000, 100), 1_000);
        assert_eq!(
            apply_tsc_correction(1_713_184_500_000, 9_999),
            1_713_184_500_000
        );
    }

    #[test]
    fn tsc_correction_negative_elapsed_falls_back() {
        // Wall-clock skew or NTP step could in theory produce a negative
        // elapsed reading from Instant::now().elapsed() (very rare). Belt
        // and braces: don't subtract from the consensus timestamp.
        assert_eq!(apply_tsc_correction(1_000, -10), 1_000);
    }

    #[test]
    fn tsc_elapsed_precision_via_real_sleep() {
        // Smoke test that Instant::now() actually measures real time.
        // Sleep 150 ms, accept 150–200 ms (CI / scheduler jitter).
        let anchor = Instant::now();
        std::thread::sleep(Duration::from_millis(150));
        let elapsed = anchor.elapsed().as_millis() as i64;
        assert!(
            (150..=200).contains(&elapsed),
            "expected elapsed ~150 ms, got {elapsed} ms"
        );
    }
}
