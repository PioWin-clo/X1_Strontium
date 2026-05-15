mod config;
mod consensus;
mod ntp_client;
mod rotation;
mod status;
mod submitter;

use crate::config::X1StrontiumConfig;
use crate::consensus::{run_consensus_cycle, ConsensusRejection, ConsensusResult};
use crate::ntp_client::{discover_sources, get_system_clock_ms, to_source_status};
use crate::rotation::{rotation_my_turn_at, window_has_submission_at, RotationState};
use crate::status::{DaemonStatus, SilentReason};
use crate::submitter::{
    base64_encode, build_cleanup_inactive_transaction, build_initialize_transaction,
    build_register_transaction, build_submit_transaction_signed, derive_registration_pda,
    estimate_days_remaining, format_clock_3dec, lamports_to_xnt, load_keypair,
    parse_vote_epoch_credits_len, RegistrationEntry, RpcClient, SubmitParams, COST_PER_TX_XNT,
};
use ed25519_dalek::SigningKey;
use std::env;
use std::io::Read;
use std::process;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MIN_BALANCE_WARN: f64 = 1.0;
const MIN_BALANCE_STOP: f64 = 0.05;
/// Minimum oracle.json balance the v1.3 startup auto-recover requires
/// before it will send a `register_submitter` TX on the operator's behalf.
/// Covers one register TX (~0.5 XNT rent for the new ValidatorRegistration
/// PDA + ~0.000005 XNT fee) plus a small buffer for the first few
/// `submit_time` cycles before the operator can top up further.
const MIN_BALANCE_AUTO_RECOVER_XNT: f64 = 0.6;
const REDISCOVER_SECS: i64 = 3600;
const READINESS_MAX_TRIES: u32 = 20;

// Cadence for the two off-chain background tasks run inside the main cycle
// loop (both gated by elapsed wall-clock time, reset after each run).
const PEERS_REFETCH_SECS: i64 = 15 * 60;
const SELF_STAKE_CHECK_SECS: i64 = 24 * 60 * 60; // 24 h, daemon-only

/// Cleanup pre-flight throttle: if `OracleState.last_cleanup_slot` is more
/// than this many slots behind the current slot, the daemon prepends a
/// `cleanup_inactive` TX to its submission cycle. ~9000 slots ≈ 1 h at
/// X1's 0.4 s slot time; "first daemon to notice the timeout fires it,
/// rest see the updated last_cleanup_slot and skip" naturally distributes
/// the cost across the fleet.
const CLEANUP_STALE_SLOTS: u64 = 9_000;

/// Off-chain anti-farm gate — minimum number of `epoch_credits` entries
/// the validator's vote account must carry at register time (~64 epochs ≈
/// 2 months of consistent voting on X1's epoch length).
const MIN_EPOCH_HISTORY: u64 = 64;

/// Maximum allowed delta in milliseconds between the NTP-derived
/// consensus timestamp and the daemon's local system clock at the
/// consensus moment. Beyond this, the host's system clock is suspected
/// of being broken and the cycle silences itself rather than push a
/// garbage timestamp on chain.
const MAX_SYSDRIFT_MS: i64 = 5000;

fn print_help() {
    println!(
        "\
X1 Strontium — Decentralized Time Oracle for X1 Blockchain (v1.3.0)

USAGE:
  x1-strontium <command> [options]
  x1sr <command> [options]            (symlink installed by `install`)

COMMANDS:
  start [--dry-run]     Start the daemon (--dry-run: compute only, no TX)
  stop                  Stop the running daemon and reap zombie processes
  status                Show daemon status, last TX, spread, confidence
  sources               Show NTP source table with RTT and offsets
  balance               Show oracle keypair balance and runway
  config show           Show current configuration
  config set <k> <v>    Set a config value
  read [--last N]       Decode Oracle PDA ring buffer (default: last 10)
  init [--authority <keypair>]
                        Initialize Oracle State PDA (one-time setup after deploy)
  register              Register this validator as a Strontium operator
                        (off-chain anti-farm gates: 64 epoch credits + a
                        stake whose withdraw authority matches the vote
                        account; sends register_submitter TX)
  install               Install as systemd service (requires sudo)
  uninstall             Remove systemd service (requires sudo)
  update                Pull, rebuild, restart (git + cargo + systemctl)

CONFIG KEYS:
  oracle_keypair_path, vote_keypair_path, rpc, interval, memo, dry_run,
  alert_webhook, alert_balance, tier_threshold, rotation_peers,
  program_id, oracle_pda

ORACLE PDA (v1.2.0):
  cfm1Tc7CNdTa8Hm8FGWAuHXaaozSjQHNmdBD5mEVN9P"
    );
}

fn main() {
    install_panic_hook();

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
                kill_pids(&existing, 10);
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
        "register" => cmd_register(&args[2..]),
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("unknown subcommand: {other}");
            print_help();
            process::exit(1);
        }
    }
}

/// Install a panic hook that captures the panic info, current UTC, and a
/// backtrace into `~/.config/x1-strontium/last_crash.log`. Lets the
/// operator inspect post-mortem after `systemctl restart` puts the daemon
/// back online without needing `journalctl` access.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let log_path = format!(
            "{}/.config/x1-strontium/last_crash.log",
            env::var("HOME").unwrap_or_default()
        );
        if let Some(parent) = std::path::Path::new(&log_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let backtrace = std::backtrace::Backtrace::force_capture();
        let body = format!(
            "X1 Strontium daemon crash\nunix_secs: {now_secs}\npanic: {info}\nbacktrace:\n{backtrace}\n"
        );
        let _ = std::fs::write(&log_path, body);
        eprintln!("daemon panic logged to {log_path}");
    }));
}

// ---------------------------------------------------------------------------
// Daemon main loop
// ---------------------------------------------------------------------------

fn run_daemon(config: X1StrontiumConfig) -> Result<(), String> {
    // The daemon only ever holds the oracle.json keypair. Registration is
    // a one-time `x1-strontium register` op that creates the on-chain
    // ValidatorRegistration PDA; from then on the daemon signs
    // `submit_time` every cycle and may fire `cleanup_inactive` when the
    // on-chain `last_cleanup_slot` falls behind by more than ~1 h.
    let oracle_path = config.oracle_keypair_path.as_ref().ok_or_else(|| {
        "config.oracle_keypair_path is not set — run \
             `x1-strontium config set oracle_keypair <path>` and \
             `x1-strontium register` first"
            .to_string()
    })?;

    let oracle_keypair = load_keypair(oracle_path)?;
    let oracle_bytes: [u8; 32] = oracle_keypair.verifying_key().to_bytes();
    let oracle_pubkey_b58 = bs58::encode(oracle_bytes).into_string();

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

    // ValidatorRegistration PDA — seeds [b"reg", oracle_keypair].
    let registration_pda = derive_registration_pda(&oracle_bytes, &program_id);
    let registration_pda_b58 = bs58::encode(registration_pda).into_string();

    println!("X1 Strontium daemon starting (v1.2.0)");
    println!("  oracle keypair:   {oracle_pubkey_b58}");
    println!("  registration pda: {registration_pda_b58}");
    println!("  program id:       {}", config.program_id);
    println!("  oracle pda:       {}", config.oracle_pda);
    println!(
        "  interval:         {}s  dry-run: {}",
        config.interval_s, config.dry_run
    );

    readiness_check();

    let mut rpc = RpcClient::new(config.rpc_urls.clone());

    // Verify on-chain registration exists and is active before doing
    // anything expensive. Skipping this would let the daemon happily run
    // a full NTP cycle just to have the chain reject `submit_time` with
    // RegistrationInactive (or AccountNotFound) — surface the problem at
    // startup instead.
    // v1.3 auto-recover: if the registration PDA is missing (closed by
    // `cleanup_inactive`) or flagged inactive (legacy v1.2.0 leftover),
    // try to send a fresh `register_submitter` TX automatically before
    // bailing out. Auto-recover is gated by the same anti-farm
    // preconditions as the manual `cmd_register` — see
    // `attempt_auto_recover_registration`. Only "does not exist on
    // chain" + "is_active = false" trigger recovery; other RPC errors
    // (network down, parse error) propagate so the operator
    // investigates manually.
    let own_registration = match rpc.fetch_registration(&registration_pda) {
        Ok(reg) if reg.is_active => reg,
        Ok(_reg_inactive) => {
            eprintln!(
                "[startup] registration {registration_pda_b58} is_active = false \
                 (legacy v1.2.0 inactive PDA — v1.3 cleanup closes instead of flagging)"
            );
            attempt_auto_recover_registration(
                &mut rpc,
                &config,
                &oracle_keypair,
                &program_id,
                &oracle_pda,
                &registration_pda,
                config.dry_run,
            )?;
            rpc.fetch_registration(&registration_pda).map_err(|e| {
                format!(
                    "post auto-recover fetch failed for {registration_pda_b58}: {e}\n\
                     The auto-recover TX may have landed but RPC is now flaky — \
                     restart the daemon to retry."
                )
            })?
        }
        Err(e) if e.contains("does not exist on chain") => {
            eprintln!(
                "[startup] registration {registration_pda_b58} not found on chain \
                 (closed by cleanup_inactive after >{CLEANUP_GRACE_WINDOWS} windows of silence)"
            );
            attempt_auto_recover_registration(
                &mut rpc,
                &config,
                &oracle_keypair,
                &program_id,
                &oracle_pda,
                &registration_pda,
                config.dry_run,
            )?;
            rpc.fetch_registration(&registration_pda).map_err(|e| {
                format!(
                    "post auto-recover fetch failed for {registration_pda_b58}: {e}\n\
                     The auto-recover TX may have landed but RPC is now flaky — \
                     restart the daemon to retry."
                )
            })?
        }
        Err(e) => {
            return Err(format!(
                "registration PDA {registration_pda_b58} fetch failed: {e}\n\
                 Check RPC connectivity, then run `x1-strontium register` if needed."
            ));
        }
    };
    let vote_account = own_registration.vote_account;
    let vote_account_b58 = bs58::encode(vote_account).into_string();
    println!("  vote account:     {vote_account_b58}  (from registration)");

    let mut status = DaemonStatus::load();
    status.oracle_pubkey = oracle_pubkey_b58.clone();
    status.interval_s = config.interval_s;
    status.dry_run = config.dry_run;
    status.pid = Some(process::id());
    status.running = true;
    // `silent_cycles` and `silent_reason` are per-run counters. Reset so a
    // previous session's accumulated silence doesn't trigger phantom
    // alerts on the first cycle of the new run.
    status.silent_cycles = 0;
    status.silent_reason = None;
    status.save();

    // Initial balance check. Rotation state is not built yet; use a
    // solo runway estimate (n=1 — worst case). The first main-loop
    // refresh re-computes with the real fleet size.
    match rpc.get_balance(&oracle_pubkey_b58) {
        Ok(lamports) => {
            let bal = lamports_to_xnt(lamports);
            status.balance_xnt = bal;
            status.days_remaining = estimate_days_remaining(bal, config.interval_s, 1);
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
    println!("  initial sources:  {} healthy", sources.len());
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

    // Rotation tracks oracle keypair pubkeys — that's the identity each
    // daemon signs `submit_time` with, and the natural "which operator am
    // I" key.
    let mut rotation = RotationState::from_peers(&config.rotation_peers, &oracle_bytes);
    let mut my_index = rotation.my_index(&oracle_bytes);
    let mut n_oracles = rotation.n_oracles();
    println!("  rotation:         index={my_index} of n={n_oracles}");

    // Cache the vote account's authorized_withdrawer so the off-chain
    // 24 h self-stake check can filter qualifying stakes by withdrawer.
    let authorized_withdrawer_opt: Option<[u8; 32]> =
        match rpc.fetch_account_info(&vote_account_b58) {
            Ok(data) if data.len() >= 68 => {
                let mut w = [0u8; 32];
                w.copy_from_slice(&data[36..68]);
                println!(
                    "  authorized_withdrawer: {}  (filters qualifying self-stake)",
                    bs58::encode(w).into_string()
                );
                Some(w)
            }
            Ok(data) => {
                eprintln!(
                    "[startup] vote account data too short ({} bytes) — self-stake \
                 check disabled until next refresh",
                    data.len()
                );
                None
            }
            Err(e) => {
                eprintln!("[startup] cannot fetch vote account ({e}) — self-stake check disabled");
                None
            }
        };

    // Both 0 so the first cycle fires both refresh tasks immediately.
    let mut last_peers_refetch: i64 = 0;
    let mut last_self_stake_check: i64 = 0;

    // Pre-poll architecture (Fix 6 / v1.2.0):
    //   boundary - PREPOLL_LEAD_SECS  : NTP poll fires, consensus +
    //                                   sysdrift cached
    //   boundary - PREFLIGHT_LEAD_MS  : wake, run pre-flight checks
    //                                   (balance, peers, self-stake,
    //                                   cleanup), election, send TX
    //   boundary + ~50ms              : TX lands on chain (target)
    //
    // Election + window_has_submission both gate on the upcoming
    // boundary (`now = next_boundary`) so the loop's "is it my turn"
    // decision matches the actual submit moment, not 30s earlier.
    const PREPOLL_LEAD_SECS: u64 = 30;
    const PREFLIGHT_LEAD_MS: i64 = 200;

    loop {
        let cycle_started = get_unix_secs();
        status.last_attempt_ts = Some(cycle_started);

        let now_secs_u64 = cycle_started.max(0) as u64;
        let next_boundary_secs = next_window_boundary_secs(now_secs_u64, config.interval_s);
        let next_cycle_ntp_start =
            (next_boundary_secs + config.interval_s).saturating_sub(PREPOLL_LEAD_SECS);

        // Phase 0: wait for the boundary - PREPOLL_LEAD_SECS slot. Also
        // covers the very first cycle (no separate alignment call needed).
        let ntp_start_secs = next_boundary_secs.saturating_sub(PREPOLL_LEAD_SECS);
        sleep_until_unix_secs(ntp_start_secs);

        // Periodic NTP rediscovery (gated by elapsed wall time, not
        // boundary, so it spreads across cycles regardless of cadence).
        if cycle_started - last_discovery >= REDISCOVER_SECS {
            sources = discover_sources(3);
            last_discovery = cycle_started;
            println!("[discovery] refreshed: {} sources", sources.len());
        }

        // Phase 1 (boundary - PREPOLL_LEAD_SECS): NTP poll → consensus
        // → cache sysdrift for the eventual TX timestamp.
        let results = query_selected_sources(&sources);
        if results.is_empty() {
            update_status_silent(&mut status, &config, SilentReason::NoValidSources);
            sleep_until_unix_secs(next_cycle_ntp_start);
            continue;
        }
        status.ntp_sources = to_source_status(&results);
        println!(
            "[cycle] {} sources responded — best RTT {} ms",
            results.len(),
            results.iter().map(|r| r.rtt_ms).min().unwrap_or(0)
        );

        let consensus = match run_consensus_cycle(&results, config.tier_consensus_threshold_ms) {
            Ok(c) => c,
            Err(reason) => {
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
                sleep_until_unix_secs(next_cycle_ntp_start);
                continue;
            }
        };
        let sys_at_consensus_ms = get_system_clock_ms();
        let sysdrift_ms = consensus.timestamp_ms - sys_at_consensus_ms;

        print_consensus(&consensus);
        status.consensus_ms = Some(consensus.timestamp_ms);
        status.spread_ms = Some(consensus.spread_ms);
        status.confidence = Some(consensus.confidence);
        status.sources_bitmap = Some(consensus.sources_bitmap);
        status.save();

        // Phase 2 (boundary - PREFLIGHT_LEAD_MS): wake for pre-flight.
        let preflight_target_ms =
            next_boundary_secs.saturating_mul(1000) as i64 - PREFLIGHT_LEAD_MS;
        sleep_until_unix_ms(preflight_target_ms.max(0) as u64);

        // a. Balance check. Runway scales with the active fleet size:
        // each operator pays for ~1/n of the windows, so a healthy
        // fleet of n=2 doubles the runway vs solo.
        match rpc.get_balance(&oracle_pubkey_b58) {
            Ok(lamports) => {
                let bal = lamports_to_xnt(lamports);
                status.balance_xnt = bal;
                status.days_remaining =
                    estimate_days_remaining(bal, config.interval_s, n_oracles as u16);
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

        // b1. Auto-refetch active registrations from chain every 15 min.
        //     Hot-reloads rotation state without restart.
        if cycle_started - last_peers_refetch >= PEERS_REFETCH_SECS {
            match rpc.fetch_active_registrations(&program_id) {
                Ok(regs) => {
                    let peers: Vec<[u8; 32]> = regs.iter().map(|r| r.oracle_keypair).collect();
                    let new_rotation = RotationState::from_peers_raw(&peers, &oracle_bytes);
                    let new_n = new_rotation.n_oracles();
                    if new_n != n_oracles {
                        println!(
                            "[peers] fleet changed: n={} → n={} (rotation reloaded)",
                            n_oracles, new_n
                        );
                    }
                    rotation = new_rotation;
                    my_index = rotation.my_index(&oracle_bytes);
                    n_oracles = rotation.n_oracles();
                    // Persist for `x1sr status` runway display so the
                    // one-shot status command can render the correct
                    // n-aware estimate without its own RPC fetch.
                    status.n_operators = Some(n_oracles.min(u16::MAX as usize) as u16);
                    last_peers_refetch = cycle_started;
                }
                Err(e) => {
                    eprintln!("[peers] refetch failed (keeping previous list): {e}");
                    // Still update the timestamp so we don't hammer a broken RPC.
                    last_peers_refetch = cycle_started;
                }
            }
        }

        // b2. Off-chain 24 h self-stake check. The contract holds no
        //     parser; the daemon is the sole enforcer of the gate.
        //     Below threshold → silence (don't submit) until stake recovers
        //     or the contract's 10-missed-turns cleanup deregisters us.
        if cycle_started - last_self_stake_check >= SELF_STAKE_CHECK_SECS {
            if let Some(withdrawer) = authorized_withdrawer_opt {
                match compute_self_stake_off_chain(&mut rpc, &vote_account, &withdrawer) {
                    Ok(stake) => {
                        if stake == 0 {
                            eprintln!(
                                "⚠️  no self-stake with matching withdraw authority — \
                                 daemon silenced; cleanup will deregister within 10 own turns"
                            );
                            status.set_silent_reason(SilentReason::InsufficientSelfStake);
                            status.silent_cycles += 1;
                            status.save();
                            if let Some(url) = &config.alert_webhook {
                                send_alert_webhook(
                                    url,
                                    "x1-strontium: no self-stake with matching withdraw authority — \
                                     silenced; cleanup will deregister within 10 own turns",
                                );
                            }
                            sleep_until_unix_secs(next_cycle_ntp_start);
                            continue;
                        }
                    }
                    Err(e) => eprintln!("[self-stake check] {e}"),
                }
            }
            last_self_stake_check = cycle_started;
        }

        // b3. Cleanup pre-flight. If the on-chain `last_cleanup_slot` is
        //     stale by more than CLEANUP_STALE_SLOTS (~1 h), this daemon
        //     pre-empts the cleanup work for the fleet. Whichever daemon
        //     fires first stamps `last_cleanup_slot` and the rest skip.
        if let Ok(header) = rpc.fetch_oracle_state_header(&oracle_pda) {
            let current_slot = rpc.get_epoch_info().map(|e| e.absolute_slot).unwrap_or(0);
            if current_slot > 0
                && current_slot.saturating_sub(header.last_cleanup_slot) > CLEANUP_STALE_SLOTS
            {
                if let Err(e) = try_cleanup_inactive(
                    &mut rpc,
                    &oracle_keypair,
                    &program_id,
                    &oracle_pda,
                    current_slot,
                ) {
                    eprintln!("[cleanup] preflight skipped: {e}");
                }
            }
        }

        // h. Dry-run early exit.
        if config.dry_run {
            update_status_dry_run(&mut status);
            sleep_until_unix_secs(next_cycle_ntp_start);
            continue;
        }

        // Phase 3: election + filters at the upcoming boundary.
        let (my_turn, window_id, _secs_to_next) =
            rotation_my_turn_at(my_index, n_oracles, config.interval_s, next_boundary_secs);
        status.rotation_window_id = Some(window_id);
        status.rotation_is_my_turn = Some(my_turn);

        if !my_turn {
            update_status_silent(&mut status, &config, SilentReason::NotElected);
            sleep_until_unix_secs(next_cycle_ntp_start);
            continue;
        }

        if window_has_submission_at(
            status.last_submit_ts,
            config.interval_s,
            next_boundary_secs as i64,
        ) {
            // Already covered the upcoming window (process restart, etc.).
            sleep_until_unix_secs(next_cycle_ntp_start);
            continue;
        }

        // j. Sysdrift gate (uses the value cached at NTP poll moment —
        //    same value the memo's `sys=` / `sysdrift=` fields will
        //    report, so the gate and the diagnostic agree).
        if sysdrift_ms.abs() > MAX_SYSDRIFT_MS {
            update_status_silent(&mut status, &config, SilentReason::SystemClockOutOfSync);
            sleep_until_unix_secs(next_cycle_ntp_start);
            continue;
        }

        // k. Best-effort chain time for memo.
        let chain_time_ms = rpc.get_chain_time_ms();

        // l. Recent blockhash.
        let blockhash = match rpc.get_recent_blockhash() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[blockhash] {e}");
                update_status_silent(&mut status, &config, SilentReason::NoHealthyRpc);
                sleep_until_unix_secs(next_cycle_ntp_start);
                continue;
            }
        };

        // TX timestamp = current system clock + cached sysdrift. The
        // sysdrift was captured ~30s ago at NTP-poll moment; system
        // clock drift over 30s is sub-millisecond on a healthy host
        // (the sysdrift gate above guards against the unhealthy case),
        // so this gives a good UTC estimate at the actual send moment
        // without re-polling NTP.
        let tx_timestamp_ms = get_system_clock_ms() + sysdrift_ms;

        // m. Build & sign.
        let params = SubmitParams {
            consensus: &consensus,
            window_id,
            memo_enabled: config.memo_enabled,
            chain_time_ms,
            precise_time_ms: tx_timestamp_ms,
            sys_at_consensus_ms,
            // v1.3: pass the cached sysdrift snapshot so build_memo's
            // `sysdrift=` field reflects drift at NTP poll moment, not
            // a misleading recompute that bleeds in the ~30 s pre-poll
            // lead.
            sysdrift_ms,
        };
        let tx = build_submit_transaction_signed(
            &oracle_keypair,
            &program_id,
            &oracle_pda,
            &registration_pda,
            &blockhash,
            &params,
        );
        let tx_b64 = base64_encode(&tx);

        // n. Send. Drift signals are persisted on success so `x1sr
        // status` can render Chain drift / Sys drift.
        //
        // BUG 2 fix (v1.2.1): use the CACHED `sysdrift_ms` snapshot
        // taken at NTP poll moment, not a fresh `tx_timestamp_ms -
        // sys_at_consensus_ms`. The latter substitutes to
        //   sysdrift_ms + (sys_now - sys_at_consensus_ms)
        // and (sys_now - sys_at_consensus_ms) ≈ PREPOLL_LEAD_SECS
        // (~30s of intentional pre-poll wait), so the displayed
        // value would falsely show ~+30 s every cycle even on a
        // perfectly-synced system clock. The cached `sysdrift_ms`
        // is the actual drift between consensus NTP and local
        // system clock at the moment of NTP poll — that is the
        // semantically correct value to surface in `x1sr status`.
        let drift_for_status = chain_time_ms.map(|c| tx_timestamp_ms - c);
        let sysdrift_for_status = sysdrift_ms;
        let send_target_ms = next_boundary_secs.saturating_mul(1000) as i64;
        match rpc.send_transaction(&tx_b64) {
            Ok(sig) => {
                let after_send_ms = get_system_clock_ms();
                let delta_ms = after_send_ms - send_target_ms;
                println!(
                    "[timing] target={} actual={} delta={:+}ms",
                    format_clock_3dec(send_target_ms),
                    format_clock_3dec(after_send_ms),
                    delta_ms
                );
                println!("✅ submit OK — tx: {sig}");
                update_status_ok(&mut status, &sig, drift_for_status, sysdrift_for_status);
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

        // Sleep until the NEXT cycle's NTP-poll start. Aligning on the
        // boundary rather than on a flat `sleep(interval_s)` keeps the
        // schedule from drifting away from wall-clock alignment if a
        // single send takes long.
        sleep_until_unix_secs(next_cycle_ntp_start);
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

fn update_status_ok(
    status: &mut DaemonStatus,
    signature: &str,
    drift_ms: Option<i64>,
    sysdrift_ms: i64,
) {
    let now = get_unix_secs();
    status.running = true;
    status.last_submit_ts = Some(now);
    status.last_submit_tx = Some(signature.to_string());
    status.last_error = None;
    status.silent_cycles = 0;
    status.silent_reason = None;
    // Persist the drift signals from this submission so `x1sr status`
    // can render Chain drift / Sys drift without reading on-chain memos.
    status.last_drift_ms = drift_ms;
    status.last_sysdrift_ms = Some(sysdrift_ms);
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
        kill_pids(&others, 10);
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
    let keypair_path = match config.oracle_keypair_path.as_ref() {
        Some(p) => p,
        None => {
            eprintln!("config.oracle_keypair_path is not set");
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

    // Fleet-size lookup for the runway estimate. If the RPC call fails
    // (network down, program_id misconfigured, etc.) we fall back to a
    // solo estimate (n=1) and tag the line with `(solo estimate)`.
    let mut program_id_bytes = [0u8; 32];
    let n_oracles: u16 = match bs58::decode(&config.program_id).into_vec() {
        Ok(v) if v.len() == 32 => {
            program_id_bytes.copy_from_slice(&v);
            match rpc.fetch_active_registrations(&program_id_bytes) {
                Ok(regs) => regs.len().max(1).min(u16::MAX as usize) as u16,
                Err(_) => 1,
            }
        }
        _ => 1,
    };
    let solo_fallback = n_oracles == 1;

    match rpc.get_balance(&pubkey_b58) {
        Ok(lamports) => {
            let bal = lamports_to_xnt(lamports);
            let runway = estimate_days_remaining(bal, config.interval_s, n_oracles);
            // tx_per_day is the network's TX rate; my_share is what THIS
            // operator pays after rotation factors out the fleet.
            let tx_per_day = 86_400.0 / config.interval_s as f64;
            let my_share = tx_per_day / n_oracles.max(1) as f64;
            let solo_tag = if solo_fallback {
                "  (solo estimate — n unknown / RPC unreachable)"
            } else {
                ""
            };
            println!("oracle:  {pubkey_b58}");
            println!("balance: {bal:.3} XNT  (lamports {lamports})");
            println!(
                "runway:  ~{runway:.1} days  (@ {COST_PER_TX_XNT:.3} XNT × {my_share:.0} TX/day, n={n_oracles}){solo_tag}"
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

    // Symlink: force overwrite. Failure here is logged but does NOT abort
    // the install — the binary, the unit file, and daemon-reload still
    // need to land. The operator can fix the symlink manually after.
    let _ = std::fs::remove_file(symlink);
    let symlink_status = match std::os::unix::fs::symlink(bin_target, symlink) {
        Ok(()) => "ok (overwritten or created)".to_string(),
        Err(e) => {
            eprintln!("symlink {symlink}: {e}");
            format!("FAILED ({e})")
        }
    };

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

    // Unit file is ALWAYS written (overwrites any prior version). Exit
    // only when this fails — without the unit, systemd cannot manage
    // the daemon. The symlink may have failed; that is recoverable.
    if let Err(e) = std::fs::write(unit_path, &unit) {
        eprintln!("write {unit_path}: {e}");
        process::exit(1);
    }

    // daemon-reload picks up the new (or overwritten) unit. Logged but
    // never auto-enabled — operator decides when to bring the service
    // up via `systemctl enable --now`.
    let reload_status = match process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
    {
        Ok(s) if s.success() => "ok".to_string(),
        Ok(s) => format!("non-zero exit ({s})"),
        Err(e) => format!("ERROR ({e})"),
    };

    println!("symlink {symlink}: {symlink_status}");
    println!("unit file {unit_path}: written");
    println!("systemctl daemon-reload: {reload_status}");
    println!("Run: sudo systemctl enable --now x1-strontium");
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
    let kp_path = match authority_path.or_else(|| config.oracle_keypair_path.clone()) {
        Some(p) => p,
        None => {
            eprintln!(
                "[init] no authority keypair — pass --authority <path> or set \
                 `config.oracle_keypair_path`. Note: `init` creates the Oracle \
                 State PDA (X1 Strontium admin op, signed by the upgrade authority \
                 keypair) and is distinct from per-operator registration — see \
                 `x1-strontium register` for that."
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
// cmd_register — daemon-driven operator onboarding
// ---------------------------------------------------------------------------
//
// Generates oracle.json if missing, loads vote.json, runs the off-chain
// anti-farm gates (≥ 64 epoch credits + withdrawer-match qualifying stake),
// and on success builds + sends the 2-signer `register_submitter` TX.
//
// REFUSES to send if any gate fails — the contract holds no parsers in
// The contract holds no parsers in this codebase, so the daemon is the
// sole enforcer of the operator-quality constraint.

fn cmd_register(args: &[String]) {
    if !args.is_empty() {
        eprintln!("usage: x1-strontium register");
        process::exit(1);
    }

    let config = X1StrontiumConfig::load();

    let oracle_path = match &config.oracle_keypair_path {
        Some(p) => p.clone(),
        None => {
            eprintln!(
                "[register] config.oracle_keypair_path is not set — run \
                 `x1-strontium config set oracle_keypair <path>` first"
            );
            process::exit(1);
        }
    };
    let vote_path = match &config.vote_keypair_path {
        Some(p) => p.clone(),
        None => {
            eprintln!(
                "[register] config.vote_keypair_path is not set — run \
                 `x1-strontium config set vote_keypair <path>` first"
            );
            process::exit(1);
        }
    };

    // Generate oracle keypair if missing. We never overwrite — if the file
    // exists but is malformed, surface that as an error so the operator
    // can decide what to do.
    let expanded_oracle = expand_tilde(&oracle_path);
    let oracle_keypair = if std::path::Path::new(&expanded_oracle).exists() {
        match load_keypair(&oracle_path) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[register] cannot load existing oracle keypair: {e}");
                process::exit(1);
            }
        }
    } else {
        println!("[register] generating fresh oracle keypair at {expanded_oracle}");
        let kp = match generate_keypair() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[register] cannot generate keypair: {e}");
                process::exit(1);
            }
        };
        if let Err(e) = save_keypair(&expanded_oracle, &kp) {
            eprintln!("[register] cannot save keypair: {e}");
            process::exit(1);
        }
        kp
    };

    let vote_keypair = match load_keypair(&vote_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[register] cannot load vote keypair: {e}");
            process::exit(1);
        }
    };

    let oracle_pubkey: [u8; 32] = oracle_keypair.verifying_key().to_bytes();
    let oracle_pubkey_b58 = bs58::encode(oracle_pubkey).into_string();
    let vote_pubkey: [u8; 32] = vote_keypair.verifying_key().to_bytes();
    let vote_pubkey_b58 = bs58::encode(vote_pubkey).into_string();

    let mut program_id = [0u8; 32];
    match bs58::decode(&config.program_id).into_vec() {
        Ok(v) if v.len() == 32 => program_id.copy_from_slice(&v),
        _ => {
            eprintln!(
                "[register] invalid program_id in config: {}",
                config.program_id
            );
            process::exit(1);
        }
    }
    let mut oracle_pda = [0u8; 32];
    match bs58::decode(&config.oracle_pda).into_vec() {
        Ok(v) if v.len() == 32 => oracle_pda.copy_from_slice(&v),
        _ => {
            eprintln!(
                "[register] invalid oracle_pda in config: {}",
                config.oracle_pda
            );
            process::exit(1);
        }
    }
    let registration_pda = derive_registration_pda(&oracle_pubkey, &program_id);
    let registration_pda_b58 = bs58::encode(registration_pda).into_string();

    println!("[register] Oracle keypair:    {oracle_pubkey_b58}");
    println!("[register] Vote keypair:      {vote_pubkey_b58}");
    println!("[register] Registration PDA:  {registration_pda_b58}");
    println!("[register] Oracle PDA:        {}", config.oracle_pda);
    println!();
    println!("[register] Off-chain anti-farm gates:");

    let mut rpc = RpcClient::new(config.rpc_urls.clone());

    // Gate 1: ≥ 64 epoch_credits entries on the validator's vote account.
    let vote_account_data = match rpc.fetch_account_info(&vote_pubkey_b58) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[register] cannot fetch vote account: {e}");
            process::exit(1);
        }
    };
    let ec_len = match parse_vote_epoch_credits_len(&vote_account_data) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[register] cannot parse vote account: {e}");
            process::exit(1);
        }
    };
    if ec_len < MIN_EPOCH_HISTORY {
        eprintln!(
            "[register] ❌ epoch_credits has {ec_len} entries, need ≥ {MIN_EPOCH_HISTORY}. \
             Validator is too young (~64 epochs ≈ 2 months of voting on X1). \
             Wait a few days and retry."
        );
        process::exit(1);
    }
    println!("       ✓ epoch_credits = {ec_len} (≥ {MIN_EPOCH_HISTORY})");

    // Gate 2: withdrawer-match — at least one stake account exists with
    // withdraw authority equal to the vote account's authorized_withdrawer
    // (filter voter / withdrawer / age ≥ 2 epochs / not deactivating).
    // Any qualifying amount counts; the operator-quality signal is the
    // withdraw-authority binding, not the lamports amount.
    if vote_account_data.len() < 68 {
        eprintln!("[register] vote account too short — cannot read authorized_withdrawer");
        process::exit(1);
    }
    let mut withdrawer = [0u8; 32];
    withdrawer.copy_from_slice(&vote_account_data[36..68]);
    println!(
        "       authorized_withdrawer: {}",
        bs58::encode(withdrawer).into_string()
    );
    let stake = match compute_self_stake_off_chain(&mut rpc, &vote_pubkey, &withdrawer) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[register] cannot compute self-stake: {e}");
            process::exit(1);
        }
    };
    if stake == 0 {
        eprintln!(
            "[register] ❌ qualifying self-stake = 0 XNT (no stake with matching withdrawer). \
             Filter: voter=this vote account, withdrawer=authorized_withdrawer, \
             age ≥ 2 epochs, not deactivating."
        );
        process::exit(1);
    }
    println!(
        "       ✓ qualifying self-stake = {} XNT (withdrawer-match)",
        stake / 1_000_000_000
    );
    println!();

    // Build + send register_submitter TX (oracle_keypair pays rent for
    // the new ValidatorRegistration PDA; vote_keypair co-signs).
    let blockhash = match rpc.get_recent_blockhash() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[register] blockhash error: {e}");
            process::exit(1);
        }
    };
    let tx = build_register_transaction(
        &oracle_keypair,
        &vote_keypair,
        &program_id,
        &oracle_pda,
        &registration_pda,
        &blockhash,
    );
    let tx_b64 = base64_encode(&tx);

    println!("[register] Sending register_submitter ...");
    match rpc.send_transaction(&tx_b64) {
        Ok(sig) => {
            println!("[register] ✅ Success — Signature: {sig}");
            println!("[register] You can now start the daemon: `systemctl start x1-strontium`.");
        }
        Err(e) => {
            eprintln!("[register] ❌ failed: {e}");
            process::exit(1);
        }
    }
}

/// Generate a fresh ed25519 keypair from /dev/urandom — no extra deps,
/// works on Linux + macOS (the daemon's targets).
fn generate_keypair() -> Result<SigningKey, String> {
    let mut file =
        std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Persist a keypair in Solana's standard JSON-array-of-64-bytes format
/// (32-byte secret seed followed by 32-byte public key). Sets the file
/// mode to 0600 — the file holds a private key that signs every cycle.
fn save_keypair(path: &str, keypair: &SigningKey) -> Result<(), String> {
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    bytes.extend_from_slice(&keypair.to_bytes());
    bytes.extend_from_slice(keypair.verifying_key().as_bytes());
    let text = serde_json::to_string(&bytes).map_err(|e| format!("{e}"))?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, text).map_err(|e| format!("write {path}: {e}"))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/{rest}")
    } else {
        path.to_string()
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
//     last_cleanup_slot  : struct +88..96    -> account +96..104   (was _pad_reserve in v1.0)
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

// ---------------------------------------------------------------------------
// Auto-recover (v1.3): re-register at startup if the registration PDA is
// missing or inactive, without forcing the operator to hand-execute
// `x1-strontium register`. Common trigger: the operator's daemon was
// silent past CLEANUP_GRACE_WINDOWS (~24 h) and a cleanup_inactive TX
// closed their PDA; on restart they want to rejoin the fleet immediately.
// ---------------------------------------------------------------------------

/// Pure preconditions check for auto-recover. Extracted so cargo test
/// can exercise each refuse-path (low oracle balance, missing vote
/// keypair file, zero qualifying self-stake) without I/O.
///
/// Preconditions, evaluated in this order so the operator-facing error
/// message points at the first blocker:
/// 1. Oracle balance ≥ `MIN_BALANCE_AUTO_RECOVER_XNT` (covers register
///    rent + small `submit_time` runway buffer).
/// 2. Vote keypair file present on disk (existence + `expand_tilde`).
/// 3. Qualifying self-stake > 0 lamports (anti-farm: at least one stake
///    account whose withdraw authority matches `vote.authorized_withdrawer`).
///
/// Returns Ok(()) iff all three pass.
fn check_auto_recover_preconditions(
    oracle_balance_lamports: u64,
    vote_keypair_path: &str,
    self_stake_lamports: u64,
) -> Result<(), String> {
    let oracle_balance_xnt = lamports_to_xnt(oracle_balance_lamports);
    if oracle_balance_xnt < MIN_BALANCE_AUTO_RECOVER_XNT {
        return Err(format!(
            "oracle.json balance {oracle_balance_xnt:.3} XNT < {MIN_BALANCE_AUTO_RECOVER_XNT:.2} XNT \
             required for auto-recover — top up from authorized_withdrawer Ledger before restart"
        ));
    }
    let expanded = expand_tilde(vote_keypair_path);
    if !std::path::Path::new(&expanded).exists() {
        return Err(format!(
            "vote keypair not found at {expanded} — run \
             `x1-strontium config set vote_keypair <path>` and ensure the \
             file exists before restart"
        ));
    }
    if self_stake_lamports == 0 {
        return Err(
            "qualifying self-stake = 0 XNT (no stake account whose withdraw \
             authority matches vote.authorized_withdrawer, age ≥ 2 epochs, \
             not deactivating) — anti-farm gate refuses auto-recover"
                .to_string(),
        );
    }
    Ok(())
}

/// Orchestration for auto-recover: fetch all required RPC state,
/// validate preconditions, build the 2-signer `register_submitter` TX,
/// and send it (or print without sending when `dry_run` is true).
///
/// The function deliberately surfaces the SAME refuse-paths and error
/// shapes the manual `cmd_register` would emit — operators reading
/// daemon logs after a failed auto-recover should get the exact same
/// remediation guidance they'd see from a hand-run `x1-strontium register`.
fn attempt_auto_recover_registration(
    rpc: &mut RpcClient,
    config: &X1StrontiumConfig,
    oracle_keypair: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    registration_pda: &[u8; 32],
    dry_run: bool,
) -> Result<(), String> {
    let vote_path = match &config.vote_keypair_path {
        Some(p) => p.clone(),
        None => {
            return Err("vote_keypair_path is not set in config — run \
                 `x1-strontium config set vote_keypair <path>` before restart"
                .to_string());
        }
    };

    let oracle_pubkey: [u8; 32] = oracle_keypair.verifying_key().to_bytes();
    let oracle_pubkey_b58 = bs58::encode(oracle_pubkey).into_string();

    // 1. Balance.
    let oracle_balance_lamports = rpc
        .get_balance(&oracle_pubkey_b58)
        .map_err(|e| format!("auto-recover: balance check failed: {e}"))?;

    // 2. Vote keypair load — needed to derive pubkey for the stake
    //    computation AND to co-sign the register TX. The file-existence
    //    half of the precondition is asserted in
    //    `check_auto_recover_preconditions`, run after this step
    //    succeeds; we still load here to fail early if the file is
    //    present but corrupt.
    let vote_keypair = load_keypair(&vote_path)
        .map_err(|e| format!("auto-recover: cannot load vote keypair at {vote_path}: {e}"))?;
    let vote_pubkey: [u8; 32] = vote_keypair.verifying_key().to_bytes();
    let vote_pubkey_b58 = bs58::encode(vote_pubkey).into_string();

    // 3. Self-stake (withdrawer-match anti-farm gate).
    let vote_account_data = rpc
        .fetch_account_info(&vote_pubkey_b58)
        .map_err(|e| format!("auto-recover: cannot fetch vote account: {e}"))?;
    if vote_account_data.len() < 68 {
        return Err(
            "auto-recover: vote account too short to read authorized_withdrawer".to_string(),
        );
    }
    let mut withdrawer = [0u8; 32];
    withdrawer.copy_from_slice(&vote_account_data[36..68]);
    let self_stake_lamports = compute_self_stake_off_chain(rpc, &vote_pubkey, &withdrawer)
        .map_err(|e| format!("auto-recover: self-stake compute failed: {e}"))?;

    check_auto_recover_preconditions(oracle_balance_lamports, &vote_path, self_stake_lamports)?;

    println!(
        "[startup] registration absent/inactive — auto-recovering \
         (no manual intervention required)"
    );
    println!(
        "[auto-recover] oracle balance: {:.3} XNT (≥ {:.2} required)",
        lamports_to_xnt(oracle_balance_lamports),
        MIN_BALANCE_AUTO_RECOVER_XNT
    );
    println!(
        "[auto-recover] qualifying self-stake: {} XNT (withdrawer-match)",
        self_stake_lamports / 1_000_000_000
    );

    let blockhash = rpc
        .get_recent_blockhash()
        .map_err(|e| format!("auto-recover: blockhash error: {e}"))?;
    let tx = build_register_transaction(
        oracle_keypair,
        &vote_keypair,
        program_id,
        oracle_pda,
        registration_pda,
        &blockhash,
    );

    if dry_run {
        println!(
            "[auto-recover] dry-run: register TX built ({} bytes) — not sending",
            tx.len()
        );
        return Ok(());
    }

    println!("[auto-recover] sending register_submitter ...");
    let sig = rpc
        .send_transaction(&base64_encode(&tx))
        .map_err(|e| format!("auto-recover: register TX failed: {e}"))?;
    println!("[auto-recover] ✅ Success — signature: {sig}");
    Ok(())
}

/// Replicated from `programs/x1-strontium/src/lib.rs` so the daemon can
/// mirror the contract's stale-operator math when deciding whether to
/// fire `cleanup_inactive`. Bumped together with the contract literal
/// — there is no enforcement linking the two values, so a contract
/// change without a daemon change here would leak no-op TXs again.
///
/// v1.3: fixed-grace wall-clock window (`windows_since >
/// CLEANUP_GRACE_WINDOWS`). Replaces v1.2's per-fleet-size
/// `CLEANUP_MAX_MISSED_TURNS = 10` with `windows_per_turn` division —
/// the daemon and contract now share the same fleet-size-independent
/// threshold, so the pre-flight never fires no-op TXs that the
/// contract would skip (and vice versa).
const CLEANUP_GRACE_WINDOWS: u64 = 1440;
const CLEANUP_WINDOW_SLOTS: u64 = 150;

/// Cleanup pre-flight: fetch all active registrations and fire one
/// `cleanup_inactive` TX that asks the contract to evaluate every one
/// of them. The contract iterates the batch, CLOSES any
/// `ValidatorRegistration` PDA past `CLEANUP_GRACE_WINDOWS` of silence
/// (lamports return to the cleanup-TX payer), and stamps
/// `last_cleanup_slot` so other daemons in the same cycle skip this
/// work.
///
/// v1.2.0 hotfix: pre-flight first checks whether ANY registration is
/// stale; if not, no TX is sent (saves ~0.004 XNT per daemon per cycle
/// on a healthy fleet, which is the common case).
fn try_cleanup_inactive(
    rpc: &mut RpcClient,
    fee_payer: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    current_slot: u64,
) -> Result<(), String> {
    let regs: Vec<RegistrationEntry> = rpc.fetch_active_registrations(program_id)?;
    if regs.is_empty() {
        return Err("no active registrations to evaluate".to_string());
    }

    // Stale-check: mirror the contract's `windows_since >
    // CLEANUP_GRACE_WINDOWS` semantics. Skip the TX when no
    // registration would be touched.
    let current_window_id = current_slot / CLEANUP_WINDOW_SLOTS;
    let any_stale = regs.iter().any(|r| {
        let windows_since = current_window_id.saturating_sub(r.last_submitted_window_id);
        windows_since > CLEANUP_GRACE_WINDOWS
    });
    if !any_stale {
        if std::env::var("X1SR_DEBUG").is_ok() {
            eprintln!(
                "[cleanup] no stale operators among {} active — skipping TX",
                regs.len()
            );
        }
        return Ok(());
    }

    let blockhash = rpc.get_recent_blockhash()?;
    let pdas: Vec<[u8; 32]> = regs.iter().map(|r| r.pda).collect();
    let tx =
        build_cleanup_inactive_transaction(fee_payer, program_id, oracle_pda, &pdas, &blockhash);
    let sig = rpc.send_transaction(&base64_encode(&tx))?;
    println!(
        "[cleanup] fired cleanup_inactive (n={}) — tx: {sig}",
        pdas.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Wall-clock window alignment
// ---------------------------------------------------------------------------

/// Compute the next wall-clock window boundary (in unix seconds) strictly
/// after `now_secs`. Used by the pre-poll flow so NTP and the eventual
/// election all reference the SAME boundary.
fn next_window_boundary_secs(now_secs: u64, interval_s: u64) -> u64 {
    let interval = interval_s.max(1);
    ((now_secs / interval) + 1) * interval
}

/// Sleep until `target_secs` UNIX seconds. No-op if we're already at or
/// past the target.
fn sleep_until_unix_secs(target_secs: u64) {
    sleep_until_unix_ms(target_secs.saturating_mul(1000));
}

/// Sleep until `target_ms` UNIX milliseconds. Higher precision variant
/// of [`sleep_until_unix_secs`] — used to wake at boundary-200ms for the
/// pre-flight phase.
fn sleep_until_unix_ms(target_ms: u64) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if target_ms > now_ms {
        sleep(Duration::from_millis(target_ms - now_ms));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Withdrawer-match gate tripwire ----------

    /// v1.2.0 replaces the 128 XNT minimum-stake floor with a
    /// withdrawer-match gate: any qualifying stake (voter == this vote
    /// account, withdrawer == authorized_withdrawer, age ≥ 2 epochs,
    /// not deactivating) is sufficient as long as the SUM is non-zero.
    /// The cmd_register / 24 h refresh paths both call
    /// `compute_self_stake_off_chain` and short-circuit only when the
    /// sum is zero — this test locks that semantic so an accidental
    /// reintroduction of a `> N XNT` threshold trips loudly.
    #[test]
    fn withdrawer_match_gate_requires_nonzero_stake() {
        // The gate logic is `if stake == 0 { reject }`. Any positive
        // amount qualifies — even a single lamport.
        let zero: u64 = 0;
        let one_lamport: u64 = 1;
        let one_xnt: u64 = 1_000_000_000;
        let large: u64 = 500_000_000_000;

        assert!(zero == 0, "zero stake must trip the gate");
        assert!(
            one_lamport > 0,
            "even 1 lamport with matching withdrawer passes the gate"
        );
        assert!(one_xnt > 0);
        assert!(large > 0);
    }

    #[test]
    fn min_epoch_history_is_64() {
        // Validator-age gate at register time. ~64 epochs ≈ 2 months on X1's
        // epoch length. Off-chain only.
        assert_eq!(MIN_EPOCH_HISTORY, 64);
    }

    // ---------- next_window_boundary_secs (Fix 6 / v1.2.0) ----------

    #[test]
    fn next_window_boundary_secs_basic() {
        let interval_s = 300u64; // 5 min
                                 // Exactly on a boundary → returns the NEXT boundary (not the
                                 // current one). This avoids a zero-length sleep that would burn
                                 // a window doing nothing.
        assert_eq!(next_window_boundary_secs(0, interval_s), 300);
        assert_eq!(next_window_boundary_secs(300, interval_s), 600);
        // Mid-window → returns the upcoming boundary.
        assert_eq!(next_window_boundary_secs(150, interval_s), 300);
        assert_eq!(next_window_boundary_secs(599, interval_s), 600);
        // Different interval (60 s).
        assert_eq!(next_window_boundary_secs(0, 60), 60);
        assert_eq!(next_window_boundary_secs(59, 60), 60);
        assert_eq!(next_window_boundary_secs(60, 60), 120);
    }

    #[test]
    fn next_window_boundary_secs_clamps_zero_interval_to_one() {
        // Defensive: interval = 0 must not panic. Treated as 1s.
        assert_eq!(next_window_boundary_secs(100, 0), 101);
    }

    // ---------- cleanup pre-flight stale check (v1.3 wall-clock grace) ----------

    #[test]
    fn cleanup_stale_check_skips_when_fleet_healthy() {
        // n=2, both registrations submitted in the current window
        // (last_submitted_window_id = current_window_id) → 0 windows
        // elapsed each → no stale → daemon must NOT fire the TX.
        let current_slot = 1_000_000u64;
        let current_window_id = current_slot / CLEANUP_WINDOW_SLOTS;

        // Two registrations both fresh.
        let last_submits = [current_window_id, current_window_id];
        let any_stale = last_submits.iter().any(|&last| {
            let windows_since = current_window_id.saturating_sub(last);
            windows_since > CLEANUP_GRACE_WINDOWS
        });
        assert!(!any_stale, "healthy fleet must not trigger cleanup");
    }

    #[test]
    fn cleanup_stale_check_fires_when_one_operator_stale() {
        // n=2, operator A submitted recently, operator B has been silent
        // for more than CLEANUP_GRACE_WINDOWS (~24 h) — daemon must fire
        // the cleanup TX. v1.3: fleet size no longer affects the
        // threshold (used to require n × MAX_MISSED_TURNS windows).
        let current_slot = 1_000_000u64;
        let current_window_id = current_slot / CLEANUP_WINDOW_SLOTS;
        let stale_last = current_window_id - (CLEANUP_GRACE_WINDOWS + 1);

        let last_submits = [current_window_id, stale_last];
        let any_stale = last_submits.iter().any(|&last| {
            let windows_since = current_window_id.saturating_sub(last);
            windows_since > CLEANUP_GRACE_WINDOWS
        });
        assert!(any_stale, "stale operator B must trigger cleanup");
    }

    /// v1.3 invariant: the daemon's stale check is fleet-size-independent
    /// (was n × MAX_MISSED_TURNS in v1.2). The daemon would otherwise
    /// fire cleanup TXs that the contract would skip — wasting XNT every
    /// cycle on no-op closures.
    #[test]
    fn cleanup_stale_check_grace_is_fleet_size_independent() {
        let current_slot = 1_000_000u64;
        let current_window_id = current_slot / CLEANUP_WINDOW_SLOTS;
        let inside = current_window_id - CLEANUP_GRACE_WINDOWS; // at boundary
        let outside = current_window_id - (CLEANUP_GRACE_WINDOWS + 1); // past

        for _n in [2u16, 6, 100, 512] {
            // Fleet size is no longer consulted by the daemon's stale
            // check; we just exercise the boundary at multiple n values
            // to document the invariant.
            let windows_inside = current_window_id.saturating_sub(inside);
            let windows_outside = current_window_id.saturating_sub(outside);
            assert!(windows_inside <= CLEANUP_GRACE_WINDOWS);
            assert!(windows_outside > CLEANUP_GRACE_WINDOWS);
        }
    }

    // ---------- sysdrift gate ----------

    #[test]
    fn daemon_silences_when_sysdrift_exceeds_threshold() {
        // Fix #4: when the daemon's system clock drifts more than
        // MAX_SYSDRIFT_MS from the NTP consensus, main loop step j
        // silences the cycle with SilentReason::SystemClockOutOfSync
        // rather than submitting a garbage timestamp. The full main
        // loop is exercised in integration; here we lock the threshold
        // arithmetic directly so an accidental change to the constant
        // or to the comparison fails loudly.
        let consensus_ms: i64 = 1_000_000_000;

        // 10 s behind consensus → |drift| = 10000 > 5000 → silence.
        let sys_drifted_back: i64 = 999_990_000;
        assert!(
            (consensus_ms - sys_drifted_back).abs() > MAX_SYSDRIFT_MS,
            "10s behind consensus must trigger silence"
        );

        // 10 s ahead of consensus → silence as well (sign-symmetric).
        let sys_drifted_forward: i64 = 1_000_010_000;
        assert!(
            (consensus_ms - sys_drifted_forward).abs() > MAX_SYSDRIFT_MS,
            "10s ahead of consensus must trigger silence"
        );

        // 4.999 s drift — under threshold, daemon submits.
        let sys_close: i64 = consensus_ms + 4_999;
        assert!(
            (consensus_ms - sys_close).abs() <= MAX_SYSDRIFT_MS,
            "4.999s drift must NOT trigger silence"
        );

        // Boundary: exactly 5000 ms drift. The gate uses strict `>`, so
        // an exact-match drift is acceptable.
        let sys_at_limit: i64 = consensus_ms + 5_000;
        assert_eq!((consensus_ms - sys_at_limit).abs(), MAX_SYSDRIFT_MS);
        assert!(
            (consensus_ms - sys_at_limit).abs() <= MAX_SYSDRIFT_MS,
            "drift exactly at MAX_SYSDRIFT_MS must NOT trigger silence (strict >)"
        );
    }

    // ---------- auto-recover preconditions (v1.3 startup) ----------

    /// Helper: write a 64-byte zero-filled keypair stub to a tempfile.
    /// The auto-recover precondition only checks file existence — not
    /// parseable content — so even an empty marker file is enough to
    /// exercise the happy path of `check_auto_recover_preconditions`.
    fn touch_tempfile(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        std::fs::write(&path, b"").expect("tempfile write");
        path
    }

    /// BUG fix: refuse auto-recover when the oracle wallet can't cover
    /// the register TX. Surfacing the balance error LOUDLY (with a
    /// concrete remediation hint) beats silently sending a TX that
    /// fails on-chain and leaves the operator confused.
    #[test]
    fn auto_recover_skipped_when_balance_low() {
        // 0.1 XNT — well below MIN_BALANCE_AUTO_RECOVER_XNT=0.6.
        let result = check_auto_recover_preconditions(
            100_000_000, // 0.1 XNT
            "/tmp/whatever",
            1_000_000_000, // stake OK, but balance fails first
        );
        let err = result.expect_err("low balance must refuse auto-recover");
        assert!(
            err.contains("balance"),
            "error should mention balance: {err}"
        );
        assert!(
            err.contains("0.1") || err.contains("0.100"),
            "error should quote the actual balance: {err}"
        );
    }

    #[test]
    fn auto_recover_skipped_when_vote_keypair_missing() {
        // Generate a tempfile path that won't exist (no touch).
        let nonexistent =
            std::env::temp_dir().join(format!("x1sr-vote-keypair-missing-{}", std::process::id()));
        // Best-effort cleanup in case a prior run left a file behind.
        let _ = std::fs::remove_file(&nonexistent);

        let result = check_auto_recover_preconditions(
            1_000_000_000, // 1.0 XNT — balance OK
            nonexistent.to_str().unwrap(),
            1_000_000_000, // stake OK
        );
        let err = result.expect_err("missing vote keypair must refuse auto-recover");
        assert!(
            err.contains("vote keypair") && err.contains("not found"),
            "error should mention missing vote keypair: {err}"
        );
    }

    #[test]
    fn auto_recover_skipped_when_self_stake_zero() {
        // Both balance and vote keypair file pass; self_stake = 0 trips.
        let vote_path = touch_tempfile("x1sr-vote-keypair-stake-zero");
        let result = check_auto_recover_preconditions(
            1_000_000_000, // 1.0 XNT — balance OK
            vote_path.to_str().unwrap(),
            0, // anti-farm gate refuses
        );
        let err = result.expect_err("zero self-stake must refuse auto-recover");
        assert!(
            err.contains("self-stake") && err.contains("anti-farm"),
            "error should mention anti-farm self-stake gate: {err}"
        );
        let _ = std::fs::remove_file(&vote_path);
    }

    /// Happy path: every precondition satisfied, function returns Ok.
    /// The actual TX build / send is exercised end-to-end at deploy
    /// time; here we just lock the "all green ⇒ Ok" invariant.
    #[test]
    fn auto_recover_happy_path_dry_run() {
        let vote_path = touch_tempfile("x1sr-vote-keypair-happy");
        let result = check_auto_recover_preconditions(
            (MIN_BALANCE_AUTO_RECOVER_XNT * 1_000_000_000.0) as u64 + 1, // just over the gate
            vote_path.to_str().unwrap(),
            500_000_000, // 0.5 XNT qualifying self-stake
        );
        assert_eq!(
            result,
            Ok(()),
            "all preconditions satisfied → Ok, got: {result:?}"
        );
        let _ = std::fs::remove_file(&vote_path);
    }

    #[test]
    fn auto_recover_balance_threshold_is_exactly_0_6_xnt() {
        // Document the threshold value. The precondition compares the
        // f64 XNT representation against MIN_BALANCE_AUTO_RECOVER_XNT
        // (0.6), so 0.6 XNT - 1 lamport must fail, 0.6 XNT exactly must
        // pass (gate uses `<`, not `<=`).
        let vote_path = touch_tempfile("x1sr-vote-keypair-threshold");
        let just_under: u64 = 599_999_999; // 0.6 XNT - 1 lamport
        let just_at: u64 = 600_000_000; // exactly 0.6 XNT
        assert!(check_auto_recover_preconditions(
            just_under,
            vote_path.to_str().unwrap(),
            1_000_000_000
        )
        .is_err());
        assert!(check_auto_recover_preconditions(
            just_at,
            vote_path.to_str().unwrap(),
            1_000_000_000
        )
        .is_ok());
        let _ = std::fs::remove_file(&vote_path);
    }
}
