//! Stage 1 of X1 Strontium v1.0: validate the contract's manual byte-offset
//! parsers for Solana vote / stake accounts against the official
//! `solana-program` reference deserializers, using LIVE X1 mainnet accounts.
//!
//! **Why:** the contract's `initialize_operator` gate parses raw vote & stake
//! account bytes inside the program (no CPI to vote/stake programs). A
//! silent off-by-N-bytes error would either accept forged proofs or reject
//! legitimate operators. This test is the canonical "offsets are right"
//! checkpoint — it must pass green before any on-chain deploy.
//!
//! **How to run** (requires internet access to X1 mainnet RPC):
//!
//! ```bash
//! cargo test --test account_parse_integration -- --ignored --nocapture
//! ```
//!
//! All tests are `#[ignore]`-gated so `cargo test` / CI skip them by default.
//!
//! Reporting rule (agreed during FAZA 0 recon): when comparing per-epoch
//! values from `epoch_credits`, only assert on entries with
//! `epoch < current_epoch`. The last entry is the in-progress epoch, and
//! its `this_epoch_credits` monotonically grows between snapshots —
//! comparing it against a frozen reference would race.

use std::time::Duration;

use anchor_lang::solana_program::{
    pubkey::Pubkey, stake::state::StakeStateV2, vote::state::VoteStateVersions,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use x1_strontium::{
    parse_and_validate_vote, parse_stake_state, stake_is_qualifying, MIN_SELF_STAKE_LAMPORTS,
};

// ---------------------------------------------------------------------------
// Identifiers (mirrored from CLAUDE_CODE_PROMPT.md §3)
// ---------------------------------------------------------------------------

const X1_RPC: &str = "https://rpc.mainnet.x1.xyz";

/// Prime's vote account — has a long epoch-credits history + known
/// authorized_withdrawer (Ledger `7k4tvn5Aim8y…`) + ≥128 XNT self-stake,
/// so it's the natural smoke-test target for the operator gates.
const PRIME_VOTE: &str = "5NoKHzd37MY2ysu9bN2vrztzUvsuRfWTX2YVPyhXChVL";

/// Prime's self-stake accounts (withdrawer == Ledger). Both must parse.
const PRIME_SELF_STAKES: &[&str] = &[
    "Cdp5hETNVvGBY7F7hxvhsQT8djHZ4dhbgYmdsV5jyezM",
    "GKpBtsDUAobQG5TNwjDYakrbKtRLKmw5kqUmiPxqHiB6",
];

/// Ledger cold key = vote account's authorized_withdrawer.
const LEDGER_WITHDRAWER: &str = "7k4tvn5Aim8yWEdSAfZqptTvTf7r1WXUNSNa8evmmNGq";

// ---------------------------------------------------------------------------
// Minimal JSON-RPC client (no solana-client dep — keeps contract crate slim)
// ---------------------------------------------------------------------------

/// Fetch `getAccountInfo` and return `(owner_pubkey, raw_data_bytes, current_epoch_context)`.
/// Panics on any transport / decoding / RPC failure — these tests are smoke
/// tests, a network blip should surface as a loud failure, not a silent skip.
fn rpc_get_account(pubkey: &str) -> (Pubkey, Vec<u8>) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [pubkey, { "encoding": "base64", "commitment": "confirmed" }],
    });
    let resp: serde_json::Value = ureq::post(X1_RPC)
        .timeout(Duration::from_secs(15))
        .set("content-type", "application/json")
        .send_json(body)
        .expect("RPC POST failed")
        .into_json()
        .expect("RPC response not JSON");

    let value = resp
        .pointer("/result/value")
        .and_then(|v| if v.is_null() { None } else { Some(v) })
        .unwrap_or_else(|| panic!("account {pubkey} not found on X1 mainnet: {resp}"));

    let owner_str = value["owner"].as_str().expect("owner missing");
    let owner = Pubkey::try_from(
        bs58::decode(owner_str)
            .into_vec()
            .expect("owner not base58")
            .as_slice(),
    )
    .expect("owner not 32 bytes");

    let data_arr = value["data"].as_array().expect("data missing");
    let b64_str = data_arr[0].as_str().expect("data[0] not string");
    let raw = B64.decode(b64_str).expect("data not valid base64");

    (owner, raw)
}

/// Fetch `getEpochInfo().epoch`. Used so we only assert on completed epochs
/// (the in-progress one races).
fn rpc_current_epoch() -> u64 {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getEpochInfo",
        "params": [],
    });
    let resp: serde_json::Value = ureq::post(X1_RPC)
        .timeout(Duration::from_secs(15))
        .set("content-type", "application/json")
        .send_json(body)
        .expect("getEpochInfo failed")
        .into_json()
        .expect("epoch info not JSON");
    resp["result"]["epoch"]
        .as_u64()
        .expect("no epoch in response")
}

fn pubkey_from_bs58(s: &str) -> Pubkey {
    Pubkey::try_from(bs58::decode(s).into_vec().unwrap().as_slice()).unwrap()
}

// ---------------------------------------------------------------------------
// Tests — all #[ignore]-gated, require network access to X1 mainnet
// ---------------------------------------------------------------------------

#[test]
#[ignore = "live mainnet — run with: cargo test --ignored --nocapture"]
fn vote_parser_matches_solana_program_on_prime() {
    let (owner, data) = rpc_get_account(PRIME_VOTE);
    assert_eq!(
        owner,
        anchor_lang::solana_program::vote::program::ID,
        "Prime vote account is not owned by the vote program"
    );

    // (1) Our manual parser — if this errors, the contract would reject Prime
    //     at initialize_operator. That would be a deploy blocker.
    let header = parse_and_validate_vote(&data)
        .expect("parse_and_validate_vote rejected Prime — offset drift or gate bug");

    // (2) solana-program's bincode reference deserialize — single source of
    //     truth. If these two disagree, our byte offsets are wrong.
    let reference: VoteStateVersions = bincode::deserialize(&data)
        .expect("solana-program failed to deserialize Prime vote — account is malformed");
    let ref_state = match reference {
        VoteStateVersions::Current(b) => *b,
        other => panic!("expected VoteStateVersions::Current, got {other:?}"),
    };

    assert_eq!(
        header.node_pubkey, ref_state.node_pubkey,
        "manual parser's node_pubkey disagrees with solana-program"
    );
    assert_eq!(
        header.authorized_withdrawer, ref_state.authorized_withdrawer,
        "manual parser's authorized_withdrawer disagrees with solana-program"
    );
    assert_eq!(
        header.authorized_withdrawer,
        pubkey_from_bs58(LEDGER_WITHDRAWER),
        "Prime's authorized_withdrawer is no longer the Ledger — §3 is stale"
    );

    println!(
        "Prime vote OK — node={}, withdrawer={}, epoch_credits_len={}",
        header.node_pubkey,
        header.authorized_withdrawer,
        ref_state.epoch_credits.len()
    );
}

#[test]
#[ignore = "live mainnet — run with: cargo test --ignored --nocapture"]
fn stake_parser_matches_solana_program_on_prime_stakes() {
    for stake_pk in PRIME_SELF_STAKES {
        let (owner, data) = rpc_get_account(stake_pk);
        assert_eq!(
            owner,
            anchor_lang::solana_program::stake::program::ID,
            "{stake_pk} is not owned by the stake program"
        );

        let parsed = parse_stake_state(&data)
            .expect("parse_stake_state errored")
            .expect("parse_stake_state returned None on a live Stake account");

        let reference: StakeStateV2 = bincode::deserialize(&data)
            .expect("solana-program failed to deserialize stake account");
        let (ref_meta, ref_stake) = match reference {
            StakeStateV2::Stake(meta, stake, _flags) => (meta, stake),
            other => panic!("{stake_pk} is not in Stake variant: {other:?}"),
        };

        assert_eq!(
            parsed.withdrawer, ref_meta.authorized.withdrawer,
            "{stake_pk}: manual withdrawer mismatch"
        );
        assert_eq!(
            parsed.voter_pubkey, ref_stake.delegation.voter_pubkey,
            "{stake_pk}: manual voter_pubkey mismatch"
        );
        assert_eq!(
            parsed.stake_amount, ref_stake.delegation.stake,
            "{stake_pk}: manual stake_amount mismatch"
        );
        assert_eq!(
            parsed.activation_epoch, ref_stake.delegation.activation_epoch,
            "{stake_pk}: manual activation_epoch mismatch"
        );
        assert_eq!(
            parsed.deactivation_epoch, ref_stake.delegation.deactivation_epoch,
            "{stake_pk}: manual deactivation_epoch mismatch"
        );
        assert_eq!(
            parsed.withdrawer,
            pubkey_from_bs58(LEDGER_WITHDRAWER),
            "{stake_pk}: withdrawer is no longer the Ledger"
        );
        assert_eq!(
            parsed.voter_pubkey,
            pubkey_from_bs58(PRIME_VOTE),
            "{stake_pk}: delegated to a different vote account than Prime"
        );

        println!(
            "Prime stake {stake_pk} OK — amount={} XNT, activation_epoch={}, deactivation_epoch={}",
            parsed.stake_amount / 1_000_000_000,
            parsed.activation_epoch,
            parsed.deactivation_epoch,
        );
    }
}

#[test]
#[ignore = "live mainnet — run with: cargo test --ignored --nocapture"]
fn prime_operator_would_pass_initialize_gate() {
    // End-to-end: run the same checks `initialize_operator` would run,
    // live, against Prime. If this passes, the deploy-day flow works.
    let current_epoch = rpc_current_epoch();
    let vote_pk = pubkey_from_bs58(PRIME_VOTE);
    let authority = pubkey_from_bs58(LEDGER_WITHDRAWER);

    // (1) Vote gate: parse + validate (64-epoch window, bad-epoch tolerance,
    //     total credits floor). Then confirm authority claim.
    let (_, vote_data) = rpc_get_account(PRIME_VOTE);
    let header = parse_and_validate_vote(&vote_data).expect("Prime failed the epoch-credits gate");
    assert_eq!(
        header.authorized_withdrawer, authority,
        "Prime's authorized_withdrawer drifted from the Ledger"
    );

    // (2) Self-stake gate: sum qualifying stakes from Prime's self-stake set.
    let mut total: u64 = 0;
    for stake_pk in PRIME_SELF_STAKES {
        let (_, data) = rpc_get_account(stake_pk);
        let Some(parsed) = parse_stake_state(&data).expect("parse error") else {
            continue;
        };
        if stake_is_qualifying(&parsed, &vote_pk, &authority, current_epoch) {
            total = total.checked_add(parsed.stake_amount).unwrap();
        }
    }
    assert!(
        total >= MIN_SELF_STAKE_LAMPORTS,
        "Prime's qualifying self-stake {} XNT < 128 XNT floor",
        total / 1_000_000_000,
    );
    println!(
        "Prime would pass initialize_operator — self-stake {} XNT at epoch {}",
        total / 1_000_000_000,
        current_epoch
    );
}
