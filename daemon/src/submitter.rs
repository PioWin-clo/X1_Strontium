use crate::consensus::ConsensusResult;
use crate::status::NtpTier;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::Duration;

/// Read a Solana-style JSON keypair file (a JSON array of 64 bytes) and
/// return a usable `SigningKey`. Only the first 32 bytes (the seed / secret
/// key) are consumed — `ed25519-dalek` derives the public key from those.
/// Accepts a leading `~/` which is expanded via `$HOME`.
pub fn load_keypair(path: &str) -> Result<SigningKey, String> {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|e| format!("HOME not set: {e}"))?;
        format!("{home}/{rest}")
    } else {
        path.to_string()
    };
    let text = fs::read_to_string(&expanded).map_err(|e| format!("cannot read {expanded}: {e}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&text)
        .map_err(|e| format!("cannot parse {expanded} as JSON array: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!(
            "keypair {expanded}: expected 64 bytes, got {}",
            bytes.len()
        ));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes[..32]);
    Ok(SigningKey::from_bytes(&secret))
}

/// Solana System Program ID (all zeros) — used as the program for the
/// `initialize` instruction's system_program account slot.
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Solana memo program v2.
pub const MEMO_PROGRAM_ID_B58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Solana stake program (`Stake11111111111111111111111111111111111111`) —
/// used by `fetch_stake_accounts_for_vote` and as the expected owner of
/// stake accounts attached to `submit_time` TXs.
pub const STAKE_PROGRAM_ID_B58: &str = "Stake11111111111111111111111111111111111111";

/// Parsed view of a stake account. The `pubkey` field is filled by
/// `fetch_stake_accounts_for_vote` for callers that need to address the
/// account on chain (cleanup paths, future RPC operations); the daemon
/// main loop only reads the filter fields, hence the dead-code allowance.
#[derive(Debug, Clone)]
pub struct StakeAccountInfo {
    #[allow(dead_code)]
    pub pubkey: [u8; 32],
    pub withdrawer: [u8; 32],
    pub voter: [u8; 32],
    pub stake_amount: u64,
    pub activation_epoch: u64,
    pub deactivation_epoch: u64,
}

/// Response shape for `getEpochInfo`.
#[derive(Debug, Clone)]
pub struct EpochInfoResponse {
    pub epoch: u64,
    pub absolute_slot: u64,
}

/// Parsed view of a `ValidatorRegistration` account — every field the
/// daemon parses, including a few not consumed by the current main loop
/// but useful for `x1-strontium status` and future diagnostics.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RegistrationEntry {
    /// The registration PDA address. Used as a `remaining_accounts`
    /// entry when the daemon calls `cleanup_inactive`.
    pub pda: [u8; 32],
    pub oracle_keypair: [u8; 32],
    pub vote_account: [u8; 32],
    pub registered_at: i64,
    pub last_submitted_window_id: u64,
    pub is_active: bool,
}

/// On-chain account layout for `ValidatorRegistration` (Anchor `#[account]`,
/// 8-byte discriminator + 88-byte body). All offsets below are absolute
/// from the start of the account data (including the discriminator).
const REG_ACCOUNT_SIZE: usize = 96;
const REG_OFF_ORACLE: usize = 8;
const REG_OFF_VOTE: usize = 40;
const REG_OFF_REGISTERED_AT: usize = 72;
const REG_OFF_LAST_WINDOW: usize = 80;
const REG_OFF_IS_ACTIVE: usize = 88;

/// Native lamports → XNT (X1 Native Token) conversion. 1 XNT = 1e9 lamports.
const LAMPORTS_PER_XNT: f64 = 1_000_000_000.0;

// ---------------------------------------------------------------------------
// PDA derivation (full Solana algorithm)
// ---------------------------------------------------------------------------

/// True iff the 32-byte point sits on the ed25519 curve. A valid PDA must be
/// **off** the curve — that's the whole point of the nonce search.
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    let compressed = CompressedEdwardsY(*bytes);
    compressed.decompress().is_some()
}

/// Solana `find_program_address`: walk nonces 255..=0, return the first
/// candidate that is OFF the curve.
pub fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for nonce in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for s in seeds {
            hasher.update(s);
        }
        hasher.update([nonce]);
        hasher.update(program_id);
        hasher.update(b"ProgramDerivedAddress");
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        if !is_on_curve(&out) {
            return (out, nonce);
        }
    }
    panic!("find_program_address: no off-curve hash found (statistically impossible)");
}

/// Registration PDA derivation. Seeds: `[b"reg", oracle_keypair]` —
/// bound to the daemon-side oracle keypair (the key that signs
/// `submit_time` every cycle). One registration per oracle keypair, so
/// rotation = generate fresh keypair, register again; the contract
/// auto-cleans the old one after 10 missed turns.
pub fn derive_registration_pda(oracle_keypair: &[u8; 32], program_id: &[u8; 32]) -> [u8; 32] {
    let (pda, _bump) = find_program_address(&[b"reg", oracle_keypair], program_id);
    pda
}

// ---------------------------------------------------------------------------
// RPC client
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RpcClient {
    urls: Vec<String>,
    fail_counts: Vec<u32>,
    cooldown_until: Vec<i64>,
}

impl RpcClient {
    pub fn new(urls: Vec<String>) -> Self {
        let len = urls.len();
        Self {
            urls,
            fail_counts: vec![0; len],
            cooldown_until: vec![0; len],
        }
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn rpc_call_with_retry<F, T>(&mut self, mut op: F) -> Result<T, String>
    where
        F: FnMut(&str) -> Result<T, String>,
    {
        if self.urls.is_empty() {
            return Err("no rpc endpoints configured".to_string());
        }
        let now = Self::now_secs();

        // Bypass cooldowns when EVERY URL is on cooldown — otherwise the
        // daemon would deadlock for 5 minutes on "no rpc endpoints
        // configured" even though some endpoint might be reachable
        // again. This was the root cause of the v1.2.0 submit_time DNS
        // fallback bug: once a noisy cycle pushed both endpoints past
        // the 3-fail threshold, every subsequent call returned the
        // generic error and silently aborted the cycle.
        let bypass_cooldown = (0..self.urls.len()).all(|i| self.cooldown_until[i] > now);

        // Per-URL error log so the final Err message names the actual
        // endpoint(s) that failed, not just the last one tried. Helps
        // operators diagnose DNS-vs-RPC-vs-firewall issues from logs.
        let mut errors: Vec<String> = Vec::with_capacity(self.urls.len());
        let mut first_failed: Option<String> = None;

        for i in 0..self.urls.len() {
            if !bypass_cooldown && self.cooldown_until[i] > now {
                continue;
            }
            match op(&self.urls[i]) {
                Ok(v) => {
                    if let Some(failed) = &first_failed {
                        if std::env::var("X1SR_DEBUG").is_ok() {
                            eprintln!(
                                "[rpc] fallback: {failed} unreachable, using {}",
                                self.urls[i]
                            );
                        }
                    }
                    // Healthy endpoint: clear both counter AND any
                    // outstanding cooldown so the recovery isn't
                    // shadowed by a stale block.
                    self.fail_counts[i] = 0;
                    self.cooldown_until[i] = 0;
                    return Ok(v);
                }
                Err(e) => {
                    if first_failed.is_none() {
                        first_failed = Some(self.urls[i].clone());
                    }
                    errors.push(format!("{}: {e}", self.urls[i]));
                    self.fail_counts[i] += 1;
                    if self.fail_counts[i] >= 3 {
                        self.cooldown_until[i] = now + 5 * 60;
                        self.fail_counts[i] = 0;
                    }
                }
            }
        }
        Err(format!("all rpc endpoints failed: [{}]", errors.join("; ")))
    }

    pub fn get_recent_blockhash(&mut self) -> Result<[u8; 32], String> {
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": [{ "commitment": "finalized" }]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(8))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            let bh_str = resp
                .pointer("/result/value/blockhash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("missing blockhash: {resp}"))?;
            let raw = bs58::decode(bh_str)
                .into_vec()
                .map_err(|e| format!("{e}"))?;
            if raw.len() != 32 {
                return Err(format!("blockhash length {} != 32", raw.len()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            Ok(out)
        })
    }

    pub fn get_balance(&mut self, pubkey: &str) -> Result<u64, String> {
        let pk = pubkey.to_string();
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [pk, { "commitment": "finalized" }]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(8))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            let lamports = resp
                .pointer("/result/value")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("missing balance: {resp}"))?;
            Ok(lamports)
        })
    }

    pub fn send_transaction(&mut self, tx_b64: &str) -> Result<String, String> {
        let tx_string = tx_b64.to_string();
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sendTransaction",
                "params": [
                    tx_string,
                    { "encoding": "base64", "skipPreflight": false, "preflightCommitment": "finalized" }
                ]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(15))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            if let Some(err) = resp.pointer("/error") {
                return Err(format!("rpc error: {err}"));
            }
            let sig = resp
                .pointer("/result")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("missing signature: {resp}"))?;
            Ok(sig.to_string())
        })
    }

    /// Best-effort chain time used solely to fill the memo's `chain=` and
    /// `drift=` fields. Does not block the submission if it fails.
    pub fn get_chain_time_ms(&mut self) -> Option<i64> {
        let slot = self
            .rpc_call_with_retry(|url| {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getSlot",
                    "params": [{ "commitment": "confirmed" }]
                });
                let resp: serde_json::Value = ureq::post(url)
                    .timeout(Duration::from_secs(6))
                    .send_json(body)
                    .map_err(|e| format!("{e}"))?
                    .into_json()
                    .map_err(|e| format!("{e}"))?;
                resp.pointer("/result")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| "missing slot".to_string())
            })
            .ok()?;

        let block_time = self
            .rpc_call_with_retry(|url| {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getBlockTime",
                    "params": [slot]
                });
                let resp: serde_json::Value = ureq::post(url)
                    .timeout(Duration::from_secs(6))
                    .send_json(body)
                    .map_err(|e| format!("{e}"))?
                    .into_json()
                    .map_err(|e| format!("{e}"))?;
                resp.pointer("/result")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| "missing block_time".to_string())
            })
            .ok()?;

        Some(block_time * 1000)
    }

    /// `getAccountInfo` with base64 encoding — returns the raw account data
    /// bytes (after base64-decoding). Used to fetch vote + stake +
    /// registration accounts for off-chain parsing.
    pub fn fetch_account_info(&mut self, pubkey_b58: &str) -> Result<Vec<u8>, String> {
        let pk = pubkey_b58.to_string();
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [pk, { "encoding": "base64", "commitment": "confirmed" }]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(10))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            if let Some(v) = resp.pointer("/result/value") {
                if v.is_null() {
                    return Err(format!("account {pk} does not exist on chain"));
                }
            }
            let s = resp
                .pointer("/result/value/data/0")
                .and_then(|x| x.as_str())
                .ok_or_else(|| format!("unexpected shape: {resp}"))?;
            base64_decode(s).ok_or_else(|| "base64 decode failed".to_string())
        })
    }

    /// `getEpochInfo` — used for filtering stake accounts by activation_epoch.
    pub fn get_epoch_info(&mut self) -> Result<EpochInfoResponse, String> {
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getEpochInfo",
                "params": [{ "commitment": "confirmed" }]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(8))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            let epoch = resp
                .pointer("/result/epoch")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("missing /result/epoch: {resp}"))?;
            let absolute_slot = resp
                .pointer("/result/absoluteSlot")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("missing /result/absoluteSlot: {resp}"))?;
            Ok(EpochInfoResponse {
                epoch,
                absolute_slot,
            })
        })
    }

    /// `getProgramAccounts` against the stake program with a memcmp filter at
    /// offset 124 (`Delegation.voter_pubkey` in StakeStateV2::Stake variant).
    /// Parses every matching account using the same offsets validated by
    /// Stage 1 integration tests.
    pub fn fetch_stake_accounts_for_vote(
        &mut self,
        vote: &[u8; 32],
    ) -> Result<Vec<StakeAccountInfo>, String> {
        let vote_b58 = bs58::encode(vote).into_string();
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getProgramAccounts",
                "params": [
                    STAKE_PROGRAM_ID_B58,
                    {
                        "encoding": "base64",
                        "commitment": "confirmed",
                        "filters": [
                            { "memcmp": { "offset": 124, "bytes": vote_b58 } }
                        ]
                    }
                ]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(30))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            let arr = resp
                .pointer("/result")
                .and_then(|x| x.as_array())
                .ok_or_else(|| format!("getProgramAccounts shape: {resp}"))?;
            let mut out: Vec<StakeAccountInfo> = Vec::with_capacity(arr.len());
            for item in arr {
                let pk_b58 = match item.pointer("/pubkey").and_then(|x| x.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let data_b64 = match item.pointer("/account/data/0").and_then(|x| x.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let data = match base64_decode(data_b64) {
                    Some(d) => d,
                    None => continue,
                };
                if data.len() < 180 {
                    continue;
                }
                // Discriminant must be 2 (Stake variant).
                let disc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                if disc != 2 {
                    continue;
                }
                let pubkey_raw = bs58::decode(pk_b58)
                    .into_vec()
                    .map_err(|e| format!("pubkey b58: {e}"))?;
                if pubkey_raw.len() != 32 {
                    continue;
                }
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&pubkey_raw);
                let mut withdrawer = [0u8; 32];
                withdrawer.copy_from_slice(&data[44..76]);
                let mut voter = [0u8; 32];
                voter.copy_from_slice(&data[124..156]);
                let stake_amount = u64::from_le_bytes([
                    data[156], data[157], data[158], data[159], data[160], data[161], data[162],
                    data[163],
                ]);
                let activation_epoch = u64::from_le_bytes([
                    data[164], data[165], data[166], data[167], data[168], data[169], data[170],
                    data[171],
                ]);
                let deactivation_epoch = u64::from_le_bytes([
                    data[172], data[173], data[174], data[175], data[176], data[177], data[178],
                    data[179],
                ]);
                out.push(StakeAccountInfo {
                    pubkey,
                    withdrawer,
                    voter,
                    stake_amount,
                    activation_epoch,
                    deactivation_epoch,
                });
            }
            Ok(out)
        })
    }

    /// `getProgramAccounts` against the X1 Strontium program, filtered
    /// to accounts of size `8 + ValidatorRegistration::LEN = 96` bytes.
    /// Returns every active registration with the full body parsed. Used
    /// for rotation membership (`oracle_keypair`) and for `cleanup_inactive`
    /// (`pda` + `last_submitted_window_id`).
    pub fn fetch_active_registrations(
        &mut self,
        program_id: &[u8; 32],
    ) -> Result<Vec<RegistrationEntry>, String> {
        let pid_b58 = bs58::encode(program_id).into_string();
        self.rpc_call_with_retry(|url| {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getProgramAccounts",
                "params": [
                    pid_b58,
                    {
                        "encoding": "base64",
                        "commitment": "confirmed",
                        "filters": [
                            { "dataSize": REG_ACCOUNT_SIZE as u64 }
                        ]
                    }
                ]
            });
            let resp: serde_json::Value = ureq::post(url)
                .timeout(Duration::from_secs(15))
                .send_json(body)
                .map_err(|e| format!("{e}"))?
                .into_json()
                .map_err(|e| format!("{e}"))?;
            let arr = resp
                .pointer("/result")
                .and_then(|x| x.as_array())
                .ok_or_else(|| format!("getProgramAccounts shape: {resp}"))?;
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let pk_b58 = match item.pointer("/pubkey").and_then(|x| x.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let data_b64 = match item.pointer("/account/data/0").and_then(|x| x.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let data = match base64_decode(data_b64) {
                    Some(d) => d,
                    None => continue,
                };
                if data.len() < REG_ACCOUNT_SIZE {
                    continue;
                }
                if data[REG_OFF_IS_ACTIVE] == 0 {
                    continue;
                }
                let pk_raw = match bs58::decode(pk_b58).into_vec() {
                    Ok(v) if v.len() == 32 => v,
                    _ => continue,
                };
                let mut pda = [0u8; 32];
                pda.copy_from_slice(&pk_raw);
                let mut oracle = [0u8; 32];
                oracle.copy_from_slice(&data[REG_OFF_ORACLE..REG_OFF_VOTE]);
                let mut vote = [0u8; 32];
                vote.copy_from_slice(&data[REG_OFF_VOTE..REG_OFF_REGISTERED_AT]);
                let registered_at = i64::from_le_bytes(
                    data[REG_OFF_REGISTERED_AT..REG_OFF_LAST_WINDOW]
                        .try_into()
                        .unwrap(),
                );
                let last_submitted_window_id = u64::from_le_bytes(
                    data[REG_OFF_LAST_WINDOW..REG_OFF_IS_ACTIVE]
                        .try_into()
                        .unwrap(),
                );
                out.push(RegistrationEntry {
                    pda,
                    oracle_keypair: oracle,
                    vote_account: vote,
                    registered_at,
                    last_submitted_window_id,
                    is_active: true,
                });
            }
            Ok(out)
        })
    }

    /// Fetch a single `ValidatorRegistration` PDA. The daemon calls this on
    /// its own registration to detect being cleaned up (e.g. after a long
    /// silent period — `is_active = false` means it must re-register).
    pub fn fetch_registration(&mut self, reg_pda: &[u8; 32]) -> Result<RegistrationEntry, String> {
        let data = self.fetch_account_info(&bs58::encode(reg_pda).into_string())?;
        if data.len() < REG_ACCOUNT_SIZE {
            return Err(format!(
                "ValidatorRegistration account too small: {} bytes (expected {REG_ACCOUNT_SIZE})",
                data.len()
            ));
        }
        let mut oracle = [0u8; 32];
        oracle.copy_from_slice(&data[REG_OFF_ORACLE..REG_OFF_VOTE]);
        let mut vote = [0u8; 32];
        vote.copy_from_slice(&data[REG_OFF_VOTE..REG_OFF_REGISTERED_AT]);
        let registered_at = i64::from_le_bytes(
            data[REG_OFF_REGISTERED_AT..REG_OFF_LAST_WINDOW]
                .try_into()
                .map_err(|e| format!("{e}"))?,
        );
        let last_submitted_window_id = u64::from_le_bytes(
            data[REG_OFF_LAST_WINDOW..REG_OFF_IS_ACTIVE]
                .try_into()
                .map_err(|e| format!("{e}"))?,
        );
        let is_active = data[REG_OFF_IS_ACTIVE] != 0;
        Ok(RegistrationEntry {
            pda: *reg_pda,
            oracle_keypair: oracle,
            vote_account: vote,
            registered_at,
            last_submitted_window_id,
            is_active,
        })
    }

    /// Fetch the OracleState account header — the daemon reads
    /// `n_operators` for rotation math and `last_cleanup_slot` for the
    /// cleanup pre-flight throttle.
    pub fn fetch_oracle_state_header(
        &mut self,
        oracle_pda: &[u8; 32],
    ) -> Result<OracleStateHeader, String> {
        let data = self.fetch_account_info(&bs58::encode(oracle_pda).into_string())?;
        if data.len() < 96 {
            return Err(format!(
                "OracleState account too small: {} bytes (expected >= 96 for header)",
                data.len()
            ));
        }
        // Header offsets after the 8-byte Anchor discriminator:
        //   [82..84]  n_operators (u16)
        //   [88..96]  last_cleanup_slot (u64)
        let n_operators = u16::from_le_bytes(data[82..84].try_into().unwrap());
        let last_cleanup_slot = u64::from_le_bytes(data[88..96].try_into().unwrap());
        Ok(OracleStateHeader {
            n_operators,
            last_cleanup_slot,
        })
    }
}

/// Subset of `OracleState` the daemon actively reads at runtime.
/// `n_operators` is parsed alongside `last_cleanup_slot` for the same
/// header read; main loop currently only consumes `last_cleanup_slot`
/// for the cleanup throttle.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct OracleStateHeader {
    pub n_operators: u16,
    pub last_cleanup_slot: u64,
}

// ---------------------------------------------------------------------------
// Transaction building
// ---------------------------------------------------------------------------

/// Solana compact-u16 length encoding.
pub fn encode_compact_u16(mut n: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return out;
        } else {
            b |= 0x80;
            out.push(b);
        }
    }
}

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{name}").as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Memo-format helper — milliseconds shown with 3 decimal places (`HH:MM:SS.mmm`).
/// Earlier revisions multiplied `ms * 10` to fake a 4-digit field, but that was
/// misleading: a value like `26.4090` reads as "26.4 seconds" rather than
/// "26 s + 409 ms". Three digits matches ISO-8601 fractional-second convention.
pub fn format_clock_3dec(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let ms = unix_ms.rem_euclid(1000) as u64;
    let h = ((secs / 3600) % 24) as u64;
    let m = ((secs / 60) % 60) as u64;
    let s = (secs % 60) as u64;
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}

pub struct SubmitParams<'a> {
    pub consensus: &'a ConsensusResult,
    pub window_id: u64,
    pub memo_enabled: bool,
    pub chain_time_ms: Option<i64>,
    /// The wall-clock UTC ms value the daemon ACTUALLY wants to commit on
    /// chain. Equals `consensus.timestamp_ms + tsc_elapsed_ms` when the
    /// build/sign/RPC pipeline is fast enough (typical case), or
    /// `consensus.timestamp_ms` when the elapsed time exceeds the contract's
    /// 50 ms spread budget (fallback). The contract instruction and the
    /// memo's `{prefix}=` field both use this value, so they always agree.
    pub precise_time_ms: i64,
    /// The daemon's `SystemTime::now()` (UTC ms) captured at the moment the
    /// consensus was computed — i.e. before TSC correction. Recorded for
    /// the memo's `sys=` and `sysdrift=` fields, which signal the health of
    /// the daemon's underlying system clock relative to the NTP consensus.
    pub sys_at_consensus_ms: i64,
}

fn best_stratum(consensus: &ConsensusResult) -> u8 {
    consensus
        .sources
        .iter()
        .map(|r| r.stratum)
        .min()
        .unwrap_or(0)
}

/// Pick the memo prefix from the highest-quality tier present in the kept
/// consensus sources. Order of preference:
///   `gps`  — physical GPS/PPS lock (consensus.is_gps)
///   `nts`  — at least one NTS-secured server in the kept set
///   `s1`   — at least one Stratum-1 server
///   `ntp`  — only Pool-tier sources
fn time_source_prefix(consensus: &ConsensusResult) -> &'static str {
    if consensus.is_gps {
        return "gps";
    }
    if consensus
        .sources
        .iter()
        .any(|s| matches!(s.tier, NtpTier::Nts))
    {
        return "nts";
    }
    if consensus
        .sources
        .iter()
        .any(|s| matches!(s.tier, NtpTier::Stratum1))
    {
        return "s1";
    }
    "ntp"
}

fn build_memo(params: &SubmitParams) -> String {
    // Memo v1 (still v1 — protocol-level identifier, not codebase version).
    // `drift` is the signed delta between our precise consensus estimate
    // and the on-chain `Clock::unix_timestamp` (positive = chain is behind,
    // negative = ahead; X1 chain has historically run 12–20 s behind real
    // UTC). The `sys=` field reports the daemon's system clock at the
    // consensus moment and `sysdrift=` reports precise vs sys, exposing
    // the daemon's local clock health alongside the chain drift signal.
    let prefix = time_source_prefix(params.consensus);
    let time_str = format_clock_3dec(params.precise_time_ms);
    let sys_str = format_clock_3dec(params.sys_at_consensus_ms);
    let sysdrift = params.precise_time_ms - params.sys_at_consensus_ms;
    let (chain_str, drift_str) = match params.chain_time_ms {
        Some(t) => (
            format_clock_3dec(t),
            (params.precise_time_ms - t).to_string(),
        ),
        None => ("??:??:??.???".to_string(), "null".to_string()),
    };
    let conf = (params.consensus.confidence * 100.0).round() as u32;

    // Example:
    //   X1Strontium:v1:w=5921961:nts=08:45:00.003:sys=08:45:00.005:
    //   chain=08:45:00.000:drift=3:sysdrift=-2:c=97:s=10:st=1
    // Length ~120 bytes — well under the 566 B Memo Program limit.
    format!(
        "X1Strontium:v1:w={w}:{prefix}={time}:sys={sys}:chain={chain}:\
         drift={drift}:sysdrift={sysdrift}:c={c}:s={s}:st={st}",
        w = params.window_id,
        prefix = prefix,
        time = time_str,
        sys = sys_str,
        chain = chain_str,
        drift = drift_str,
        sysdrift = sysdrift,
        c = conf,
        s = params.consensus.sources_used,
        st = best_stratum(params.consensus),
    )
}

fn pubkey_from_b58(s: &str) -> Result<[u8; 32], String> {
    let raw = bs58::decode(s).into_vec().map_err(|e| format!("{e}"))?;
    if raw.len() != 32 {
        return Err(format!("pubkey {s}: length {} != 32", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn write_compact(buf: &mut Vec<u8>, n: u16) {
    buf.extend_from_slice(&encode_compact_u16(n));
}

/// Build and sign a `submit_time` Anchor transaction (optionally with a
/// Memo instruction). Signer = `oracle_keypair`. The contract
/// instruction touches only `oracle_state` and the caller's own
/// `registration` PDA — no vote account, no stake remaining_accounts.
pub fn build_submit_transaction_signed(
    keypair: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    registration_pda: &[u8; 32],
    blockhash: &[u8; 32],
    params: &SubmitParams,
) -> Vec<u8> {
    let signer_pubkey: [u8; 32] = keypair.verifying_key().to_bytes();
    let memo_program =
        pubkey_from_b58(MEMO_PROGRAM_ID_B58).expect("memo program id is constant and valid");

    // Account ordering (Solana message header convention):
    //   writable_signed   = [oracle_keypair]                 (pays fees)
    //   readonly_signed   = []
    //   writable_unsigned = [oracle_pda, registration_pda]   (both mutated)
    //   readonly_unsigned = [program_id, memo_program?]
    let mut ordered_keys: Vec<[u8; 32]> =
        vec![signer_pubkey, *oracle_pda, *registration_pda, *program_id];
    if params.memo_enabled {
        ordered_keys.push(memo_program);
    }
    let num_required_signatures: u8 = 1;
    let num_readonly_signed: u8 = 0;
    let num_readonly_unsigned: u8 = if params.memo_enabled { 2 } else { 1 };

    let idx = |key: &[u8; 32]| -> u8 {
        ordered_keys
            .iter()
            .position(|k| k == key)
            .expect("ordered_keys must contain all referenced accounts") as u8
    };

    // ---- Instruction 1: submit_time(SubmitTimeArgs) ----
    let discriminator = anchor_discriminator("submit_time");
    let mut ix1_data: Vec<u8> = Vec::with_capacity(8 + 8 + 2 + 1 + 1 + 8);
    ix1_data.extend_from_slice(&discriminator);
    ix1_data.extend_from_slice(&params.precise_time_ms.to_le_bytes());
    ix1_data.extend_from_slice(&(params.consensus.spread_ms as i16).to_le_bytes());
    let conf_pct: u8 = (params.consensus.confidence * 100.0)
        .clamp(0.0, 255.0)
        .round() as u8;
    ix1_data.push(params.consensus.sources_used);
    ix1_data.push(conf_pct);
    ix1_data.extend_from_slice(&params.consensus.sources_bitmap.to_le_bytes());

    // SubmitTime Anchor derive order: oracle_state, registration, submitter
    let ix1_accounts: Vec<u8> = vec![idx(oracle_pda), idx(registration_pda), idx(&signer_pubkey)];
    let ix1_program_id_index = idx(program_id);

    // ---- Optional Instruction 2: Memo ----
    let memo_string = build_memo(params);
    let memo_bytes = memo_string.as_bytes();
    let memo_program_idx = if params.memo_enabled {
        Some(idx(&memo_program))
    } else {
        None
    };

    // ---- Build message ----
    let mut msg = Vec::with_capacity(256);
    msg.push(num_required_signatures);
    msg.push(num_readonly_signed);
    msg.push(num_readonly_unsigned);

    write_compact(&mut msg, ordered_keys.len() as u16);
    for k in &ordered_keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(blockhash);

    let n_instructions: u16 = if params.memo_enabled { 2 } else { 1 };
    write_compact(&mut msg, n_instructions);

    msg.push(ix1_program_id_index);
    write_compact(&mut msg, ix1_accounts.len() as u16);
    msg.extend_from_slice(&ix1_accounts);
    write_compact(&mut msg, ix1_data.len() as u16);
    msg.extend_from_slice(&ix1_data);

    if let Some(memo_idx) = memo_program_idx {
        msg.push(memo_idx);
        write_compact(&mut msg, 0);
        write_compact(&mut msg, memo_bytes.len() as u16);
        msg.extend_from_slice(memo_bytes);
    }

    let sig = keypair.sign(&msg).to_bytes();

    let mut tx = Vec::with_capacity(64 + msg.len() + 4);
    write_compact(&mut tx, 1);
    tx.extend_from_slice(&sig);
    tx.extend_from_slice(&msg);
    tx
}

/// Build and sign a `register_submitter` Anchor transaction. Two signers
/// are required: the freshly funded `oracle_keypair` (which pays rent for
/// the new `ValidatorRegistration` PDA) and the validator's `vote_keypair`
/// (which co-signs as proof that the operator controls both halves of the
/// system). The contract performs no vote-account validation — the daemon
/// must enforce the off-chain anti-farm gates (epoch credits, qualifying
/// self-stake) BEFORE building this TX.
pub fn build_register_transaction(
    oracle_keypair: &SigningKey,
    vote_keypair: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    registration_pda: &[u8; 32],
    blockhash: &[u8; 32],
) -> Vec<u8> {
    let oracle_pubkey: [u8; 32] = oracle_keypair.verifying_key().to_bytes();
    let vote_pubkey: [u8; 32] = vote_keypair.verifying_key().to_bytes();

    // Account ordering:
    //   writable_signed   = [oracle_keypair]                  (pays fees + rent)
    //   readonly_signed   = [vote_keypair]                    (co-signs only)
    //   writable_unsigned = [registration_pda, oracle_pda]    (both mutated)
    //   readonly_unsigned = [program_id, system_program]
    let ordered_keys: Vec<[u8; 32]> = vec![
        oracle_pubkey,
        vote_pubkey,
        *registration_pda,
        *oracle_pda,
        *program_id,
        SYSTEM_PROGRAM_ID,
    ];
    let num_required_signatures: u8 = 2;
    let num_readonly_signed: u8 = 1;
    let num_readonly_unsigned: u8 = 2;

    let idx = |key: &[u8; 32]| -> u8 {
        ordered_keys
            .iter()
            .position(|k| k == key)
            .expect("ordered_keys must contain all referenced accounts") as u8
    };

    // RegisterSubmitter Anchor derive order:
    //   registration, oracle_state, oracle_keypair, vote_keypair, system_program
    let discriminator = anchor_discriminator("register_submitter");
    let ix_data: Vec<u8> = discriminator.to_vec();
    let ix_accounts: Vec<u8> = vec![
        idx(registration_pda),
        idx(oracle_pda),
        idx(&oracle_pubkey),
        idx(&vote_pubkey),
        idx(&SYSTEM_PROGRAM_ID),
    ];
    let ix_program_id_index = idx(program_id);

    let mut msg = Vec::with_capacity(256);
    msg.push(num_required_signatures);
    msg.push(num_readonly_signed);
    msg.push(num_readonly_unsigned);

    write_compact(&mut msg, ordered_keys.len() as u16);
    for k in &ordered_keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(blockhash);

    write_compact(&mut msg, 1);
    msg.push(ix_program_id_index);
    write_compact(&mut msg, ix_accounts.len() as u16);
    msg.extend_from_slice(&ix_accounts);
    write_compact(&mut msg, ix_data.len() as u16);
    msg.extend_from_slice(&ix_data);

    let sig_oracle = oracle_keypair.sign(&msg).to_bytes();
    let sig_vote = vote_keypair.sign(&msg).to_bytes();

    let mut tx = Vec::with_capacity(64 * 2 + msg.len() + 4);
    write_compact(&mut tx, 2);
    tx.extend_from_slice(&sig_oracle);
    tx.extend_from_slice(&sig_vote);
    tx.extend_from_slice(&msg);
    tx
}

/// Build and sign a `cleanup_inactive` Anchor transaction with a batch of
/// candidate `ValidatorRegistration` PDAs in `remaining_accounts` (all
/// passed as writable). The fee payer is also the lone signer; lamports
/// from any closed PDA flow back to this same key (the contract uses
/// `payer` both as `Signer<'info>` and as the destination of
/// `acct.close()`). The contract iterates the batch and CLOSES any
/// stale `ValidatorRegistration` PDA (lamports → payer, data zeroed,
/// discriminator overwritten with `CLOSED_ACCOUNT_DISCRIMINATOR`),
/// recomputing `n_operators` / `quorum_threshold` / `last_cleanup_slot`.
/// v1.2.1 fix: prior versions only flipped `is_active = false`, which
/// left the PDA on chain and prevented re-registration with the same
/// `oracle_keypair`.
pub fn build_cleanup_inactive_transaction(
    fee_payer: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    registration_pdas: &[[u8; 32]],
    blockhash: &[u8; 32],
) -> Vec<u8> {
    let payer_pubkey: [u8; 32] = fee_payer.verifying_key().to_bytes();

    // Defensive dedup of registration_pdas against the fixed account set
    // and against each other (AccountLoadedTwice rejects the TX otherwise).
    let mut fixed: Vec<[u8; 32]> = vec![payer_pubkey, *oracle_pda, *program_id];
    let mut regs: Vec<[u8; 32]> = Vec::with_capacity(registration_pdas.len());
    for r in registration_pdas {
        if fixed.contains(r) || regs.contains(r) {
            continue;
        }
        regs.push(*r);
    }
    fixed.extend_from_slice(&regs);
    let _ = fixed; // silence unused after dedup; ordered_keys is the real list

    // Account ordering:
    //   writable_signed   = [fee_payer]
    //   readonly_signed   = []
    //   writable_unsigned = [oracle_pda, *regs]
    //   readonly_unsigned = [program_id]
    let mut ordered_keys: Vec<[u8; 32]> = vec![payer_pubkey, *oracle_pda];
    for r in &regs {
        ordered_keys.push(*r);
    }
    ordered_keys.push(*program_id);

    let num_required_signatures: u8 = 1;
    let num_readonly_signed: u8 = 0;
    let num_readonly_unsigned: u8 = 1;

    let idx = |key: &[u8; 32]| -> u8 {
        ordered_keys
            .iter()
            .position(|k| k == key)
            .expect("ordered_keys must contain all referenced accounts") as u8
    };

    // CleanupInactive Anchor derive order (v1.2.1):
    //   [0] oracle_state    (writable, PDA)
    //   [1] payer           (writable, signer — receives closed-PDA lamports)
    //   [2..] remaining_accounts (writable, registration PDAs)
    let discriminator = anchor_discriminator("cleanup_inactive");
    let ix_data: Vec<u8> = discriminator.to_vec();
    let mut ix_accounts: Vec<u8> = vec![idx(oracle_pda), idx(&payer_pubkey)];
    for r in &regs {
        ix_accounts.push(idx(r));
    }
    let ix_program_id_index = idx(program_id);

    let mut msg = Vec::with_capacity(256 + 32 * regs.len());
    msg.push(num_required_signatures);
    msg.push(num_readonly_signed);
    msg.push(num_readonly_unsigned);

    write_compact(&mut msg, ordered_keys.len() as u16);
    for k in &ordered_keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(blockhash);

    write_compact(&mut msg, 1);
    msg.push(ix_program_id_index);
    write_compact(&mut msg, ix_accounts.len() as u16);
    msg.extend_from_slice(&ix_accounts);
    write_compact(&mut msg, ix_data.len() as u16);
    msg.extend_from_slice(&ix_data);

    let sig = fee_payer.sign(&msg).to_bytes();

    let mut tx = Vec::with_capacity(64 + msg.len() + 4);
    write_compact(&mut tx, 1);
    tx.extend_from_slice(&sig);
    tx.extend_from_slice(&msg);
    tx
}

/// Build a signed `initialize` Anchor transaction — no arguments, the
/// contract stores the signer's pubkey as `oracle_state.authority` and
/// sets `n_operators = 0` / `quorum_threshold = required_quorum(0) = 1`.
///
/// Accounts in instruction order (per the `Initialize` derive):
///   [0] oracle_state    (writable, non-signer, PDA — created by the program)
///   [1] authority       (writable, signer — pays rent for the new PDA)
///   [2] system_program  (read-only, non-signer — used by `init`)
pub fn build_initialize_transaction(
    authority: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    blockhash: &[u8; 32],
) -> Vec<u8> {
    let auth_pubkey: [u8; 32] = authority.verifying_key().to_bytes();

    // Account order in the message header:
    //   writable_signed   | readonly_signed | writable_unsigned | readonly_unsigned
    //   [authority]       | []              | [oracle_pda]      | [program_id, system_program]
    let ordered_keys: Vec<[u8; 32]> =
        vec![auth_pubkey, *oracle_pda, *program_id, SYSTEM_PROGRAM_ID];

    let num_required_signatures: u8 = 1;
    let num_readonly_signed: u8 = 0;
    let num_readonly_unsigned: u8 = 2;

    let idx = |key: &[u8; 32]| -> u8 {
        ordered_keys
            .iter()
            .position(|k| k == key)
            .expect("ordered_keys must contain all referenced accounts") as u8
    };

    let discriminator = anchor_discriminator("initialize");
    // `initialize` takes no instruction arguments — the discriminator alone
    // is the entire ix data.
    let ix_data: Vec<u8> = discriminator.to_vec();
    let ix_accounts: Vec<u8> = vec![idx(oracle_pda), idx(&auth_pubkey), idx(&SYSTEM_PROGRAM_ID)];
    let ix_program_id_index = idx(program_id);

    let mut msg = Vec::with_capacity(256);
    msg.push(num_required_signatures);
    msg.push(num_readonly_signed);
    msg.push(num_readonly_unsigned);

    write_compact(&mut msg, ordered_keys.len() as u16);
    for k in &ordered_keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(blockhash);

    write_compact(&mut msg, 1);
    msg.push(ix_program_id_index);
    write_compact(&mut msg, ix_accounts.len() as u16);
    msg.extend_from_slice(&ix_accounts);
    write_compact(&mut msg, ix_data.len() as u16);
    msg.extend_from_slice(&ix_data);

    let sig = authority.sign(&msg).to_bytes();

    let mut tx = Vec::with_capacity(64 + msg.len() + 4);
    write_compact(&mut tx, 1);
    tx.extend_from_slice(&sig);
    tx.extend_from_slice(&msg);
    tx
}

// Operator onboarding is daemon-driven: `cmd_register` builds the
// `register_submitter` TX after enforcing the off-chain anti-farm gates
// (epoch credits ≥ 64 + withdrawer-match qualifying stake). The operator's
// hardware wallet (Ledger / Trezor / etc.) is invoked exactly once,
// out-of-band, to fund the freshly generated `oracle_keypair` via native
// `solana transfer`. See docs/OPERATOR_ONBOARDING.md.

// ---------------------------------------------------------------------------
// Vote-account parsing helpers (off-chain anti-farm gate)
// ---------------------------------------------------------------------------

/// Walk a `VoteStateVersions::Current` body to read the `epoch_credits`
/// length. The daemon enforces the ≥ 64-epoch anti-farm gate at register
/// time before sending `register_submitter`; the contract itself holds no
/// vote-account parser.
///
/// Byte offsets match the bincode serialisation rules validated against
/// live X1 mainnet during v1.0 development. Variable-length sections are
/// walked rather than peeked (votes VecDeque, root_slot Option,
/// authorized_voters BTreeMap, prior_voters fixed CircBuf).
pub fn parse_vote_epoch_credits_len(data: &[u8]) -> Result<u64, String> {
    if data.len() < 69 {
        return Err(format!("vote account too small: {} bytes", data.len()));
    }
    let tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if tag != 2 {
        return Err(format!(
            "unsupported VoteStateVersions tag {tag} (expected 2 = Current)"
        ));
    }

    let mut off: usize = 69;

    // votes: VecDeque<LandedVote> — u64 len + len × 13
    if data.len() < off + 8 {
        return Err("vote account truncated at votes".to_string());
    }
    let votes_len = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as usize;
    off = off.checked_add(8).ok_or("offset overflow at votes")?;
    let votes_bytes = votes_len.checked_mul(13).ok_or("votes_len overflow")?;
    off = off
        .checked_add(votes_bytes)
        .ok_or("offset overflow past votes")?;

    // root_slot: Option<Slot>
    if data.len() < off + 1 {
        return Err("vote account truncated at root_slot".to_string());
    }
    let root_tag = data[off];
    off = off.checked_add(1).ok_or("offset overflow at root tag")?;
    if root_tag == 1 {
        off = off
            .checked_add(8)
            .ok_or("offset overflow at root payload")?;
    } else if root_tag != 0 {
        return Err(format!("unknown root_slot Option tag: {root_tag}"));
    }

    // authorized_voters: BTreeMap<Epoch, Pubkey> — u64 len + len × 40
    if data.len() < off + 8 {
        return Err("vote account truncated at authorized_voters".to_string());
    }
    let av_len = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as usize;
    off = off.checked_add(8).ok_or("offset overflow at av")?;
    let av_bytes = av_len.checked_mul(40).ok_or("av_len overflow")?;
    off = off.checked_add(av_bytes).ok_or("offset overflow past av")?;

    // prior_voters: CircBuf<(Pubkey, Epoch, Epoch), 32> — fixed 1545 B
    off = off
        .checked_add(1545)
        .ok_or("offset overflow at prior_voters")?;

    // epoch_credits: Vec<(Epoch, u64, u64)> — u64 len follows
    if data.len() < off + 8 {
        return Err("vote account truncated at epoch_credits".to_string());
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn lamports_to_xnt(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_XNT
}

/// Per-submission cost in XNT (`submit_time` + `Memo` instruction combined),
/// measured empirically against the X1 mainnet fee schedule. Used by both
/// `estimate_days_remaining` and the human-facing `x1-strontium balance`
/// output, so any future fee change touches one place only.
pub const COST_PER_TX_XNT: f64 = 0.004;

/// Days of fee runway given a balance, interval, and fleet size.
///
/// In a fleet of `n_operators` the rotation gives each operator on
/// average `1/n` of the windows, so daily TX cost scales as
/// `cost_per_tx * (86400/interval) / n`. `n_operators = 0` is treated
/// as 1 (defensive — solo estimate).
pub fn estimate_days_remaining(balance_xnt: f64, interval_s: u64, n_operators: u16) -> f64 {
    if balance_xnt <= 0.0 || interval_s == 0 {
        return 0.0;
    }
    let n = n_operators.max(1) as f64;
    let tx_per_day: f64 = 86_400.0 / interval_s as f64;
    let daily_cost = COST_PER_TX_XNT * tx_per_day / n;
    if daily_cost <= 0.0 {
        return f64::INFINITY;
    }
    balance_xnt / daily_cost
}

/// Standard base64 encoder. Pure Rust, no external dependency.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let b0 = data[i];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = data[i];
        let b1 = data[i + 1];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[((b1 & 0x0f) << 2) as usize] as char);
        out.push('=');
    }
    out
}

/// Minimal base64 decoder (standard alphabet). Returns `None` on invalid
/// characters. Whitespace is ignored. Used by RpcClient's getAccountInfo /
/// getProgramAccounts helpers that parse base64 account data inline.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn v(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out: Vec<u8> = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let v0 = v(chunk[0])?;
        let v1 = v(chunk[1])?;
        out.push((v0 << 2) | (v1 >> 4));
        if chunk.len() >= 3 && chunk[2] != b'=' {
            let v2 = v(chunk[2])?;
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            if chunk.len() == 4 && chunk[3] != b'=' {
                let v3 = v(chunk[3])?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests — time_source_prefix + memo v1 format
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp_client::NtpResult;

    fn mock_source(tier: NtpTier, host: &str, stratum: u8) -> NtpResult {
        NtpResult {
            host: host.to_string(),
            offset_ms: 0,
            rtt_ms: 10,
            stratum,
            tier,
        }
    }

    fn mock_consensus(sources: Vec<NtpResult>, is_gps: bool) -> ConsensusResult {
        let n = sources.len() as u8;
        ConsensusResult {
            timestamp_ms: 1_713_184_500_003, // 2024-04-15T14:35:00.003Z
            spread_ms: 1,
            confidence: 0.97,
            sources_used: n,
            sources_bitmap: 0x000003FF,
            is_gps,
            sources,
        }
    }

    fn mock_params<'a>(
        consensus: &'a ConsensusResult,
        chain_time_ms: Option<i64>,
        precise_time_ms: i64,
    ) -> SubmitParams<'a> {
        SubmitParams {
            consensus,
            window_id: 5_921_961,
            memo_enabled: true,
            chain_time_ms,
            precise_time_ms,
            // Default to sys = precise + 5 ms — gives a stable, non-zero
            // sysdrift in tests. Override per-test where needed.
            sys_at_consensus_ms: precise_time_ms + 5,
        }
    }

    // ---------- time_source_prefix ----------

    #[test]
    fn prefix_gps_when_is_gps_true() {
        let c = mock_consensus(vec![mock_source(NtpTier::Stratum1, "s1.x", 1)], true);
        assert_eq!(time_source_prefix(&c), "gps");
    }

    #[test]
    fn prefix_nts_when_any_nts_source() {
        let c = mock_consensus(
            vec![
                mock_source(NtpTier::Stratum1, "s1.x", 1),
                mock_source(NtpTier::Nts, "nts.x", 1),
                mock_source(NtpTier::Pool, "pool.x", 2),
            ],
            false,
        );
        assert_eq!(time_source_prefix(&c), "nts");
    }

    #[test]
    fn prefix_s1_when_only_stratum1_sources() {
        let c = mock_consensus(
            vec![
                mock_source(NtpTier::Stratum1, "a.x", 1),
                mock_source(NtpTier::Stratum1, "b.x", 1),
                mock_source(NtpTier::Pool, "c.x", 2),
            ],
            false,
        );
        assert_eq!(time_source_prefix(&c), "s1");
    }

    #[test]
    fn prefix_ntp_when_only_pool_sources() {
        let c = mock_consensus(
            vec![
                mock_source(NtpTier::Pool, "p1.x", 2),
                mock_source(NtpTier::Pool, "p2.x", 3),
            ],
            false,
        );
        assert_eq!(time_source_prefix(&c), "ntp");
    }

    #[test]
    fn prefix_gps_wins_over_nts() {
        // is_gps=true should override even when NTS sources are present.
        let c = mock_consensus(vec![mock_source(NtpTier::Nts, "nts.x", 1)], true);
        assert_eq!(time_source_prefix(&c), "gps");
    }

    // ---------- memo v1 ----------

    #[test]
    fn memo_v1_starts_with_correct_prefix() {
        let c = mock_consensus(vec![mock_source(NtpTier::Stratum1, "s1.x", 1)], false);
        let p = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        let memo = build_memo(&p);
        assert!(memo.starts_with("X1Strontium:v1:"), "prefix: {memo}");
    }

    #[test]
    fn memo_v1_contains_drift_field() {
        let c = mock_consensus(vec![mock_source(NtpTier::Stratum1, "s1.x", 1)], false);
        let p = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        let memo = build_memo(&p);
        // precise=...500_003, chain=...500_000 → drift=3
        assert!(memo.contains(":drift=3:"), "expect :drift=3: in: {memo}");
    }

    #[test]
    fn memo_v1_drift_can_be_negative_or_null() {
        let c = mock_consensus(vec![mock_source(NtpTier::Stratum1, "s1.x", 1)], false);
        // chain ahead of precise → negative drift
        let p_neg = mock_params(&c, Some(1_713_184_500_010), 1_713_184_500_003);
        let memo_neg = build_memo(&p_neg);
        assert!(
            memo_neg.contains(":drift=-7:"),
            "negative drift expected, got: {memo_neg}"
        );
        // chain unavailable → drift=null
        let p_null = mock_params(&c, None, 1_713_184_500_003);
        let memo_null = build_memo(&p_null);
        assert!(
            memo_null.contains(":drift=null:"),
            "null drift expected, got: {memo_null}"
        );
    }

    #[test]
    fn memo_v1_prefix_for_nts_sources() {
        let c = mock_consensus(
            vec![
                mock_source(NtpTier::Nts, "nts.x", 1),
                mock_source(NtpTier::Stratum1, "s1.x", 1),
            ],
            false,
        );
        let p = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        let memo = build_memo(&p);
        assert!(
            memo.contains(":nts="),
            "expect :nts= time field, got: {memo}"
        );
    }

    #[test]
    fn memo_v1_length_under_566_bytes() {
        let c = mock_consensus(
            (0..10)
                .map(|i| mock_source(NtpTier::Nts, "nts.example.org", i + 1))
                .collect(),
            false,
        );
        let p = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        let memo = build_memo(&p);
        assert!(
            memo.len() <= 566,
            "memo too long: {} bytes — Memo Program rejects > 566",
            memo.len()
        );
    }

    #[test]
    fn memo_v1_has_sys_fields() {
        // Mandate: every memo carries `sys=HH:MM:SS.mmm` and
        // `sysdrift=N` so stat sites can monitor each operator's local
        // system-clock health alongside the chain drift.
        let c = mock_consensus(vec![mock_source(NtpTier::Stratum1, "s1.x", 1)], false);
        // precise = 1_713_184_500_003, sys = precise + 5 = 1_713_184_500_008
        // ⇒ sysdrift = precise - sys = -5
        let p = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        let memo = build_memo(&p);
        assert!(memo.contains(":sys="), "missing :sys= field in: {memo}");
        assert!(
            memo.contains(":sysdrift=-5:"),
            "expect :sysdrift=-5: in: {memo}"
        );

        // Override sys to be earlier than precise — sysdrift should flip
        // sign (positive = NTP consensus is ahead of system clock).
        let mut p2 = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        p2.sys_at_consensus_ms = 1_713_184_499_990; // 13 ms before precise
        let memo2 = build_memo(&p2);
        assert!(
            memo2.contains(":sysdrift=13:"),
            "expect :sysdrift=13: in: {memo2}"
        );
    }

    /// Regression test mandated by the rebuild mission: the v0.5 STAMP
    /// memo fields (`:ppm=`, `:off=`, `:tsc=`, `:ent=`, `:stamp=`) must
    /// never reappear. If anyone re-adds a STAMP measurement path and
    /// accidentally wires it back into the memo, this test fails loudly.
    #[test]
    fn memo_v1_has_no_stamp_fields() {
        // Exhaustive-feeling fixture: GPS + NTS + Stratum1 + Pool so the
        // format path branches all run.
        let c = mock_consensus(
            vec![
                mock_source(NtpTier::Nts, "nts.x", 1),
                mock_source(NtpTier::Stratum1, "s1.x", 1),
                mock_source(NtpTier::Pool, "pool.x", 2),
            ],
            true,
        );
        let p = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        let memo = build_memo(&p);
        for banned in [":ppm=", ":off=", ":tsc=", ":ent=", ":stamp="] {
            assert!(
                !memo.contains(banned),
                "banned STAMP field `{banned}` found in memo: {memo}"
            );
        }

        // Also verify it with `memo_enabled = false` path — even when
        // SubmitParams says memo is disabled, build_memo output must still
        // not contain stamp fields (defense in depth).
        let mut p2 = mock_params(&c, Some(1_713_184_500_000), 1_713_184_500_003);
        p2.memo_enabled = false;
        let memo2 = build_memo(&p2);
        for banned in [":ppm=", ":off=", ":tsc=", ":ent=", ":stamp="] {
            assert!(
                !memo2.contains(banned),
                "banned STAMP field `{banned}` found in memo (memo_disabled path): {memo2}"
            );
        }
    }

    // ---------- Fix 1 (v1.2.0): runway scales with fleet size ----------

    #[test]
    fn estimate_days_remaining_solo_baseline_is_one_day_per_1152xnt() {
        // Solo (n=1): every window is mine. At 5-min cadence:
        //   tx_per_day = 86400/300 = 288
        //   daily_cost = 0.004 * 288 / 1 = 1.152 XNT/day
        //   1.152 XNT balance ⇒ exactly 1.0 day.
        let runway = estimate_days_remaining(1.152, 300, 1);
        assert!(
            (runway - 1.0).abs() < 0.001,
            "expected ~1.0 day runway, got {runway}"
        );
    }

    #[test]
    fn estimate_days_remaining_doubles_when_fleet_doubles() {
        // n=2: each operator pays for half the windows. Same balance
        // funds twice as long.
        let solo = estimate_days_remaining(1.152, 300, 1);
        let pair = estimate_days_remaining(1.152, 300, 2);
        assert!(
            (pair / solo - 2.0).abs() < 0.01,
            "expected pair/solo ratio ~2.0, got {}",
            pair / solo
        );
    }

    #[test]
    fn estimate_days_remaining_zero_n_treated_as_solo() {
        // Defensive: a caller passing n_operators = 0 must not divide
        // by zero — clamp to 1 (solo estimate).
        let solo = estimate_days_remaining(1.152, 300, 1);
        let zero = estimate_days_remaining(1.152, 300, 0);
        assert_eq!(solo, zero);
    }

    #[test]
    fn estimate_days_remaining_large_fleet_extends_runway() {
        // n=100: ~100x runway vs solo (small rounding from f64 arithmetic).
        let solo = estimate_days_remaining(1.152, 300, 1);
        let big = estimate_days_remaining(1.152, 300, 100);
        assert!(
            (big / solo - 100.0).abs() < 0.5,
            "expected ~100x runway, got ratio {}",
            big / solo
        );
    }

    // ---------- RpcClient::rpc_call_with_retry (BUG 1 v1.2.1) ----------

    #[test]
    fn rpc_retry_empty_urls_returns_specific_error() {
        let mut rpc = RpcClient::new(vec![]);
        let r: Result<(), String> = rpc.rpc_call_with_retry(|_| Ok(()));
        assert_eq!(r, Err("no rpc endpoints configured".to_string()));
    }

    #[test]
    fn rpc_retry_succeeds_on_first_url_when_healthy() {
        let mut rpc = RpcClient::new(vec![
            "https://primary".to_string(),
            "https://secondary".to_string(),
        ]);
        let mut calls: Vec<String> = Vec::new();
        let r = rpc.rpc_call_with_retry(|url| {
            calls.push(url.to_string());
            Ok::<_, String>(42u32)
        });
        assert_eq!(r, Ok(42));
        assert_eq!(calls, vec!["https://primary"]);
        assert_eq!(rpc.fail_counts, vec![0, 0]);
        assert_eq!(rpc.cooldown_until, vec![0, 0]);
    }

    #[test]
    fn rpc_retry_falls_back_to_secondary_when_primary_fails() {
        let mut rpc = RpcClient::new(vec![
            "https://primary".to_string(),
            "https://secondary".to_string(),
        ]);
        let mut calls: Vec<String> = Vec::new();
        let r = rpc.rpc_call_with_retry(|url| {
            calls.push(url.to_string());
            if url == "https://primary" {
                Err::<u32, _>("dns error".to_string())
            } else {
                Ok(7u32)
            }
        });
        assert_eq!(r, Ok(7));
        assert_eq!(calls, vec!["https://primary", "https://secondary"]);
        // Primary failed once → fail_count=1, no cooldown yet (threshold=3).
        assert_eq!(rpc.fail_counts[0], 1);
        assert_eq!(rpc.cooldown_until[0], 0);
        // Secondary succeeded → counter and cooldown both cleared.
        assert_eq!(rpc.fail_counts[1], 0);
        assert_eq!(rpc.cooldown_until[1], 0);
    }

    #[test]
    fn rpc_retry_all_fail_returns_per_url_diagnostics() {
        let mut rpc = RpcClient::new(vec![
            "https://primary".to_string(),
            "https://secondary".to_string(),
        ]);
        let r: Result<u32, String> = rpc.rpc_call_with_retry(|url| {
            if url == "https://primary" {
                Err("dns error".to_string())
            } else {
                Err("timeout".to_string())
            }
        });
        let err = r.unwrap_err();
        assert!(err.contains("https://primary: dns error"), "got: {err}");
        assert!(err.contains("https://secondary: timeout"), "got: {err}");
        assert!(err.starts_with("all rpc endpoints failed: ["), "got: {err}");
    }

    #[test]
    fn rpc_retry_third_consecutive_failure_arms_cooldown() {
        let mut rpc = RpcClient::new(vec!["https://only".to_string()]);
        for _ in 0..3 {
            let _: Result<u32, String> = rpc.rpc_call_with_retry(|_| Err("boom".to_string()));
        }
        // After 3 failures: cooldown armed (now + 5min), counter reset to 0.
        assert_eq!(rpc.fail_counts[0], 0);
        assert!(rpc.cooldown_until[0] > 0, "cooldown should be armed");
    }

    /// BUG 1 root cause: when EVERY URL is on cooldown the loop body
    /// would `continue` past every entry and fall through to the empty-
    /// errors `Err(...)` branch, returning a generic message and silently
    /// aborting the cycle for up to 5 minutes. The bypass flag forces the
    /// retry to attempt every URL one more time even while their
    /// cooldowns are still nominally in effect.
    #[test]
    fn rpc_retry_bypasses_when_all_urls_on_cooldown() {
        let mut rpc = RpcClient::new(vec!["https://a".to_string(), "https://b".to_string()]);
        // Simulate "both URLs cooled" — the exact state that broke
        // submit_time on Sentinel.
        let future = RpcClient::now_secs() + 300;
        rpc.cooldown_until = vec![future, future];

        let mut tried: Vec<String> = Vec::new();
        let r = rpc.rpc_call_with_retry(|url| {
            tried.push(url.to_string());
            if url == "https://a" {
                Err::<u32, _>("still down".to_string())
            } else {
                Ok(99u32)
            }
        });

        assert_eq!(r, Ok(99), "expected bypass to find healthy URL");
        assert_eq!(
            tried,
            vec!["https://a", "https://b"],
            "both URLs must be tried under bypass"
        );
        // Recovered URL: counter AND cooldown cleared.
        assert_eq!(rpc.cooldown_until[1], 0);
        assert_eq!(rpc.fail_counts[1], 0);
    }

    /// Counter-check: when at least one URL is NOT on cooldown the
    /// bypass does NOT kick in, and the cooled URL is correctly skipped.
    #[test]
    fn rpc_retry_skips_cooldown_when_some_url_available() {
        let mut rpc = RpcClient::new(vec!["https://cold".to_string(), "https://warm".to_string()]);
        rpc.cooldown_until = vec![RpcClient::now_secs() + 300, 0];

        let mut tried: Vec<String> = Vec::new();
        let r = rpc.rpc_call_with_retry(|url| {
            tried.push(url.to_string());
            Ok::<_, String>(1u32)
        });
        assert_eq!(r, Ok(1));
        // Cold URL skipped, only the warm one is hit.
        assert_eq!(tried, vec!["https://warm"]);
        // Cold URL still cooled — bypass did NOT trigger.
        assert!(rpc.cooldown_until[0] > 0);
    }

    // ---------- build_cleanup_inactive_transaction (BUG 3 v1.2.1) ----------

    /// Decode just enough of a built TX to inspect its account layout
    /// and instruction-account index list. Returns
    /// (ordered_keys, ix_program_id_index, ix_accounts).
    fn parse_cleanup_tx_layout(tx: &[u8]) -> (Vec<[u8; 32]>, u8, Vec<u8>) {
        // [compact(num_sigs)] [sigs...] [msg]
        // For 1 signature: compact(1) = 0x01.
        assert_eq!(tx[0], 1, "expected exactly 1 signature");
        let mut p = 1 + 64;

        // Header.
        let _num_required_signatures = tx[p];
        p += 1;
        let _num_readonly_signed = tx[p];
        p += 1;
        let _num_readonly_unsigned = tx[p];
        p += 1;

        // compact(account_keys.len()).
        let n_keys = tx[p] as usize; // small fleet → fits in 1 byte
        assert!(
            n_keys < 0x80,
            "test only supports 1-byte compact for n_keys"
        );
        p += 1;

        let mut ordered_keys: Vec<[u8; 32]> = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            let mut k = [0u8; 32];
            k.copy_from_slice(&tx[p..p + 32]);
            ordered_keys.push(k);
            p += 32;
        }

        // Skip blockhash.
        p += 32;

        // compact(num_instructions = 1).
        assert_eq!(tx[p], 1, "expected exactly 1 instruction");
        p += 1;
        let ix_program_id_index = tx[p];
        p += 1;
        // compact(ix_accounts.len()).
        let n_ix_accounts = tx[p] as usize;
        assert!(
            n_ix_accounts < 0x80,
            "test only supports 1-byte compact for n_ix_accounts"
        );
        p += 1;
        let ix_accounts = tx[p..p + n_ix_accounts].to_vec();

        (ordered_keys, ix_program_id_index, ix_accounts)
    }

    fn fixed_signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    #[test]
    fn cleanup_tx_includes_payer_in_ix_accounts() {
        let payer = fixed_signing_key(0xA1);
        let payer_pubkey = payer.verifying_key().to_bytes();
        let program_id = [0xC0u8; 32];
        let oracle_pda = [0x05u8; 32];
        let blockhash = [0xBBu8; 32];
        let regs = vec![[0x10u8; 32], [0x20u8; 32]];

        let tx =
            build_cleanup_inactive_transaction(&payer, &program_id, &oracle_pda, &regs, &blockhash);
        let (ordered_keys, ix_program_id_index, ix_accounts) = parse_cleanup_tx_layout(&tx);

        // Layout: [payer (writable signed), oracle_pda, regs..., program_id (readonly)]
        assert_eq!(ordered_keys[0], payer_pubkey);
        assert_eq!(ordered_keys[1], oracle_pda);
        assert!(ordered_keys.contains(&regs[0]));
        assert!(ordered_keys.contains(&regs[1]));
        assert_eq!(ordered_keys[ix_program_id_index as usize], program_id);

        // BUG 3 fix: ix_accounts must now be [oracle_pda, payer, ...regs].
        // The prior v1.2.0 layout omitted payer, which makes the new
        // contract reject the TX (CleanupInactive expects a Signer field).
        assert_eq!(ix_accounts.len(), 2 + regs.len());
        let oracle_idx = ordered_keys.iter().position(|k| k == &oracle_pda).unwrap() as u8;
        let payer_idx = ordered_keys
            .iter()
            .position(|k| k == &payer_pubkey)
            .unwrap() as u8;
        assert_eq!(
            ix_accounts[0], oracle_idx,
            "ix_accounts[0] must point at oracle_state"
        );
        assert_eq!(
            ix_accounts[1], payer_idx,
            "ix_accounts[1] must point at payer (v1.2.1 layout)"
        );
        for reg in &regs {
            let reg_idx = ordered_keys.iter().position(|k| k == reg).unwrap() as u8;
            assert!(ix_accounts[2..].contains(&reg_idx));
        }
    }

    #[test]
    fn cleanup_tx_payer_index_is_writable_signer_slot() {
        // Header invariant: the payer is a writable signer (slot 0) — so
        // the program may (and does) debit lamports from it for TX fees
        // and ALSO credit the lamports recovered from `acct.close()`.
        let payer = fixed_signing_key(0xA2);
        let tx = build_cleanup_inactive_transaction(
            &payer,
            &[0xC0u8; 32],
            &[0x05u8; 32],
            &[[0x10u8; 32]],
            &[0xBBu8; 32],
        );

        // tx[0..1]: compact(num_sigs)=1; tx[1..65]: signature; tx[65..]: msg
        // Header: [num_required_sigs, num_readonly_signed, num_readonly_unsigned]
        let header_offset = 1 + 64;
        assert_eq!(tx[header_offset], 1, "exactly 1 signer (payer)");
        assert_eq!(tx[header_offset + 1], 0, "no readonly signers");
        // 1 readonly_unsigned = program_id; payer is writable_signed at idx 0.
        assert_eq!(tx[header_offset + 2], 1);
    }

    #[test]
    fn cleanup_tx_dedups_payer_against_regs() {
        // Defensive: even if the caller (somehow) supplies their own
        // payer pubkey as a registration PDA, the TX builder must dedupe
        // — Solana's runtime rejects messages with duplicate keys
        // (AccountLoadedTwice).
        let payer = fixed_signing_key(0xA3);
        let payer_pubkey = payer.verifying_key().to_bytes();
        let program_id = [0xC0u8; 32];
        let oracle_pda = [0x05u8; 32];
        let blockhash = [0xBBu8; 32];
        // Three "registrations", but two of them collide with the payer
        // and oracle_pda. After dedup only the genuine one remains.
        let regs = vec![payer_pubkey, oracle_pda, [0x30u8; 32]];

        let tx =
            build_cleanup_inactive_transaction(&payer, &program_id, &oracle_pda, &regs, &blockhash);
        let (ordered_keys, _ix_pid, ix_accounts) = parse_cleanup_tx_layout(&tx);

        // No key appears twice.
        for i in 0..ordered_keys.len() {
            for j in (i + 1)..ordered_keys.len() {
                assert_ne!(
                    ordered_keys[i], ordered_keys[j],
                    "ordered_keys must be deduplicated"
                );
            }
        }
        // ix_accounts: [oracle_pda, payer, only_genuine_reg] = 3 entries.
        assert_eq!(ix_accounts.len(), 3);
    }

    #[test]
    fn cleanup_tx_with_no_regs_still_lists_oracle_and_payer() {
        // Edge case: empty registration_pdas. Builder must still produce
        // a valid TX whose ix_accounts is exactly [oracle_pda, payer].
        // This shape is what the contract's `cleanup_inactive` sees when
        // remaining_accounts is empty (a no-op stale-check that updates
        // `last_cleanup_slot` but closes nothing).
        let payer = fixed_signing_key(0xA4);
        let tx = build_cleanup_inactive_transaction(
            &payer,
            &[0xC0u8; 32],
            &[0x05u8; 32],
            &[],
            &[0xBBu8; 32],
        );
        let (_ordered_keys, _ix_pid, ix_accounts) = parse_cleanup_tx_layout(&tx);
        assert_eq!(
            ix_accounts.len(),
            2,
            "ix_accounts must contain [oracle_pda, payer] only"
        );
    }
}
