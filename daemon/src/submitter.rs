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

/// Parsed view of a stake account (layout offsets validated in
/// `programs/x1-strontium/tests/account_parse_integration.rs`).
#[derive(Debug, Clone)]
pub struct StakeAccountInfo {
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

/// Minimal view of an `OperatorPDA` account — only the field the daemon
/// actively consumes (`last_stake_check_slot`, used by the daily recheck
/// gating in `main.rs`). The other fields (authority/Ledger, hot_signer,
/// vote_account, validator_identity, self_stake_amount, active, bump) are
/// either already known locally at startup or redundant with the off-chain
/// self-stake computation. Expand when a new field is genuinely needed.
#[derive(Debug, Clone)]
pub struct OperatorInfo {
    pub last_stake_check_slot: u64,
}

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

/// v1.0 operator PDA derivation. Seeds: `[b"operator", vote_account]` —
/// bound to the validator's vote account, not to any daemon-side keypair.
/// One operator per validator; PDA collision makes duplicates impossible.
pub fn derive_operator_pda(vote_account: &[u8; 32], program_id: &[u8; 32]) -> [u8; 32] {
    let (pda, _bump) = find_program_address(&[b"operator", vote_account], program_id);
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
        let mut last_err = String::from("no rpc endpoints configured");
        let now = Self::now_secs();
        for i in 0..self.urls.len() {
            if self.cooldown_until[i] > now {
                continue;
            }
            match op(&self.urls[i]) {
                Ok(v) => {
                    self.fail_counts[i] = 0;
                    return Ok(v);
                }
                Err(e) => {
                    last_err = e;
                    self.fail_counts[i] += 1;
                    if self.fail_counts[i] >= 3 {
                        self.cooldown_until[i] = now + 5 * 60;
                        self.fail_counts[i] = 0;
                    }
                }
            }
        }
        Err(last_err)
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

    /// `getProgramAccounts` against the X1 Strontium v1.0 program, filtered
    /// to accounts of size `8 + OperatorPDA::LEN = 168` bytes and with
    /// `active == true`. Returns the list of **hot_signer pubkeys** — that's
    /// the identity the rotation state tracks (it's what signs `submit_time`
    /// and therefore what each daemon uses to find itself in the fleet).
    pub fn fetch_active_operators(
        &mut self,
        program_id: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, String> {
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
                            { "dataSize": 168u64 }
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
            // OperatorPDA layout inside the account body (after the 8-byte
            // Anchor discriminator — so account-level offsets below are
            // struct_offset + 8):
            //   [  8.. 40]  authority            (Pubkey — Ledger)
            //   [ 40.. 72]  hot_signer           (Pubkey — daemon signer)
            //   [ 72..104]  vote_account         (Pubkey)
            //   [104..136]  validator_identity   (Pubkey)
            //   [136..144]  registered_at        (i64)
            //   [144..152]  last_stake_check_slot(u64)
            //   [152..160]  self_stake_amount    (u64)
            //   [160     ]  active               (bool)
            //   [161     ]  bump                 (u8)
            //   [162..168]  _pad
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let data_b64 = match item.pointer("/account/data/0").and_then(|x| x.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let data = match base64_decode(data_b64) {
                    Some(d) => d,
                    None => continue,
                };
                if data.len() < 168 {
                    continue;
                }
                let active = data[160] != 0;
                if !active {
                    continue;
                }
                let mut hot = [0u8; 32];
                hot.copy_from_slice(&data[40..72]);
                out.push(hot);
            }
            Ok(out)
        })
    }

    /// Fetch a single `OperatorPDA` account and parse the field the daemon
    /// needs for its 24 h self-stake recheck gate.
    ///
    /// Account layout (with 8-byte Anchor discriminator prefix — so
    /// account-level offsets below are struct_offset + 8):
    ///   [  8.. 40]  authority (Pubkey)
    ///   [ 40.. 72]  hot_signer (Pubkey)
    ///   [ 72..104]  vote_account (Pubkey)
    ///   [104..136]  validator_identity (Pubkey)
    ///   [136..144]  registered_at (i64)
    ///   [144..152]  last_stake_check_slot (u64)   ← used here
    ///   [152..160]  self_stake_amount (u64)
    ///   [160     ]  active (bool)
    ///   [161     ]  bump (u8)
    ///   [162..168]  _pad
    pub fn fetch_operator(&mut self, operator_pda: &[u8; 32]) -> Result<OperatorInfo, String> {
        let data = self.fetch_account_info(&bs58::encode(operator_pda).into_string())?;
        if data.len() < 168 {
            return Err(format!(
                "OperatorPDA account too small: {} bytes (expected ≥ 168)",
                data.len()
            ));
        }
        let last_stake_check_slot =
            u64::from_le_bytes(data[144..152].try_into().map_err(|e| format!("{e}"))?);
        Ok(OperatorInfo {
            last_stake_check_slot,
        })
    }
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
fn format_clock_3dec(unix_ms: i64) -> String {
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
    // Memo v1: the v0.5 STAMP suffix (ppm/off/tsc/ent/stamp) has been removed
    // wholesale in v1.0. `drift` is the signed delta between our precise
    // estimate and the on-chain `Clock::unix_timestamp` (positive = chain is
    // behind, negative = ahead; the X1 chain has historically run 12–20 s
    // behind real UTC).
    let prefix = time_source_prefix(params.consensus);
    let time_str = format_clock_3dec(params.precise_time_ms);
    let (chain_str, drift_str) = match params.chain_time_ms {
        Some(t) => (
            format_clock_3dec(t),
            (params.precise_time_ms - t).to_string(),
        ),
        None => ("??:??:??.???".to_string(), "null".to_string()),
    };
    let conf = (params.consensus.confidence * 100.0).round() as u32;

    // Example with NTS sources:
    //   X1Strontium:v1:w=5921961:nts=08:45:00.003:chain=08:45:00.000:drift=3:
    //   c=97:s=10:st=1
    // Length ~100 bytes — well under the 566 B Memo Program limit.
    format!(
        "X1Strontium:v1:w={w}:{prefix}={time}:chain={chain}:drift={drift}:\
         c={c}:s={s}:st={st}",
        w = params.window_id,
        prefix = prefix,
        time = time_str,
        chain = chain_str,
        drift = drift_str,
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
/// Memo instruction). Signer = `hot_signer`. The daemon holds exactly one
/// signer — there is no second validator-identity signer.
///
/// - `vote_account`: required — the validator's vote account, read-only in
///   the instruction for the cheap liveness heuristic and as PDA seed
///   source for `operator_pda`.
/// - `stake_accounts`: optional remaining_accounts — passed only when the
///   daily stake recheck window is approaching. Empty slice = no recheck.
#[allow(clippy::too_many_arguments)]
pub fn build_submit_transaction_signed(
    keypair: &SigningKey,
    program_id: &[u8; 32],
    oracle_pda: &[u8; 32],
    operator_pda: &[u8; 32],
    vote_account: &[u8; 32],
    blockhash: &[u8; 32],
    params: &SubmitParams,
    stake_accounts: &[[u8; 32]],
) -> Vec<u8> {
    let signer_pubkey: [u8; 32] = keypair.verifying_key().to_bytes();
    let memo_program =
        pubkey_from_b58(MEMO_PROGRAM_ID_B58).expect("memo program id is constant and valid");

    // Defensive dedup of stake_accounts against the fixed account set and
    // against each other. Even a single duplicate anywhere in the message
    // makes Solana runtime reject the TX with AccountLoadedTwice before the
    // contract runs.
    let mut fixed_set: Vec<[u8; 32]> = vec![
        signer_pubkey,
        *oracle_pda,
        *operator_pda,
        *vote_account,
        *program_id,
    ];
    if params.memo_enabled {
        fixed_set.push(memo_program);
    }
    let mut dedup_stakes: Vec<[u8; 32]> = Vec::with_capacity(stake_accounts.len());
    for sa in stake_accounts {
        if fixed_set.contains(sa) || dedup_stakes.contains(sa) {
            continue;
        }
        dedup_stakes.push(*sa);
    }

    // Account ordering (Solana message header convention):
    //   writable_signed   = [hot_signer]                 (pays fees)
    //   readonly_signed   = []
    //   writable_unsigned = [oracle_pda, operator_pda]   (both mutated)
    //   readonly_unsigned = [vote_account, *dedup_stakes, program_id (+ memo?)]
    let mut ordered_keys: Vec<[u8; 32]> =
        vec![signer_pubkey, *oracle_pda, *operator_pda, *vote_account];
    for sa in &dedup_stakes {
        ordered_keys.push(*sa);
    }
    ordered_keys.push(*program_id);
    if params.memo_enabled {
        ordered_keys.push(memo_program);
    }
    let num_required_signatures: u8 = 1;
    let num_readonly_signed: u8 = 0;
    let num_readonly_unsigned: u8 = {
        let base = 1 /* vote */ + dedup_stakes.len() as u8 + 1 /* program_id */;
        if params.memo_enabled {
            base + 1
        } else {
            base
        }
    };

    let idx = |key: &[u8; 32]| -> u8 {
        ordered_keys
            .iter()
            .position(|k| k == key)
            .expect("ordered_keys must contain all referenced accounts") as u8
    };

    // ---- Instruction 1: submit_time ----
    // Timestamp written on chain is `precise_time_ms` (= consensus timestamp
    // + TSC elapsed for the build/sign/RPC pipeline, with fallback to raw
    // consensus when elapsed > 50 ms). Memo's `{prefix}=` field uses the
    // same value, so the on-chain instruction and memo always agree.
    let discriminator = anchor_discriminator("submit_time");
    let mut ix1_data: Vec<u8> = Vec::with_capacity(8 + 8 + 2 + 1 + 1 + 4);
    ix1_data.extend_from_slice(&discriminator);
    ix1_data.extend_from_slice(&params.precise_time_ms.to_le_bytes());
    ix1_data.extend_from_slice(&(params.consensus.spread_ms as i16).to_le_bytes());
    let conf_pct: u8 = (params.consensus.confidence * 100.0)
        .clamp(0.0, 255.0)
        .round() as u8;
    ix1_data.push(params.consensus.sources_used);
    ix1_data.push(conf_pct);
    ix1_data.extend_from_slice(&params.consensus.sources_bitmap.to_le_bytes());

    // SubmitTime Anchor derive order:
    //   oracle_state, operator_pda, vote_account, submitter
    //   + remaining_accounts = stakes (only at 24 h recheck)
    let mut ix1_accounts: Vec<u8> = vec![
        idx(oracle_pda),
        idx(operator_pda),
        idx(vote_account),
        idx(&signer_pubkey),
    ];
    for sa in &dedup_stakes {
        ix1_accounts.push(idx(sa));
    }
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

    // Instruction 1 wire format
    msg.push(ix1_program_id_index);
    write_compact(&mut msg, ix1_accounts.len() as u16);
    msg.extend_from_slice(&ix1_accounts);
    write_compact(&mut msg, ix1_data.len() as u16);
    msg.extend_from_slice(&ix1_data);

    // Instruction 2 (memo)
    if let Some(memo_idx) = memo_program_idx {
        msg.push(memo_idx);
        write_compact(&mut msg, 0); // memo takes no accounts
        write_compact(&mut msg, memo_bytes.len() as u16);
        msg.extend_from_slice(memo_bytes);
    }

    // ---- Sign ----
    let sig = keypair.sign(&msg).to_bytes();

    // ---- Wrap as transaction ----
    let mut tx = Vec::with_capacity(64 + msg.len() + 4);
    write_compact(&mut tx, 1); // 1 signature
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

// Note: operator onboarding is out-of-scope for the daemon. The contract's
// `initialize_operator` / `rotate_hot_signer` / `deactivate_operator` /
// `close_operator` instructions are all Ledger-signed (cold key = vote
// account's authorized_withdrawer). Operators run `solana` CLI + Ledger
// out-of-band. See docs/OPERATOR_ONBOARDING.md.

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

pub fn estimate_days_remaining(balance_xnt: f64, interval_s: u64) -> f64 {
    if balance_xnt <= 0.0 || interval_s == 0 {
        return 0.0;
    }
    let tx_per_day: f64 = 86_400.0 / interval_s as f64;
    let daily_cost = COST_PER_TX_XNT * tx_per_day;
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

    /// Regression test mandated by the v1.0 rebuild mission: the STAMP
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
}
