use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Fail fast on obvious mis-pastes (wrong length, non-base58 chars) before
/// the value reaches any RPC call, keypair derivation, or TX build.
fn validate_pubkey_str(s: &str, label: &str) -> Result<(), String> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("{label}: invalid base58 — {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "{label}: length {} bytes != 32 (expected a Solana pubkey)",
            raw.len()
        ));
    }
    Ok(())
}

// X1 Strontium v1.0 mainnet — Ledger-authority redeploy with new Program
// ID, new seeds (`["X1","Strontium","v1"]`), and new per-operator PDAs
// (`["operator", vote_account]`). No backwards-compat with v0.3 / v0.4 / v0.5
// — on hosts with a cached `~/.config/x1-strontium/config.json` (or the
// legacy `~/.config/strontium/config.json`) from an older version, either
// run `x1-strontium config set program_id <v1.0>` / `oracle_pda <v1.0>`
// or delete the cached file to pick up these defaults.
pub const PROGRAM_ID: &str = "2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch";
/// Derived via `find_program_address(["X1","Strontium","v1"], PROGRAM_ID)`,
/// bump = 255. The first successful `x1-strontium init` materialises this
/// exact PDA on chain.
pub const ORACLE_PDA: &str = "EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X1StrontiumConfig {
    /// Path to the operator's **hot signer** keypair. This is the key that
    /// actually signs `submit_time` TXs every cycle. Rotatable via the
    /// `rotate_hot_signer` contract instruction (Ledger-signed, off-band) —
    /// the daemon itself does not invoke that instruction.
    ///
    /// Kept as `Option<String>` (deviation from the literal spec text which
    /// used `String`) so "not set" is unambiguously distinguishable from
    /// "set to empty string" and shares the error-handling pattern of the
    /// rest of the config.
    pub hot_signer_keypair_path: Option<String>,

    /// The validator's **vote account pubkey** — the PDA seed for
    /// `operator_pda` and the account parsed by the contract for
    /// `authorized_withdrawer` / liveness checks. Required for all daemon
    /// operation (no usable default).
    #[serde(default)]
    pub vote_account: Option<String>,

    /// Optional BIP-44-style derivation path (e.g. `m/44'/501'/0'/0'`)
    /// surfaced to operators in `x1-strontium config show` as a reminder of
    /// which Ledger slot controls this validator's authority. Purely
    /// advisory — the daemon never uses a Ledger at runtime; only rare
    /// admin ops (initialize_operator, rotate_hot_signer, deactivate,
    /// close) touch the Ledger via `solana` CLI.
    #[serde(default)]
    pub ledger_derivation_path: Option<String>,

    pub interval_s: u64,
    pub program_id: String,
    pub oracle_pda: String,
    pub rpc_urls: Vec<String>,
    pub alert_webhook: Option<String>,
    pub alert_balance_threshold: f64,
    pub dry_run: bool,
    pub memo_enabled: bool,
    pub tier_consensus_threshold_ms: i64,
    /// Base58 pubkeys of the *other* registered oracles. Empty list = solo
    /// (rotation arithmetic naturally elects the single oracle).
    pub rotation_peers: Vec<String>,
}

impl Default for X1StrontiumConfig {
    fn default() -> Self {
        Self {
            hot_signer_keypair_path: None,
            vote_account: None,
            ledger_derivation_path: None,
            interval_s: 300,
            program_id: PROGRAM_ID.to_string(),
            oracle_pda: ORACLE_PDA.to_string(),
            rpc_urls: vec![
                "https://rpc.mainnet.x1.xyz".to_string(),
                "https://api.mainnet.x1.xyz".to_string(),
            ],
            alert_webhook: None,
            alert_balance_threshold: 1.0,
            dry_run: false,
            memo_enabled: true,
            tier_consensus_threshold_ms: 50,
            rotation_peers: Vec::new(),
        }
    }
}

impl X1StrontiumConfig {
    fn path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".config/x1-strontium/config.json")
    }

    pub fn load() -> Self {
        match fs::read_to_string(Self::path()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{e}"))?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| format!("{e}"))?;
        fs::write(&path, text).map_err(|e| format!("{e}"))?;
        Ok(())
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "interval" | "interval_s" => {
                self.interval_s = value.parse::<u64>().map_err(|e| format!("interval: {e}"))?;
            }
            "keypair" | "hot_signer" | "hot_signer_keypair" | "hot_signer_keypair_path" => {
                self.hot_signer_keypair_path = Some(value.to_string());
            }
            "vote_account" => {
                // Unset with empty string; validate otherwise.
                if value.is_empty() {
                    self.vote_account = None;
                } else {
                    validate_pubkey_str(value, "vote_account")?;
                    self.vote_account = Some(value.to_string());
                }
            }
            "ledger_path" | "ledger_derivation_path" => {
                self.ledger_derivation_path = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "program_id" => {
                validate_pubkey_str(value, "program_id")?;
                self.program_id = value.to_string();
            }
            "oracle_pda" => {
                validate_pubkey_str(value, "oracle_pda")?;
                self.oracle_pda = value.to_string();
            }
            "rpc" | "rpc_urls" => {
                self.rpc_urls = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "dry_run" => {
                self.dry_run = matches!(value, "1" | "true" | "yes" | "on");
            }
            "memo" | "memo_enabled" => {
                self.memo_enabled = matches!(value, "1" | "true" | "yes" | "on");
            }
            "tier_threshold" | "tier_consensus_threshold_ms" => {
                self.tier_consensus_threshold_ms = value
                    .parse::<i64>()
                    .map_err(|e| format!("tier_threshold: {e}"))?;
            }
            "alert_webhook" => {
                self.alert_webhook = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "alert_balance" | "alert_balance_threshold" => {
                self.alert_balance_threshold = value
                    .parse::<f64>()
                    .map_err(|e| format!("alert_balance: {e}"))?;
            }
            "rotation_peers" => {
                self.rotation_peers = if value.is_empty() {
                    Vec::new()
                } else {
                    value.split(',').map(|s| s.trim().to_string()).collect()
                };
            }
            other => return Err(format!("unknown config key: {other}")),
        }
        Ok(())
    }

    pub fn display(&self) {
        println!("X1 Strontium — config (v1.0)");
        println!("  interval_s:                  {}", self.interval_s);
        println!(
            "  hot_signer_keypair_path:     {}",
            self.hot_signer_keypair_path.as_deref().unwrap_or("(unset)")
        );
        println!(
            "  vote_account:                {}",
            self.vote_account.as_deref().unwrap_or("(unset — required)")
        );
        println!(
            "  ledger_derivation_path:      {}",
            self.ledger_derivation_path
                .as_deref()
                .unwrap_or("(advisory, unset)")
        );
        println!("  program_id:                  {}", self.program_id);
        println!("  oracle_pda:                  {}", self.oracle_pda);
        println!(
            "  rpc_urls:                    {}",
            self.rpc_urls.join(", ")
        );
        println!("  dry_run:                     {}", self.dry_run);
        println!("  memo_enabled:                {}", self.memo_enabled);
        println!(
            "  tier_consensus_threshold_ms: {}",
            self.tier_consensus_threshold_ms
        );
        println!(
            "  alert_webhook:               {}",
            self.alert_webhook.as_deref().unwrap_or("(unset)")
        );
        println!(
            "  alert_balance_threshold:     {:.4}",
            self.alert_balance_threshold
        );
        if self.rotation_peers.is_empty() {
            println!("  rotation_peers:              (none — solo, n=1)");
        } else {
            println!(
                "  rotation_peers:              {}",
                self.rotation_peers.join(", ")
            );
        }
    }
}
