use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Reasons the daemon may stay silent for a given cycle.
/// Higher `priority()` wins when multiple reasons compete in the same cycle (N5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SilentReason {
    InsufficientBalance,
    InsufficientSelfStake,
    RegistrationExpired,
    NoHealthyRpc,
    TxRejected,
    SystemClockOutOfSync,
    SpreadTooHigh,
    NoValidSources,
    LowConfidence,
    NotElected,
    DryRun,
}

impl SilentReason {
    pub fn priority(self) -> u8 {
        match self {
            SilentReason::InsufficientBalance => 100,
            SilentReason::InsufficientSelfStake => 95,
            SilentReason::RegistrationExpired => 90,
            SilentReason::NoHealthyRpc => 50,
            SilentReason::TxRejected => 50,
            SilentReason::SystemClockOutOfSync => 40,
            SilentReason::SpreadTooHigh => 30,
            SilentReason::NoValidSources => 30,
            SilentReason::LowConfidence => 30,
            SilentReason::NotElected => 10,
            SilentReason::DryRun => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SilentReason::InsufficientBalance => "insufficient_balance",
            SilentReason::InsufficientSelfStake => "insufficient_self_stake",
            SilentReason::RegistrationExpired => "registration_expired",
            SilentReason::NoHealthyRpc => "no_healthy_rpc",
            SilentReason::TxRejected => "tx_rejected",
            SilentReason::SystemClockOutOfSync => "system_clock_out_of_sync",
            SilentReason::SpreadTooHigh => "spread_too_high",
            SilentReason::NoValidSources => "no_valid_sources",
            SilentReason::LowConfidence => "low_confidence",
            SilentReason::NotElected => "not_elected",
            SilentReason::DryRun => "dry_run",
        }
    }
}

/// Tier classification for an NTP source. Defined here once and imported
/// by `ntp_client` and `consensus` — never redefined elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtpTier {
    Gps,
    /// Nts: server supports NTS-KE, but daemon currently queries via plain NTP.
    /// True NTS authentication is on roadmap — see README § Roadmap.
    Nts,
    Stratum1,
    Pool,
}

impl NtpTier {
    pub fn label(self) -> &'static str {
        match self {
            NtpTier::Gps => "GPS",
            NtpTier::Nts => "NTS",
            NtpTier::Stratum1 => "Stratum1",
            NtpTier::Pool => "Pool",
        }
    }

    /// Lower number = higher priority when sorting candidates.
    pub fn rank(self) -> u8 {
        match self {
            NtpTier::Gps => 0,
            NtpTier::Nts => 1,
            NtpTier::Stratum1 => 2,
            NtpTier::Pool => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpSourceStatus {
    pub host: String,
    pub tier: NtpTier,
    pub rtt_ms: i64,
    pub offset_ms: i64,
    pub stratum: u8,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub oracle_pubkey: String,
    pub balance_xnt: f64,
    pub days_remaining: f64,
    pub balance_warning: bool,
    pub last_submit_ts: Option<i64>,
    pub last_submit_tx: Option<String>,
    pub last_attempt_ts: Option<i64>,
    pub last_error: Option<String>,
    pub silent_cycles: u64,
    pub silent_reason: Option<SilentReason>,
    pub interval_s: u64,
    pub dry_run: bool,
    pub consensus_ms: Option<i64>,
    pub spread_ms: Option<i64>,
    pub confidence: Option<f64>,
    pub sources_bitmap: Option<u64>,
    pub ntp_sources: Vec<NtpSourceStatus>,
    pub rotation_window_id: Option<u64>,
    pub rotation_is_my_turn: Option<bool>,
}

impl DaemonStatus {
    pub fn empty() -> Self {
        Self {
            running: false,
            pid: None,
            oracle_pubkey: String::new(),
            balance_xnt: 0.0,
            days_remaining: 0.0,
            balance_warning: false,
            last_submit_ts: None,
            last_submit_tx: None,
            last_attempt_ts: None,
            last_error: None,
            silent_cycles: 0,
            silent_reason: None,
            interval_s: 300,
            dry_run: false,
            consensus_ms: None,
            spread_ms: None,
            confidence: None,
            sources_bitmap: None,
            ntp_sources: Vec::new(),
            rotation_window_id: None,
            rotation_is_my_turn: None,
        }
    }

    fn path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".config/x1-strontium/status.json")
    }

    pub fn load() -> Self {
        match fs::read_to_string(Self::path()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| Self::empty()),
            Err(_) => Self::empty(),
        }
    }

    pub fn save(&self) {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, text);
        }
    }

    /// Update `silent_reason`, but only if the new reason has equal or higher
    /// priority than the current one (N5). Resets if the daemon recovers
    /// (caller clears it explicitly).
    pub fn set_silent_reason(&mut self, reason: SilentReason) {
        match self.silent_reason {
            Some(cur) if cur.priority() > reason.priority() => {}
            _ => self.silent_reason = Some(reason),
        }
    }

    pub fn print(&self) {
        let w = 54; // inner width of the box

        // ── Header ──
        println!("\x1b[36m\x1b[1m");
        print_box_top(w);
        print_box_line(w, "X1 Strontium — Oracle Status");
        print_box_bottom(w);
        println!("\x1b[0m");

        // ── Daemon / Oracle / Mode ──
        let daemon_label = if self.running {
            match self.pid {
                Some(pid) => format!("\x1b[32m●\x1b[0m running  (PID {pid})"),
                None => "\x1b[32m●\x1b[0m running".to_string(),
            }
        } else {
            "\x1b[31m●\x1b[0m stopped".to_string()
        };
        row("Daemon", &daemon_label);

        let oracle = if self.oracle_pubkey.is_empty() {
            "(not configured)".to_string()
        } else {
            shorten_key(&self.oracle_pubkey)
        };
        row("Oracle", &oracle);

        let mode = if self.dry_run { "dry-run" } else { "live" };
        row(
            "Mode",
            &format!("{mode}  |  interval: {}s", self.interval_s),
        );

        // ── Balance & Runway ──
        section("Balance & Runway");
        if self.balance_warning {
            row(
                "Balance",
                &format!("\x1b[33m{:.3} XNT  ⚠ low\x1b[0m", self.balance_xnt),
            );
        } else {
            row("Balance", &format!("{:.3} XNT", self.balance_xnt));
        }
        let cost_per_tx: f64 = 0.004;
        let tx_per_day: f64 = if self.interval_s > 0 {
            86_400.0 / self.interval_s as f64
        } else {
            0.0
        };
        let daily_cost = cost_per_tx * tx_per_day;
        let runway_days = if daily_cost > 0.0 {
            self.balance_xnt / daily_cost
        } else {
            0.0
        };
        row(
            "Runway",
            &format!("~{runway_days:.0} days  (@ {cost_per_tx:.3} XNT x {tx_per_day:.0} TX/day)"),
        );

        // ── Last Submission ──
        section("Last Submission");
        match self.last_submit_ts {
            Some(ts) if ts > 0 => {
                let ago = format_ago(ts);
                row("Time", &format!("{}  ({ago})", format_utc(ts)));
            }
            _ => {
                row("Time", "(no submission yet)");
            }
        }
        match &self.last_submit_tx {
            Some(tx) if !tx.is_empty() => row("TX", &shorten_key(tx)),
            _ => row("TX", "—"),
        }
        match &self.last_error {
            Some(err) if !err.is_empty() => {
                row("Result", &format!("\x1b[31m✗ failed\x1b[0m  {err}"));
            }
            _ if self.last_submit_ts.is_some() => {
                row("Result", "\x1b[32m✓ success\x1b[0m");
            }
            _ => {
                row("Result", "—");
            }
        }
        if let Some(reason) = self.silent_reason {
            row(
                "Silent",
                &format!("{} ({} cycles)", reason.label(), self.silent_cycles),
            );
        }

        // ── NTP Consensus ──
        section("NTP Consensus");
        match self.consensus_ms {
            Some(ms) if ms > 0 => {
                let secs = ms.div_euclid(1000);
                let frac = ms.rem_euclid(1000).unsigned_abs();
                let h = ((secs / 3600) % 24) as u64;
                let m = ((secs / 60) % 60) as u64;
                let s = (secs % 60) as u64;
                row(
                    "Consensus time",
                    &format!("{h:02}:{m:02}:{s:02}.{frac:03} UTC"),
                );
            }
            _ => {
                row("Consensus time", "—");
            }
        }
        match self.spread_ms {
            Some(s) => {
                let color = if s <= 50 { "\x1b[32m" } else { "\x1b[31m" };
                row("Spread", &format!("{color}{s} ms\x1b[0m   (limit: 50ms)"));
            }
            None => row("Spread", "—"),
        }
        match self.confidence {
            Some(c) => {
                let pct = (c * 100.0).round() as u32;
                let color = if pct >= 60 { "\x1b[32m" } else { "\x1b[31m" };
                row("Confidence", &format!("{color}{pct}%\x1b[0m    (min: 60%)"));
            }
            None => row("Confidence", "—"),
        }
        let active: Vec<&NtpSourceStatus> = self.ntp_sources.iter().filter(|s| s.active).collect();
        let active_count = active.len();
        row("Sources active", &format!("{active_count} / 40+"));

        let best_stratum = active.iter().map(|s| s.stratum).min();
        match best_stratum {
            Some(st) => row("Best stratum", &format!("{st}")),
            None => row("Best stratum", "—"),
        }

        let best_rtt = active.iter().min_by_key(|s| s.rtt_ms);
        match best_rtt {
            Some(s) => row("Best RTT", &format!("{} ms   ({})", s.rtt_ms, s.host)),
            None => row("Best RTT", "—"),
        }

        let worst_rtt = active.iter().max_by_key(|s| s.rtt_ms);
        match worst_rtt {
            Some(s) => row("Worst RTT", &format!("{} ms  ({})", s.rtt_ms, s.host)),
            None => row("Worst RTT", "—"),
        }

        let max_offset_src = active.iter().max_by_key(|s| s.offset_ms.abs());
        match max_offset_src {
            Some(s) => row(
                "Max offset",
                &format!("{} ms  ({})", s.offset_ms.abs(), s.host),
            ),
            None => row("Max offset", "—"),
        }

        let nts_count = active
            .iter()
            .filter(|s| matches!(s.tier, NtpTier::Nts))
            .count();
        row("NTS sources", &format!("{nts_count}      (encrypted)"));

        let str1_count = active
            .iter()
            .filter(|s| matches!(s.tier, NtpTier::Stratum1))
            .count();
        row("Str1 sources", &format!("{str1_count}      (atomic)"));

        // ── Rotation ──
        section("Rotation");
        match self.rotation_window_id {
            Some(wid) => row("Window ID", &format!("{wid}")),
            None => row("Window ID", "—"),
        }
        match self.rotation_is_my_turn {
            Some(true) => row("My turn", "\x1b[32m✓ yes\x1b[0m"),
            Some(false) => row("My turn", "\x1b[33m✗ no\x1b[0m"),
            None => row("My turn", "—"),
        }

        println!("  \x1b[2m{}\x1b[0m", "─".repeat(w));
    }

    pub fn print_sources(&self) {
        if self.ntp_sources.is_empty() {
            println!("(no NTP sources recorded — daemon may not have started yet)");
            return;
        }
        println!(
            "{:<32} {:<10} {:>8} {:>10} {:>8} {:<6}",
            "HOST", "TIER", "RTT_MS", "OFFSET_MS", "STRATUM", "ACTIVE"
        );
        for s in &self.ntp_sources {
            println!(
                "{:<32} {:<10} {:>8} {:>10} {:>8} {:<6}",
                s.host,
                s.tier.label(),
                s.rtt_ms,
                s.offset_ms,
                s.stratum,
                if s.active { "yes" } else { "no" }
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers for DaemonStatus::print()
// ---------------------------------------------------------------------------

fn row(label: &str, value: &str) {
    println!("  {:<16}: {value}", label);
}

fn section(title: &str) {
    let dash_len = 54usize.saturating_sub(title.len() + 5);
    println!();
    println!("  \x1b[2m── {title} {}\x1b[0m", "─".repeat(dash_len));
}

fn print_box_top(w: usize) {
    println!("  ╔{}╗", "═".repeat(w));
}

fn print_box_line(w: usize, text: &str) {
    let pad_total = w.saturating_sub(text.len());
    let left = pad_total / 2;
    let right = pad_total - left;
    println!("  ║{}{}{}║", " ".repeat(left), text, " ".repeat(right));
}

fn print_box_bottom(w: usize) {
    println!("  ╚{}╝", "═".repeat(w));
}

/// Shorten a base58 key: first 8 chars ... last 4 chars.
fn shorten_key(key: &str) -> String {
    if key.len() <= 14 {
        key.to_string()
    } else {
        format!("{}...{}", &key[..8], &key[key.len() - 4..])
    }
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
fn format_utc(ts: i64) -> String {
    // Manual UTC decomposition — no chrono dependency.
    let s = ts;
    let secs_in_day: i64 = 86_400;
    let days = s.div_euclid(secs_in_day);
    let day_secs = s.rem_euclid(secs_in_day);
    let h = day_secs / 3600;
    let m = (day_secs / 60) % 60;
    let sec = day_secs % 60;

    // Days since 1970-01-01 → (y, mon, day).
    let (y, mon, day) = civil_from_days(days);
    format!("{y:04}-{mon:02}-{day:02} {h:02}:{m:02}:{sec:02} UTC")
}

/// Convert epoch-days to (year, month 1-12, day 1-31).
/// Algorithm from Howard Hinnant (public domain).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mon <= 2 { y + 1 } else { y };
    (y, mon as u32, d as u32)
}

/// Human-readable "X min ago" / "X hours ago" from a unix timestamp.
fn format_ago(ts: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let diff = (now - ts).max(0);
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{} min ago", diff / 60)
    } else if diff < 86_400 {
        let hours = diff / 3600;
        let mins = (diff % 3600) / 60;
        if mins > 0 {
            format!("{hours}h {mins}m ago")
        } else {
            format!("{hours}h ago")
        }
    } else {
        format!("{} days ago", diff / 86_400)
    }
}
