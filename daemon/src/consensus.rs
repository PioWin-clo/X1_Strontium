use crate::ntp_client::{get_system_clock_ms, has_gps_pps, NtpResult, NTP_SOURCES};
use crate::status::NtpTier;

pub const MAX_SPREAD_MS: i64 = 50;
pub const MIN_CONFIDENCE: f64 = 0.60;
pub const MIN_SOURCES: usize = 2;

#[derive(Debug, Clone)]
pub struct ConsensusResult {
    pub timestamp_ms: i64,
    pub spread_ms: i64,
    pub confidence: f64,
    pub sources_used: u8,
    /// 64-bit bitmap mapping back into NTP_SOURCES indices (FAZA B:
    /// upgraded from u32 to fit the expanded 43-entry source list with
    /// headroom for future additions up to index 63).
    pub sources_bitmap: u64,
    pub is_gps: bool,
    pub sources: Vec<NtpResult>,
}

/// Reasons `compute_consensus` may reject the input set. Kept separate from
/// `SilentReason` so the daemon's status can show a concise label while the
/// log prints the exact numeric detail (historical daemon bugfix: "wypisz
/// dokładny powód odrzucenia w logu").
#[derive(Debug, Clone, Copy)]
pub enum ConsensusRejection {
    InsufficientSources { have: usize, need: usize },
    IqrTooMany { kept: usize, need: usize },
    LeapSecondSmear { spread_ms: i64 },
    SpreadTooHigh { spread_ms: i64, limit_ms: i64 },
    LowConfidence { confidence: f64, minimum: f64 },
    NoCrossTierAgreement { tier_threshold_ms: i64 },
}

impl ConsensusRejection {
    pub fn label(&self) -> String {
        match self {
            Self::InsufficientSources { have, need } => {
                format!("insufficient sources ({have} < {need})")
            }
            Self::IqrTooMany { kept, need } => {
                format!("IQR filter left {kept} sources, need {need}")
            }
            Self::LeapSecondSmear { spread_ms } => {
                format!("leap-second smear (offset spread {spread_ms}ms in [400, 1100])")
            }
            Self::SpreadTooHigh {
                spread_ms,
                limit_ms,
            } => {
                format!("offset spread {spread_ms}ms > {limit_ms}ms")
            }
            Self::LowConfidence {
                confidence,
                minimum,
            } => {
                format!("confidence {confidence:.2} < {minimum:.2}")
            }
            Self::NoCrossTierAgreement { tier_threshold_ms } => {
                format!("no GPS/NTS/Stratum-1 source within {tier_threshold_ms}ms of median offset")
            }
        }
    }
}

pub fn build_sources_bitmap(results: &[NtpResult]) -> u64 {
    let mut bitmap: u64 = 0;
    for r in results {
        for (idx, src) in NTP_SOURCES.iter().enumerate().take(64) {
            if src.host == r.host {
                bitmap |= 1u64 << idx;
                break;
            }
        }
    }
    bitmap
}

fn median(sorted: &[i64]) -> i64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        // Even number: average the two middle values, integer division.
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

/// Compute median + IQR + cross-tier consensus across NTP results.
///
/// Historical daemon bugfix: consensus runs over `offset_ms`, NOT
/// `timestamp_ms`. Parallel NTP threads finish at different wall-clock
/// moments, so `r.timestamp_ms` (server time corrected for half RTT) spreads
/// wide by construction — even with perfectly synchronised servers it just
/// measures how far apart packet arrivals were. What we actually want to
/// agree on is how far each server thinks our local clock is off. The final
/// submission timestamp then = `local_clock + median_offset` → "best local
/// estimate of UTC right now".
pub fn compute_consensus(
    results: &[NtpResult],
    tier_threshold_ms: i64,
) -> Result<ConsensusResult, ConsensusRejection> {
    if results.len() < MIN_SOURCES {
        return Err(ConsensusRejection::InsufficientSources {
            have: results.len(),
            need: MIN_SOURCES,
        });
    }

    // 1. Sort offsets (NOT absolute timestamps) and compute median.
    let mut sorted: Vec<i64> = results.iter().map(|r| r.offset_ms).collect();
    sorted.sort_unstable();
    let med_offset = median(&sorted);

    // 2. IQR outlier filter on offsets.
    let q1 = sorted[sorted.len() / 4];
    let q3 = sorted[(sorted.len() * 3) / 4];
    let iqr = (q3 - q1).abs();
    let bound = 3 * iqr;

    let mut kept: Vec<NtpResult> = results
        .iter()
        .filter(|r| (r.offset_ms - med_offset).abs() <= bound.max(1))
        .cloned()
        .collect();

    if kept.len() < MIN_SOURCES {
        return Err(ConsensusRejection::IqrTooMany {
            kept: kept.len(),
            need: MIN_SOURCES,
        });
    }

    // Recompute spread on the filtered offset set.
    let mut k_offs: Vec<i64> = kept.iter().map(|r| r.offset_ms).collect();
    k_offs.sort_unstable();
    let spread = k_offs[k_offs.len() - 1] - k_offs[0];

    // 3. Leap-second smear detection: a ~1s flat spread in offsets is the
    //    classic signature of half the fleet having already smeared.
    if (400..=1100).contains(&spread) {
        return Err(ConsensusRejection::LeapSecondSmear { spread_ms: spread });
    }

    // 4. Spread budget.
    if spread > MAX_SPREAD_MS {
        return Err(ConsensusRejection::SpreadTooHigh {
            spread_ms: spread,
            limit_ms: MAX_SPREAD_MS,
        });
    }

    // 5. Confidence score = 0.4 * source_factor + 0.4 * spread_factor + 0.2 * tier_factor
    let source_factor = (kept.len() as f64 / 10.0).min(1.0);
    let spread_factor = 1.0 - (spread as f64 / MAX_SPREAD_MS as f64).clamp(0.0, 1.0);
    let tier_factor = {
        let high_tier = kept
            .iter()
            .filter(|r| matches!(r.tier, NtpTier::Gps | NtpTier::Nts | NtpTier::Stratum1))
            .count();
        (high_tier as f64 / kept.len() as f64).clamp(0.0, 1.0)
    };
    let confidence = 0.4 * source_factor + 0.4 * spread_factor + 0.2 * tier_factor;
    if confidence < MIN_CONFIDENCE {
        return Err(ConsensusRejection::LowConfidence {
            confidence,
            minimum: MIN_CONFIDENCE,
        });
    }

    // 6. Cross-tier validation. N2: if any kept source is GPS, skip the check.
    //    Tier threshold is compared against OFFSET distance, not absolute
    //    timestamp distance (same offset-vs-timestamp reasoning).
    let new_med_offset = median(&k_offs);
    let has_gps = kept.iter().any(|r| matches!(r.tier, NtpTier::Gps));
    if !has_gps {
        let trustworthy_within = kept.iter().any(|r| {
            matches!(r.tier, NtpTier::Gps | NtpTier::Nts | NtpTier::Stratum1)
                && (r.offset_ms - new_med_offset).abs() <= tier_threshold_ms
        });
        if !trustworthy_within {
            return Err(ConsensusRejection::NoCrossTierAgreement { tier_threshold_ms });
        }
    }

    // Apply the consensus offset to the current local clock. This is the
    // "best local estimate of UTC right now" which is what both the Memo and
    // the on-chain submission should carry.
    let final_timestamp = get_system_clock_ms() + new_med_offset;

    let sources_used = kept.len() as u8;
    let bitmap = build_sources_bitmap(&kept);

    // Sort the kept set so that printing is stable.
    kept.sort_by(|a, b| a.tier.rank().cmp(&b.tier.rank()).then(a.host.cmp(&b.host)));

    Ok(ConsensusResult {
        timestamp_ms: final_timestamp,
        spread_ms: spread,
        confidence,
        sources_used,
        sources_bitmap: bitmap,
        is_gps: has_gps,
        sources: kept,
    })
}

/// Top-level consensus entrypoint. If a PPS pulse is wired (`/dev/pps0`),
/// trust the system clock as a GPS reference and only sanity-check it
/// against NTP. Otherwise fall back to pure NTP consensus.
pub fn run_consensus_cycle(
    results: &[NtpResult],
    tier_threshold_ms: i64,
) -> Result<ConsensusResult, ConsensusRejection> {
    if has_gps_pps() {
        let ntp = compute_consensus(results, tier_threshold_ms);
        let gps_now = get_system_clock_ms();
        if let Ok(consensus) = &ntp {
            let drift = (consensus.timestamp_ms - gps_now).abs();
            if drift < 5000 {
                let mut gps_result = consensus.clone();
                gps_result.timestamp_ms = gps_now;
                gps_result.confidence = 0.99;
                gps_result.is_gps = true;
                return Ok(gps_result);
            }
        }
    }
    compute_consensus(results, tier_threshold_ms)
}
