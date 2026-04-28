use crate::status::{NtpSourceStatus, NtpTier};
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Difference between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
const NTP_TIMEOUT: Duration = Duration::from_millis(2000);

#[derive(Debug, Clone, Copy)]
pub struct NtpSource {
    pub host: &'static str,
    pub port: u16,
    pub stratum: u8,
    pub tier: NtpTier,
}

/// 43 NTP sources (31 Stratum1/NTS-capable + 12 pool fallbacks) across 6
/// continents. u64 bitmap, capacity 64, headroom 21 slots.
///
/// Verified reachable from Warsaw (Piotr's dev box, 2026-04-22) via SNTPv3
/// probe of 49 candidate hosts — see `/tmp/ntp_audit.log`. Removed from the
/// earlier v0.5 list after the audit: `nts.netnod.se` (NTS-only, plain NTP
/// rejected), `ntp.gum.gov.pl` (non-responsive — siostrzany `tempus1`
/// działa), `syrte.obspm.fr` (Paris observatory, rejects plain NTP),
/// `b.st1.ntp.br` (Brazil Stratum1 non-responsive — `a.st1` działa),
/// `stdtime.gov.hk` (HK gov, geo-restrict / firewall). Also dropped as
/// redundant siblings to trim to 43 for the bitmap budget: `ntp2.fau.de`,
/// `tempus2.gum.gov.pl`, `ntp2.nl.net`, `time-a/d-wwv.nist.gov`,
/// `ntp1.net.berkeley.edu`, `ntp.cida.gob.ve`.
///
/// Index 0..63 maps directly into `ConsensusResult::sources_bitmap` (u64).
pub const NTP_SOURCES: &[NtpSource] = &[
    // ---- 6 NTS-capable servers (queried via plain NTP for now; NTS auth on roadmap) ----
    NtpSource {
        host: "time.cloudflare.com",
        port: 123,
        stratum: 3,
        tier: NtpTier::Nts,
    },
    NtpSource {
        host: "nts.time.nl",
        port: 123,
        stratum: 1,
        tier: NtpTier::Nts,
    },
    NtpSource {
        host: "ntppool1.time.nl",
        port: 123,
        stratum: 1,
        tier: NtpTier::Nts,
    },
    NtpSource {
        host: "ptbtime1.ptb.de",
        port: 123,
        stratum: 1,
        tier: NtpTier::Nts,
    },
    NtpSource {
        host: "oregon.time.system76.com",
        port: 123,
        stratum: 1,
        tier: NtpTier::Nts,
    },
    NtpSource {
        host: "virginia.time.system76.com",
        port: 123,
        stratum: 1,
        tier: NtpTier::Nts,
    },
    // ---- 13 Stratum-1 Europe ----
    NtpSource {
        host: "ptbtime2.ptb.de",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "ptbtime3.ptb.de",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "tempus1.gum.gov.pl",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "ntp.metas.ch",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "ntp1.fau.de",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "tik.cesnet.cz",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "tak.cesnet.cz",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "gbg2.ntp.netnod.se",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "sth1.ntp.netnod.se",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "ntp1.nl.net",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time.euro.apple.com",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time.apple.com",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time.google.com",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    // ---- 6 Stratum-1 Americas ----
    NtpSource {
        host: "time-a-g.nist.gov",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time-b-g.nist.gov",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time-c-g.nist.gov",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "tick.usask.ca",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "a.st1.ntp.br",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "ntp.shoa.cl",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    // ---- 6 Stratum-1 Asia-Pacific ----
    NtpSource {
        host: "ntp.nict.jp",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "jp.pool.ntp.org",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time.kriss.re.kr",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "ntp1.tpg.com.au",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time.stdtime.gov.tw",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    NtpSource {
        host: "time.nplindia.org",
        port: 123,
        stratum: 1,
        tier: NtpTier::Stratum1,
    },
    // Dropped as FAIL in Warsaw probe (keep comments for future re-consideration):
    //   - ntp.ntsc.ac.cn  — Great Firewall, niestabilne (Prime OK, Sentinel FAIL)
    //   - ntp.csiro.au, ntp1.saao.ac.za, time.ae — DNS/connectivity FAIL globally

    // ---- 12 Pool fallbacks (treated as Stratum 2-3) ----
    NtpSource {
        host: "pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "europe.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "north-america.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "south-america.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "asia.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "oceania.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "africa.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "au.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "za.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "0.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "1.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
    NtpSource {
        host: "2.pool.ntp.org",
        port: 123,
        stratum: 2,
        tier: NtpTier::Pool,
    },
];

#[derive(Debug, Clone)]
pub struct NtpResult {
    pub host: String,
    /// Signed difference between the server's clock and our local clock, in
    /// milliseconds. Computed after a half-RTT correction. This — not the
    /// absolute server timestamp — is what the consensus runs over.
    pub offset_ms: i64,
    pub rtt_ms: i64,
    pub stratum: u8,
    pub tier: NtpTier,
}

pub fn get_system_clock_ms() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_millis() as i64
}

/// Issue one SNTPv3 query against `host:port` and parse the response.
pub fn query_ntp(host: &str, port: u16, tier: NtpTier, fallback_stratum: u8) -> Option<NtpResult> {
    let addr_iter = (host, port).to_socket_addrs().ok()?;
    let mut last_err = None;
    for addr in addr_iter {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        if socket.set_read_timeout(Some(NTP_TIMEOUT)).is_err() {
            continue;
        }
        if socket.set_write_timeout(Some(NTP_TIMEOUT)).is_err() {
            continue;
        }

        // NTPv3 client packet: LI=0, VN=3, Mode=3 → 0x1B
        let mut req = [0u8; 48];
        req[0] = 0x1B;

        let send_unix_ms = get_system_clock_ms();
        if socket.send_to(&req, addr).is_err() {
            continue;
        }

        let mut buf = [0u8; 48];
        let n = match socket.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let recv_unix_ms = get_system_clock_ms();
        if n < 48 {
            continue;
        }

        let server_stratum = buf[1];
        if !(1..=15).contains(&server_stratum) {
            continue;
        }

        let tx_sec = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as u64;
        let tx_frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]) as u64;
        if tx_sec <= NTP_UNIX_OFFSET {
            continue;
        }

        let server_unix_sec = tx_sec - NTP_UNIX_OFFSET;
        // tx_frac is in 2^32 fractional seconds → convert to milliseconds.
        let server_unix_ms = (server_unix_sec as i64) * 1000 + ((tx_frac * 1000) >> 32) as i64;

        let rtt_ms = (recv_unix_ms - send_unix_ms).max(0);
        // Standard SNTP offset estimator under the symmetric-link assumption:
        //   offset = (server_tx + rtt/2) - local_recv
        // Positive values mean the server clock is ahead of ours.
        let offset_ms = server_unix_ms + rtt_ms / 2 - recv_unix_ms;

        let used_stratum = if server_stratum > 0 {
            server_stratum
        } else {
            fallback_stratum
        };

        return Some(NtpResult {
            host: host.to_string(),
            offset_ms,
            rtt_ms,
            stratum: used_stratum,
            tier,
        });
    }
    if let Some(e) = last_err {
        // Print is intentional and used by the daemon's diagnostics.
        eprintln!("[ntp] {host} unreachable: {e}");
    }
    None
}

/// Query every source in `NTP_SOURCES` in parallel threads.
/// Returns a sorted, deduplicated list of healthy results, capped at min(10, ...).
pub fn discover_sources(min_count: usize) -> Vec<NtpResult> {
    let (tx, rx) = mpsc::channel::<Option<NtpResult>>();
    let mut handles = Vec::with_capacity(NTP_SOURCES.len());

    for src in NTP_SOURCES.iter().copied() {
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let res = query_ntp(src.host, src.port, src.tier, src.stratum);
            let _ = tx.send(res);
        }));
    }
    drop(tx);

    let mut results: Vec<NtpResult> = rx.into_iter().flatten().collect();
    for h in handles {
        let _ = h.join();
    }

    // Sort: tier rank ascending, then RTT ascending.
    results.sort_by(|a, b| {
        a.tier
            .rank()
            .cmp(&b.tier.rank())
            .then_with(|| a.rtt_ms.cmp(&b.rtt_ms))
    });

    // Deduplicate by hostname (keep best == first occurrence).
    let mut seen: Vec<String> = Vec::new();
    results.retain(|r| {
        if seen.iter().any(|h| h == &r.host) {
            false
        } else {
            seen.push(r.host.clone());
            true
        }
    });

    let cap = std::cmp::min(10, std::cmp::max(min_count, results.len()));
    results.truncate(cap);
    results
}

/// Best-effort PPS detection. The daemon treats /dev/pps0 as proof that a GPS
/// timing receiver is wired in; the system clock then becomes the GPS reference.
pub fn has_gps_pps() -> bool {
    std::path::Path::new("/dev/pps0").exists()
}

pub fn to_source_status(results: &[NtpResult]) -> Vec<NtpSourceStatus> {
    results
        .iter()
        .map(|r| NtpSourceStatus {
            host: r.host.clone(),
            tier: r.tier,
            rtt_ms: r.rtt_ms,
            offset_ms: r.offset_ms,
            stratum: r.stratum,
            active: true,
        })
        .collect()
}
