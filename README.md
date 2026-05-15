# X1 Strontium

Decentralized atomic time oracle for the X1 blockchain.

[![Release](https://github.com/PioWin-clo/X1_Strontium/actions/workflows/release.yml/badge.svg)](https://github.com/PioWin-clo/X1_Strontium/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Polish version: [README.pl.md](README.pl.md)

X1 Strontium aggregates measurements from 43 NTP sources across six
continents (31 Stratum-1 / NTS-capable servers plus 12 pool fallbacks)
and writes consensus UTC timestamps to an Anchor smart contract on the
X1 mainnet. Any X1 program can then call `read_time` over CPI to get a
trustworthy clock — without depending on the unreliable on-chain
`Clock::unix_timestamp`.

**v1.3** is an in-place upgrade on top of the v1.2.0 file-based
operator-onboarding flow. Cleanup tolerance switches from a per-fleet-
size missed-turn count to a fixed 24-hour wall-clock grace; the daemon
re-registers automatically at startup when its PDA was closed by a
prior `cleanup_inactive`; the memo's `sysdrift=` field now reflects the
true drift at the NTP poll moment (v1.2.x had a phantom ~30 s offset);
and two new Stratum-1 NTP sources land (`hora.roa.es`,
`time2.kriss.re.kr`). The Program ID is preserved; the on-chain
`OracleState` layout is unchanged.

---

## The problem

X1's `Clock::unix_timestamp` is sourced from the block leader's local
clock and drifts substantially behind real UTC. Empirical measurements
over six hours on 13.04.2026 (473 samples):

| Time UTC | NTP        | Chain      | Drift |
|----------|------------|------------|-------|
| 22:40    | 22:40:01   | 22:39:47   | 13 s  |
| 23:40    | 23:40:18   | 23:40:05   | 13 s  |
| 00:40    | 00:40:32   | 00:40:18   | 14 s  |
| 01:40    | 01:40:45   | 01:40:30   | 15 s  |
| 02:40    | 02:40:39   | 02:40:21   | 18 s  |
| 03:40    | 03:40:54   | 03:40:33   | 20 s  |

**Average drift: 14.48 s** over 473 measurements. X1 Strontium provides
the missing certified time reference.

---

## Quick facts (mainnet v1.3)

| Field                  | Value                                                  |
|------------------------|--------------------------------------------------------|
| Program ID             | `2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch`         |
| Oracle State PDA       | `cfm1Tc7CNdTa8Hm8FGWAuHXaaozSjQHNmdBD5mEVN9P`          |
| Oracle State PDA bump  | 255                                                    |
| PDA seeds              | `[b"X1", b"Strontium", b"v1", b"oracle"]`              |
| Registration PDA seeds | `[b"reg", oracle_keypair_pubkey]` (one per operator)   |
| Cadence                | 300 s per submission (configurable via `interval_s`)   |
| Aggregation window     | 150 slots (~60 s)                                      |
| Ring buffer depth      | 288 entries (24 h of history at 5-minute cadence)      |
| Quorum                 | 10 % of registered operators, min 1, max 6             |
| Minimum self-stake     | withdrawer-match: stake withdraw authority must equal vote account authorized_withdrawer (off-chain gate) |
| Minimum validator age  | 64 epochs of voting history (off-chain gate)           |
| Auto-cleanup threshold | 1440 contract-windows of silence (~24 h, fleet-size independent — v1.3) |
| On-chain account size  | 9744 B (488 B headroom under X1's 10 240 B CPI cap)    |
| Maximum operators      | 512                                                    |

Retired (closed on chain) v0.5 Program ID for reference only:
`2FgHeEQfY1C774uyo8RDKHcjTRz2mVPJ6wotrD9P3YgJ`.

**Bootstrap mode.** Strontium reports `is_degraded = 1`
regardless of per-window quorum and confidence whenever the active
operator fleet is below `MIN_QUORUM_ABSOLUTE = 3`. dApps should treat
`is_degraded = 1` as a signal to fall back to alternate time sources
(e.g. `Clock::unix_timestamp` or another oracle) until enough
independent operators register.

---

## For dApp developers: reading the time

```rust
use anchor_lang::prelude::*;
use x1_strontium::{cpi, program::X1Strontium, OracleState, TimeReading};

pub fn use_strontium(ctx: Context<UseStrontium>) -> Result<()> {
    let cpi_ctx = CpiContext::new(
        ctx.accounts.x1_strontium_program.to_account_info(),
        cpi::accounts::ReadTime {
            oracle_state: ctx.accounts.oracle_state.to_account_info(),
        },
    );
    // 300 = max staleness in slots. If the oracle hasn't aggregated within
    // the last 300 slots (~2 min at 400 ms/slot), the call errors with
    // OracleStale and the caller can fall back to `Clock::unix_timestamp`.
    let reading: TimeReading = cpi::read_time(cpi_ctx, 300)?.get();
    msg!(
        "strontium time: {} ms (confidence {}%, {} sources)",
        reading.timestamp_ms,
        reading.confidence_pct,
        reading.sources_count,
    );
    Ok(())
}
```

The Oracle State PDA above (`cfm1Tc7C…`) is a singleton — there is
exactly one per mainnet deployment; your contract does not need to
derive it. `read_time` is free for callers (no transaction required, no
allowlist).

---

## For validators: operator onboarding

X1 Strontium uses a file-based oracle keypair model with a one-time
hardware-wallet bootstrap. Joining the operator set requires:

1. **An active X1 validator** with at least 64 epochs of voting history
   (~2 months of activity) and self-stake whose withdraw authority
   equals your validator's vote account `authorized_withdrawer`
   (withdrawer-match gate — any amount qualifies). These are anti-farm
   gates verified off-chain by the daemon at register time and on every
   24-hour refresh.

2. **A one-time XNT transfer** from a hardware wallet (Ledger, Trezor,
   or any other) holding the validator's withdraw authority, to the
   daemon-generated `oracle.json` pubkey. About 0.5 XNT suffices —
   that covers `register_submitter` rent plus ~250 days of `submit_time`
   fees at the default 5-minute cadence. The exact amount is the
   operator's call.

3. **Running `x1-strontium register`** on the validator host. The
   command auto-generates `oracle.json` if missing, runs the off-chain
   anti-farm gates, and on success builds the 2-signer
   `register_submitter` transaction (signed by `oracle.json` and the
   validator's vote keypair). Once registered, the daemon autonomously
   rotates with other operators and submits time transactions only when
   its turn comes around — sleeping most of the time to keep server
   load minimal.

Full walkthrough: [docs/OPERATOR_ONBOARDING.md](docs/OPERATOR_ONBOARDING.md).

---

## Architecture

```
 ┌────────────────────┐  SNTPv3   ┌────────────────────┐
 │ 43 NTP sources     │◄─────────►│ x1-strontium       │
 │ (EU/AM/APAC/pool,  │           │ daemon             │
 │  31 Stratum-1 /    │           │  ├─ consensus      │
 │  NTS-capable + 12  │           │  │  (median + IQR  │
 │  pool fallbacks)   │           │  │   + cross-tier) │
 └────────────────────┘           │  ├─ rotation       │
                                  │  │  (window-slot,  │
                                  │  │   n>6 fallback) │
                                  │  └─ TSC correction │
                                  └──────────┬─────────┘
                                             │ submit_time
                                             │  (oracle.json signs)
                                             ▼
                                  ┌────────────────────┐
                                  │ X1 Strontium       │
                                  │ on-chain program   │
                                  │  ├─ OracleState    │
                                  │  ├─ 6-slot window  │
                                  │  │  (median agg.)  │
                                  │  ├─ 288-entry ring │
                                  │  │  (24 h history) │
                                  │  └─ ValidatorReg.  │
                                  │     PDAs (per op.) │
                                  └──────────┬─────────┘
                                             │ read_time  (CPI)
                                             ▼
                                  ┌────────────────────┐
                                  │ Any X1 dApp        │
                                  └────────────────────┘

   ┌─────────────────────┐
   │ hardware wallet     │  ── solana transfer ─►  oracle.json
   │ (Ledger, Trezor,    │     (≥ 0.5 XNT, ONE TIME at onboarding)
   │  any other)         │
   └─────────────────────┘
```

The hardware wallet appears exactly once in the operator's lifecycle —
to fund a freshly generated `oracle.json` keypair. From then on the
daemon is autonomous; rotation, submission, and cleanup are all
file-key signed.

---

## Memo format (v1)

Every `submit_time` TX carries a Solana Memo instruction with the
submission's provenance. The memo format is stable within the v1 major:

```
X1Strontium:v1:w=5921961:nts=08:45:00.003:sys=08:45:00.005:chain=08:45:00.000:drift=3:sysdrift=-2:c=97:s=10:st=1
```

| Field        | Meaning                                                       |
|--------------|---------------------------------------------------------------|
| `w=`         | Rotation window id                                            |
| `<tier>=`    | Consensus time (HH:MM:SS.mmm); prefix is `gps`/`nts`/`s1`/`ntp` |
| `sys=`       | Daemon's system clock at the consensus moment                 |
| `chain=`     | On-chain `Clock::unix_timestamp` at submission (or `??`)      |
| `drift=`     | Signed ms delta between our estimate and `chain=` (or `null`) |
| `sysdrift=`  | Signed ms delta between our estimate and `sys=`               |
| `c=`         | Confidence percent (60–99)                                    |
| `s=`         | Number of sources used                                        |
| `st=`        | Best stratum among contributing sources                       |

No STAMP fields. Anything claiming to be a newer memo version or carrying
`:ppm=` / `:off=` / `:tsc=` / `:ent=` / `:stamp=` is not emitted by this
daemon.

The `sysdrift` field exposes each operator's local clock health: large
deviations from the NTP consensus (positive or negative) are an early
signal that the validator host's `systemd-timesyncd` or chrony is
mis-disciplined, even when the daemon's own NTP poll still produces
acceptable results.

---

## Key design choices

- **Offset-based consensus** — the daemon polls 43 NTP sources, applies
  a 3× IQR outlier filter on offsets (not timestamps), runs leap-second
  smear detection, and requires cross-tier agreement (at least one
  Stratum-1 / NTS source within 50 ms of the median). Confidence is a
  weighted blend of source quality (40 %), spread (40 %), and tier
  (20 %).

- **Wall-clock window alignment** — submissions are emitted exactly on
  5-minute boundaries (e.g. `12:35:00.000`), with the TSC-stopwatch
  correction applied so the on-chain timestamp reflects the moment the
  TX leaves the daemon (not the moment NTP consensus finished, ~100–
  2000 ms earlier). Memo and on-chain agree by construction.

- **Off-chain anti-farm enforcement** — the daemon refuses to register
  or submit if the validator has fewer than 64 epochs of voting history
  or no self-stake with matching withdraw authority (withdrawer-match
  gate). The contract holds no parsers; the gates live in the
  open-source daemon code that anyone can audit.

- **Auto-cleanup of inactive operators** — operators that don't submit
  `submit_time` for ~24 hours are removed from the active set by
  `cleanup_inactive`, regardless of fleet size. One day of grace covers
  reboots, maintenance windows, and transient network outages without
  manual intervention. (v1.3+ behaviour; v1.2.x used per-turn missed-
  count math that gave only ~22 min tolerance at n=2 and ~14 h at
  n=100 — fixed in the v1.3 changelog.) Permissionless: any caller can
  fire the `cleanup_inactive` instruction with a batch of registrations
  in `remaining_accounts`, and the rent recovered from each closed PDA
  flows back to the cleanup-TX payer. No admin removal, no governance
  vote.

- **One registration per oracle keypair** — rotation = generate a fresh
  `oracle.json`, fund it, and re-register. The old registration auto-
  cleans after 24 h of silence. v1.3+ auto-recovers at startup: if the
  daemon finds its PDA missing or inactive, it rebuilds and sends the
  2-signer `register_submitter` TX itself (gated by oracle balance,
  vote keypair availability, and the same anti-farm self-stake check
  as the manual `register` subcommand). No on-chain "rotate"
  instruction; no hardware-wallet ceremony for routine key rotation.

---

## Roadmap

- **v1.3** (this release) — 24 h wall-clock cleanup grace
  (`CLEANUP_GRACE_WINDOWS = 1440`, fleet-size independent), startup
  auto-recover when the registration PDA is missing or flagged inactive
  (gated by 0.6 XNT min balance + withdrawer-match self-stake), memo's
  `sysdrift=` field reads the cached drift snapshot from the NTP poll
  moment (fixes phantom ~30 s offset under the pre-poll architecture),
  two new Stratum-1 NTP sources (`hora.roa.es`, `time2.kriss.re.kr`),
  System76 endpoints relabeled Stratum 2 to match actual responses.

- **v1.2.1** (previous) — DNS-fallback fix in `RpcClient` (bypass
  cooldowns when every URL is cold), defensive guard on the `x1sr
  status` drift renderer, `cleanup_inactive` closes the PDA instead of
  just flipping `is_active = false` (so the same `oracle_keypair` can
  re-register cleanly).

- **v1.2.0** (initial v1.2 line) — runway calculation corrected for
  fleet size n, install fix (unit file always written), silent RPC
  fallback, chain drift + sysdrift in status output, pre-computation
  NTP polling (sub-200ms TX timing), withdrawer-match stake gate.

- **v1.4 (proposed)** — true NTS-KE authentication on the NTS-capable
  endpoints. Today the daemon polls those servers via plain NTP; the
  tier label `nts` is informational only until session-key handshake
  lands. Likely also: re-probe USNO×2 + INRIM + named-region fallbacks
  from the Sentinel production network, add whichever respond.

- **v∞ — contract lock.** Once multiple operators beyond Prime +
  Sentinel have joined and the Tachyon validator update has rolled
  out, the upgrade authority will be removed and the contract becomes
  immutable. Any future expansion happens as a Strontium v2 program
  alongside v1, after community discussion in the X1 builders group.

**Research direction (not on roadmap) — retrospective time consensus
attestation.** The on-chain ring buffer is a cryptographically-anchored
24 h history of median UTC timestamps, signed by the full operator
fleet. We are exploring whether this can be used as an out-of-band
timestamp proof for *past* events (e.g. a dApp proving "I recorded this
state at UTC T, and here is the corroborating oracle entry at window
W"). This is open research, not planned work.

---

## Why "Strontium"?

Strontium-87 is the atom whose 5s² → 5s5p transition underpins the most
accurate optical lattice clocks built so far — the ones that define
the second to a few parts in 10⁻¹⁸. The name is aspirational, not a
claim of comparable precision: the oracle's job is to deliver
millisecond-grade UTC to a chain whose native clock drifts by tens of
seconds. Same spirit, dramatically different scale.

---

## License

MIT. See [LICENSE](LICENSE).
