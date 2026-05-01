# X1 Strontium

Decentralized atomic time oracle for the X1 blockchain.

[![CI](https://github.com/PioWin-clo/x1-strontium/actions/workflows/ci.yml/badge.svg)](https://github.com/PioWin-clo/x1-strontium/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Polish version: [README.pl.md](README.pl.md)

X1 Strontium aggregates measurements from 43 NTP sources across six
continents (31 Stratum-1 / NTS-capable servers plus 12 pool fallbacks)
and writes consensus UTC timestamps to an Anchor smart contract on the
X1 mainnet. Any X1 program can then call `read_time` over CPI to get a
trustworthy clock — without depending on the unreliable on-chain
`Clock::unix_timestamp`.

**v1.1** is an in-place upgrade that replaces the operator-onboarding
flow with a simpler file-based model. The Program ID is preserved
(deployed via `solana program deploy --program-id <existing>`) but the
OracleState PDA gains a fourth seed segment so the v1.0 PDA at
`EQ9CgHkx…` is left orphan on chain. Registration is now a single
2-signer transaction the daemon builds itself; the operator's hardware
wallet only ever signs the initial XNT transfer that funds the
`oracle.json` keypair.

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

## Quick facts (mainnet v1.1)

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
| Minimum self-stake     | 128 XNT per operator (off-chain gate)                  |
| Minimum validator age  | 64 epochs of voting history (off-chain gate)           |
| Auto-cleanup threshold | 10 of an operator's own rotation turns missed in a row |
| On-chain account size  | 9744 B (488 B headroom under X1's 10 240 B CPI cap)    |
| Maximum operators      | 512                                                    |

Retired (closed on chain) v0.5 Program ID for reference only:
`2FgHeEQfY1C774uyo8RDKHcjTRz2mVPJ6wotrD9P3YgJ`. The v1.0 OracleState PDA
at `EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy` is orphan post-v1.1
upgrade — its 0.07 XNT of rent stays locked there forever.

**Bootstrap mode (v1.1.1+).** Strontium reports `is_degraded = 1`
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
   (~2 months of activity) and self-stake ≥ 128 XNT, where the stake's
   withdraw authority equals your validator's vote account
   `authorized_withdrawer`. These are anti-farm gates verified
   off-chain by the daemon at register time and on every 24-hour
   refresh.

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
| `sys=`       | Daemon's system clock at the consensus moment (NEW in v1.1)   |
| `chain=`     | On-chain `Clock::unix_timestamp` at submission (or `??`)      |
| `drift=`     | Signed ms delta between our estimate and `chain=` (or `null`) |
| `sysdrift=`  | Signed ms delta between our estimate and `sys=` (NEW in v1.1) |
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
  or qualifying self-stake below 128 XNT. The contract holds no
  parsers; the gates live in the open-source daemon code that anyone
  can audit.

- **Auto-cleanup of inactive operators** — the contract removes
  operators who miss 10 consecutive of their own rotation turns. The
  threshold scales naturally with fleet size (~100 min for n=2, ~14 h
  for n=100). Permissionless: any caller can fire the
  `cleanup_inactive` instruction with a batch of registrations in
  `remaining_accounts`. No admin removal, no governance vote.

- **One registration per oracle keypair** — rotation = generate a fresh
  `oracle.json`, fund it, and re-register. The old registration auto-
  cleans after 10 missed turns. No on-chain "rotate" instruction; no
  hardware-wallet ceremony for routine key rotation.

---

## Roadmap

- **v1.1** (this release) — file-based oracle keypair model, 2-signer
  `register_submitter`, off-chain anti-farm gates, permissionless
  `cleanup_inactive`, in-place program upgrade.

- **v1.2** — `read_time_smoothed(windows)` CPI helper that reads N
  recent ring entries, drops outliers, and returns the median. Useful
  for consumers that want low-jitter monotone output over strict
  most-recent-sample semantics.

- **v1.3** — true NTS-KE authentication on the NTS-capable endpoints.
  Today the daemon polls those servers via plain NTP; the tier label
  `nts` is informational only until session-key handshake lands.

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
