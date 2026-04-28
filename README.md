# X1 Strontium

Decentralized atomic time oracle for the X1 blockchain.

[![CI](https://github.com/PioWin-clo/x1-strontium/actions/workflows/ci.yml/badge.svg)](https://github.com/PioWin-clo/x1-strontium/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Polish version: [README.pl.md](README.pl.md)

X1 Strontium aggregates measurements from 43 Stratum-1 NTP servers across
four continents and writes consensus UTC timestamps to an Anchor smart
contract on the X1 mainnet. Any X1 program can then call `read_time` over
CPI to get a trustworthy clock — without depending on the unreliable
on-chain `Clock::unix_timestamp`.

**v1.0** is a clean re-release of the oracle. The speculative STAMP
hardware-fingerprinting feature shipped in v0.5 did not survive scientific
review and has been removed wholesale; the memo format, on-chain data
layout, and PDA seeds are all new (`["X1","Strontium","v1"]`). Two v0.5
bugs are also fixed — see [CHANGELOG](#changelog-vs-v05).

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

## Quick facts (mainnet v1.0)

| Field                        | Value                                                |
|------------------------------|------------------------------------------------------|
| Program ID                   | `2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch`       |
| Oracle State PDA             | `EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy`       |
| PDA seeds                    | `[b"X1", b"Strontium", b"v1"]`                       |
| Cadence                      | 300 s per submission (configurable via `interval_s`) |
| Aggregation window           | 150 slots (~60 s)                                    |
| Ring buffer depth            | 288 entries (24 h of history at 5-minute cadence)    |
| Quorum                       | 10 % of registered operators, min 1, max 6           |
| Self-stake floor             | 128 XNT per operator                                 |
| On-chain account size        | 9744 B (488 B headroom under X1's 10 240 B CPI cap)  |

Retired (closed on chain) v0.5 Program ID for reference only:
`2FgHeEQfY1C774uyo8RDKHcjTRz2mVPJ6wotrD9P3YgJ`.

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
                                             ▼
                                  ┌────────────────────┐
                                  │ X1 Strontium       │
                                  │ on-chain program   │
                                  │  ├─ OracleState    │
                                  │  ├─ 6-slot window  │
                                  │  │  (median agg.)  │
                                  │  └─ 288-entry ring │
                                  │     (24 h history) │
                                  └──────────┬─────────┘
                                             │ read_time  (CPI)
                                             ▼
                                  ┌────────────────────┐
                                  │ Any X1 dApp        │
                                  └────────────────────┘
```

---

## Reading the time from your contract

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

The Oracle State PDA above (`EQ9CgHkx…`) is a singleton — there is exactly
one per mainnet deployment; your contract does not need to derive it.

---

## Validator / operator model

Running an oracle node requires a validator on X1 and a Ledger hardware
wallet. The contract uses a **two-key model**:

- **`authority` (Ledger, cold)** — must equal the vote account's
  `authorized_withdrawer`. Signs only rare admin ops:
  `initialize_operator`, `rotate_hot_signer`, `deactivate_operator`,
  `close_operator`. Lives in a drawer / safe.
- **`hot_signer` (server-local keypair)** — signs `submit_time` every
  cycle. Rotatable from the cold side; compromise of the hot signer does
  not expose stake.

Self-stake of ≥ 128 XNT with `withdrawer == authority` is enforced both at
`initialize_operator` and again every ~24 h inside `submit_time`.
Full walkthrough: [`docs/OPERATOR_ONBOARDING.md`](docs/OPERATOR_ONBOARDING.md).

The **daemon never loads the Ledger** — it only holds the hot signer.
Admin instructions are built out-of-band with `solana` CLI.

---

## Memo format (v1)

Every `submit_time` TX carries a Solana Memo instruction with the
submission's provenance. The memo format is stable within the v1 major:

```
X1Strontium:v1:w=5921961:nts=08:45:00.003:chain=08:45:00.000:drift=3:c=97:s=10:st=1
```

| Field    | Meaning                                                   |
|----------|-----------------------------------------------------------|
| `w=`     | Rotation window id                                        |
| `<tier>=`| Consensus time (HH:MM:SS.mmm); prefix is `gps`/`nts`/`s1`/`ntp` |
| `chain=` | On-chain `Clock::unix_timestamp` at submission (or `??`)  |
| `drift=` | Signed ms delta between our estimate and `chain=` (or `null`)  |
| `c=`     | Confidence percent (60–99)                                |
| `s=`     | Number of sources used                                    |
| `st=`    | Best stratum among contributing sources                   |

No STAMP fields. Anything claiming to be a newer memo version or carrying
`:ppm=` / `:off=` / `:tsc=` / `:ent=` / `:stamp=` is not emitted by this
daemon.

---

## Changelog vs v0.5

- **Bug #1 fix** — daemon's `MIN_SELF_STAKE_LAMPORTS` raised from 100 XNT
  to 128 XNT so it matches the on-chain contract. Operators now get an
  off-chain early warning before the 24 h on-chain recheck fires.
- **Bug #2 fix** — on-chain `aggregate()` now updates the ring buffer
  **in place** for submissions in the same 150-slot window. Previously a
  2-operator fleet with quorum 1 effectively halved the ring depth from
  24 h to 12 h.
- **STAMP removed.** Hardware-fingerprinting memo fields, doctor command,
  blake3 dependency, `measure_stamp` codepath — all gone.
- New Program ID + Oracle PDA + PDA seeds (v5 → v1). No upgrade migration.

---

## Roadmap

- **v1.1** — `read_time_smoothed` CPI entrypoint that computes an EWMA
  over the last N ring entries, for consumers that prefer low-jitter
  monotone output over strict "most recent sample" semantics.
- **v1.2** — real NTS-KE authentication (rustls) on the six NTS-capable
  endpoints, replacing plain NTP. Tier label `nts` becomes load-bearing.
- **v1.3** — `x1sr-admin` CLI that assembles Ledger-signed
  `initialize_operator` / `rotate_hot_signer` / `deactivate_operator` /
  `close_operator` TXs without needing the Solana CLI.

**Research direction — retrospective time consensus attestation.** The
on-chain ring buffer is a cryptographically-anchored 24 h history of
median UTC timestamps, signed by the full fleet. We are exploring whether
this can be used as an out-of-band timestamp proof for *past* events
(e.g. a dApp proving "I recorded this state at UTC T, and here is the
corroborating oracle entry at window W"). This is not a v1.x feature — it
is the question that drives v2.

---

## License

MIT. See [LICENSE](LICENSE).
