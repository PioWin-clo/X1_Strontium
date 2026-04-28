# X1 Strontium

Zdecentralizowany atomowy oracle czasu dla blockchaina X1.

[![CI](https://github.com/PioWin-clo/x1-strontium/actions/workflows/ci.yml/badge.svg)](https://github.com/PioWin-clo/x1-strontium/actions/workflows/ci.yml)
[![Licencja](https://img.shields.io/badge/licencja-MIT-blue.svg)](LICENSE)

> Wersja angielska: [README.md](README.md)

X1 Strontium agreguje pomiary z 43 serwerów NTP Stratum-1 z czterech
kontynentów i zapisuje konsensusowe znaczniki czasu UTC do smart contractu
Anchora w sieci głównej X1. Każdy program X1 może następnie wywołać
`read_time` przez CPI, aby uzyskać wiarygodny zegar — bez polegania na
zawodnym on-chainowym `Clock::unix_timestamp`.

**v1.0** to czysty re-release oracle. Spekulatywna funkcja STAMP
(hardware fingerprint) wysłana w v0.5 nie przeszła recenzji naukowej i
została całkowicie usunięta; format memo, układ danych on-chain i seedy
PDA są nowe (`["X1","Strontium","v1"]`). Poprawione zostały też dwa bugi
z v0.5 — patrz [Changelog](#changelog-względem-v05).

---

## Problem

`Clock::unix_timestamp` w X1 pochodzi z lokalnego zegara lidera bloku i
znacząco opóźnia się względem realnego UTC. Pomiary empiryczne z
13.04.2026 (6 godzin, 473 próbki):

| Czas UTC | NTP        | Chain      | Dryf  |
|----------|------------|------------|-------|
| 22:40    | 22:40:01   | 22:39:47   | 13 s  |
| 23:40    | 23:40:18   | 23:40:05   | 13 s  |
| 00:40    | 00:40:32   | 00:40:18   | 14 s  |
| 01:40    | 01:40:45   | 01:40:30   | 15 s  |
| 02:40    | 02:40:39   | 02:40:21   | 18 s  |
| 03:40    | 03:40:54   | 03:40:33   | 20 s  |

**Średni dryf: 14,48 s** w 473 pomiarach. X1 Strontium dostarcza
brakującego certyfikowanego źródła czasu.

---

## Szybkie fakty (mainnet v1.0)

| Pole                         | Wartość                                              |
|------------------------------|------------------------------------------------------|
| Program ID                   | `2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch`       |
| Oracle State PDA             | `EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy`       |
| Seedy PDA                    | `[b"X1", b"Strontium", b"v1"]`                       |
| Częstotliwość                | 300 s między submisjami (regulowane `interval_s`)    |
| Okno agregacji               | 150 slotów (~60 s)                                   |
| Głębokość ring buffera       | 288 wpisów (24 h historii przy 5-min interwale)      |
| Quorum                       | 10 % zarejestrowanych operatorów, min 1, max 6       |
| Dolny próg self-stake        | 128 XNT na operatora                                 |
| Rozmiar konta on-chain       | 9744 B (488 B zapasu pod limitem 10 240 B CPI X1)    |

Wycofany (zamknięty on-chain) Program ID v0.5 wyłącznie do odniesienia:
`2FgHeEQfY1C774uyo8RDKHcjTRz2mVPJ6wotrD9P3YgJ`.

---

## Architektura

```
 ┌────────────────────┐  SNTPv3   ┌────────────────────┐
 │ 43 źródła NTP      │◄─────────►│ x1-strontium       │
 │ (EU/AM/APAC/pool,  │           │ daemon             │
 │  31 Stratum-1 /    │           │  ├─ consensus      │
 │  NTS-capable + 12  │           │  │  (mediana + IQR │
 │  zapas. pool)      │           │  │   + cross-tier) │
 └────────────────────┘           │  ├─ rotacja        │
                                  │  │  (window-slot,  │
                                  │  │   fallback n>6) │
                                  │  └─ korekta TSC    │
                                  └──────────┬─────────┘
                                             │ submit_time
                                             ▼
                                  ┌────────────────────┐
                                  │ X1 Strontium       │
                                  │ program on-chain   │
                                  │  ├─ OracleState    │
                                  │  ├─ 6-slot okno    │
                                  │  │  (agregacja     │
                                  │  │   medianą)      │
                                  │  └─ ring 288 wpis. │
                                  │     (24 h history) │
                                  └──────────┬─────────┘
                                             │ read_time  (CPI)
                                             ▼
                                  ┌────────────────────┐
                                  │ Dowolny dApp X1    │
                                  └────────────────────┘
```

---

## Odczyt czasu z własnego kontraktu

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
    // 300 = maksymalny wiek danych w slotach. Jeżeli oracle nie zagregował
    // w ciągu ostatnich 300 slotów (~2 min przy 400 ms/slot), wywołanie
    // zwraca OracleStale i wywołujący może cofnąć się do
    // `Clock::unix_timestamp`.
    let reading: TimeReading = cpi::read_time(cpi_ctx, 300)?.get();
    msg!(
        "czas strontium: {} ms (confidence {}%, {} źródeł)",
        reading.timestamp_ms,
        reading.confidence_pct,
        reading.sources_count,
    );
    Ok(())
}
```

Oracle State PDA wyżej (`EQ9CgHkx…`) jest singletonem — jest dokładnie
jeden per deploy mainnet; Twój kontrakt nie musi go derivować.

---

## Model walidatora / operatora

Uruchomienie węzła oracle wymaga walidatora X1 i portfela sprzętowego
Ledger. Kontrakt używa **modelu dwukluczowego**:

- **`authority` (Ledger, zimny)** — musi równać się
  `authorized_withdrawer` konta vote walidatora. Podpisuje tylko rzadkie
  operacje administracyjne: `initialize_operator`, `rotate_hot_signer`,
  `deactivate_operator`, `close_operator`. Żyje w szufladzie / sejfie.
- **`hot_signer` (keypair na serwerze)** — podpisuje `submit_time` w
  każdym cyklu. Rotowany od strony zimnej; kompromitacja hot signera nie
  naraża stake'a.

Self-stake ≥ 128 XNT z `withdrawer == authority` jest wymuszany zarówno
przy `initialize_operator`, jak i co ~24 h wewnątrz `submit_time`. Pełny
opis: [`docs/OPERATOR_ONBOARDING.md`](docs/OPERATOR_ONBOARDING.md).

**Daemon nigdy nie ładuje Ledgera** — trzyma wyłącznie hot signer.
Instrukcje administracyjne buduje się poza pasmem z poziomu CLI `solana`.

---

## Format Memo (v1)

Każda transakcja `submit_time` niesie instrukcję Solana Memo z proweniencją
submisji. Format memo jest stabilny w ramach majora v1:

```
X1Strontium:v1:w=5921961:nts=08:45:00.003:chain=08:45:00.000:drift=3:c=97:s=10:st=1
```

| Pole     | Znaczenie                                                 |
|----------|-----------------------------------------------------------|
| `w=`     | Numer okna rotacji                                        |
| `<tier>=`| Czas konsensusu (HH:MM:SS.mmm); prefix to `gps`/`nts`/`s1`/`ntp` |
| `chain=` | `Clock::unix_timestamp` w momencie wysyłki (lub `??`)     |
| `drift=` | Różnica w ms między naszym estymatorem a `chain=` (lub `null`) |
| `c=`     | Confidence (procent, 60–99)                               |
| `s=`     | Liczba użytych źródeł                                     |
| `st=`    | Najlepszy stratum wśród źródeł                            |

Żadnych pól STAMP. Cokolwiek podające się za nowszą wersję memo lub
niosące `:ppm=` / `:off=` / `:tsc=` / `:ent=` / `:stamp=` nie jest
emitowane przez ten daemon.

---

## Changelog względem v0.5

- **Bug #1 fix** — `MIN_SELF_STAKE_LAMPORTS` w daemonie podniesiony ze 100
  XNT do 128 XNT żeby pasował do kontraktu on-chain. Operatorzy teraz
  dostają off-chainowe ostrzeżenie zanim 24 h on-chainowy recheck to
  odrzuci.
- **Bug #2 fix** — on-chainowe `aggregate()` aktualizuje ring buffer
  **in place** dla submisji w tym samym oknie 150-slotowym. Wcześniej
  fleet 2-operatorowy z quorum 1 efektywnie dzielił głębokość ringu o
  połowę — z 24 h do 12 h.
- **STAMP usunięty.** Pola memo, komenda doctor, zależność blake3, ścieżka
  `measure_stamp` — wszystko wycięte.
- Nowy Program ID + Oracle PDA + seedy PDA (v5 → v1). Brak migracji.

---

## Roadmap

- **v1.1** — entrypoint CPI `read_time_smoothed` liczący EWMA po ostatnich
  N wpisach ring buffera, dla konsumentów preferujących wyjście monotonne
  o niskim jitterze od ścisłej semantyki "najnowsza próbka".
- **v1.2** — prawdziwa autoryzacja NTS-KE (rustls) na sześciu endpointach
  z obsługą NTS, zastępująca zwykły NTP. Label tieru `nts` staje się
  faktycznie znaczący.
- **v1.3** — CLI `x1sr-admin` budujące Ledger-podpisane TX-y
  `initialize_operator` / `rotate_hot_signer` / `deactivate_operator` /
  `close_operator` bez potrzeby CLI Solany.

**Kierunek badań — retrospektywna atestacja konsensusu czasowego.**
On-chainowy ring buffer to kryptograficznie zakotwiczona 24 h historia
median UTC, podpisana przez cały fleet. Sprawdzamy czy można tego używać
jako zewnętrznego dowodu timestamp'u dla *przeszłych* zdarzeń (np. dApp
udowadniający "zarejestrowałem ten stan o UTC T, a oto korespondujący
wpis oracle w oknie W"). To nie jest feature w v1.x — to pytanie, które
napędza v2.

---

## Licencja

MIT. Patrz [LICENSE](LICENSE).
