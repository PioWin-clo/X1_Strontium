# X1 Strontium

Zdecentralizowany atomowy oracle czasu dla blockchaina X1.

[![Release](https://github.com/PioWin-clo/X1_Strontium/actions/workflows/release.yml/badge.svg)](https://github.com/PioWin-clo/X1_Strontium/actions/workflows/release.yml)
[![Licencja](https://img.shields.io/badge/licencja-MIT-blue.svg)](LICENSE)

> Wersja angielska: [README.md](README.md)

X1 Strontium agreguje pomiary z 45 źródeł NTP rozmieszczonych na sześciu
kontynentach (33 serwery Stratum-1 / NTS oraz 12 zapasowych z poolu) i
zapisuje konsensusowe znaczniki czasu UTC do smart contractu Anchora w
sieci głównej X1. Każdy program X1 może następnie wywołać `read_time`
przez CPI, aby uzyskać wiarygodny zegar — bez polegania na zawodnym
on-chainowym `Clock::unix_timestamp`.

**v1.3** to upgrade in-place na bazie procesu onboardingu operatorów
opartego o pliki kluczy z v1.2.0. Tolerancja cleanup przełącza się z
per-fleet-size missed-turn count na stałe 24-godzinne okno wall-clock;
daemon rejestruje się automatycznie przy starcie, gdy jego PDA zostało
zamknięte przez wcześniejszy `cleanup_inactive`; pole `sysdrift=` w
memo odzwierciedla teraz prawdziwy dryf w momencie pollowania NTP
(v1.2.x miało phantom offset ~30 s); dochodzą też dwa nowe źródła
Stratum-1 NTP (`hora.roa.es`, `time2.kriss.re.kr`). Program ID jest
zachowany; layout `OracleState` on-chain bez zmian.

---

## Szybkie fakty (mainnet v1.3)

| Pole                    | Wartość                                                |
|-------------------------|--------------------------------------------------------|
| Program ID              | `2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch`         |
| Oracle State PDA        | `cfm1Tc7CNdTa8Hm8FGWAuHXaaozSjQHNmdBD5mEVN9P`          |
| Bump Oracle State PDA   | 255                                                    |
| Seedy PDA               | `[b"X1", b"Strontium", b"v1", b"oracle"]`              |
| Seedy rejestracji       | `[b"reg", oracle_keypair_pubkey]` (jeden na operatora) |
| Częstotliwość           | 300 s między submisjami (regulowane `interval_s`)      |
| Okno agregacji          | 150 slotów (~60 s)                                     |
| Głębokość ring buffera  | 288 wpisów (24 h historii przy 5-minutowym interwale)  |
| Quorum                  | 10 % zarejestrowanych operatorów, min 1, max 6         |
| Minimalny self-stake    | withdrawer-match: withdraw authority stake'a musi być równy authorized_withdrawer konta vote (gate off-chain) |
| Minimalny wiek walidat. | 64 epoki historii głosowania (gate off-chain)          |
| Próg auto-cleanup       | 1440 contract-window'ów ciszy (~24 h, niezależne od rozmiaru fleeta — v1.3) |
| Rozmiar konta on-chain  | 9744 B (488 B zapasu pod limitem 10 240 B CPI X1)      |
| Maks. liczba operatorów | 512                                                    |

Wycofany (zamknięty on-chain) Program ID v0.5 wyłącznie do odniesienia:
`2FgHeEQfY1C774uyo8RDKHcjTRz2mVPJ6wotrD9P3YgJ`.

**Tryb bootstrap.** Strontium raportuje `is_degraded = 1`
niezależnie od per-okna quorum i confidence dopóki aktywna pula
operatorów jest mniejsza niż `MIN_QUORUM_ABSOLUTE = 3`. dApps powinny
traktować `is_degraded = 1` jako sygnał do fallbacku na alternatywne
źródła czasu (np. `Clock::unix_timestamp` lub inny oracle) dopóki
dołączy wystarczająco niezależnych operatorów.

---

## Dla deweloperów dApp: odczyt czasu

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

Oracle State PDA wyżej (`cfm1Tc7C…`) jest singletonem — jest dokładnie
jeden per deploy mainnet; Twój kontrakt nie musi go derivować.
`read_time` jest darmowy dla wywołujących (bez transakcji, bez
allowlisty).

---

## Dla walidatorów: onboarding operatora

X1 Strontium używa modelu opartego o plik z kluczem oracle z
jednorazowym bootstrapem przez portfel sprzętowy. Dołączenie do zbioru
operatorów wymaga:

1. **Aktywnego walidatora X1** z co najmniej 64 epokami historii
   głosowania (~2 miesiące aktywności) i self-stake, którego withdraw
   authority równa się `authorized_withdrawer` konta vote walidatora
   (withdrawer-match gate — liczy się każda kwota). To są anti-farm
   gates weryfikowane off-chain przez daemona w momencie rejestracji
   oraz co 24 godziny.

2. **Jednorazowego transferu XNT** z portfela sprzętowego (Ledger,
   Trezor, lub dowolnego innego) trzymającego withdraw authority
   walidatora — na pubkey `oracle.json` wygenerowany przez daemona.
   Około 0,5 XNT wystarczy: pokrywa rentę za `register_submitter` plus
   ~250 dni opłat za `submit_time` przy domyślnej kadencji 5-minutowej.
   Dokładna kwota to wybór operatora.

3. **Uruchomienia `x1-strontium register`** na hoście walidatora.
   Komenda generuje `oracle.json` jeśli go nie ma, uruchamia
   off-chainowe gates anti-farm i przy sukcesie buduje 2-podpisową
   transakcję `register_submitter` (podpisaną przez `oracle.json` oraz
   keypair vote walidatora). Po rejestracji daemon autonomicznie
   rotuje z innymi operatorami i wysyła submisje czasu tylko gdy
   wypadnie jego kolejka — większość czasu śpi, oszczędzając zasoby
   serwera.

Pełny opis: [docs/OPERATOR_ONBOARDING.md](docs/OPERATOR_ONBOARDING.md).

---

## Architektura

```
 ┌────────────────────┐  SNTPv3   ┌────────────────────┐
 │ 45 źródeł NTP      │◄─────────►│ x1-strontium       │
 │ (EU/AM/APAC/pool,  │           │ daemon             │
 │  33 Stratum-1 /    │           │  ├─ consensus      │
 │  NTS-capable + 12  │           │  │  (mediana + IQR │
 │  zapas. pool)      │           │  │   + cross-tier) │
 └────────────────────┘           │  ├─ rotacja        │
                                  │  │  (window-slot,  │
                                  │  │   fallback n>6) │
                                  │  └─ korekta TSC    │
                                  └──────────┬─────────┘
                                             │ submit_time
                                             │  (oracle.json podpis)
                                             ▼
                                  ┌────────────────────┐
                                  │ X1 Strontium       │
                                  │ program on-chain   │
                                  │  ├─ OracleState    │
                                  │  ├─ 6-slot okno    │
                                  │  │  (mediana)      │
                                  │  ├─ ring 288 wpis. │
                                  │  │  (24 h history) │
                                  │  └─ ValidatorReg.  │
                                  │     PDAs (per op.) │
                                  └──────────┬─────────┘
                                             │ read_time  (CPI)
                                             ▼
                                  ┌────────────────────┐
                                  │ Dowolny dApp X1    │
                                  └────────────────────┘

   ┌─────────────────────┐
   │ portfel sprzętowy   │  ── solana transfer ─►  oracle.json
   │ (Ledger, Trezor,    │     (≥ 0,5 XNT, JEDNORAZOWO przy onboardzie)
   │  dowolny inny)      │
   └─────────────────────┘
```

Portfel sprzętowy pojawia się dokładnie raz w cyklu życia operatora —
żeby zasilić świeżo wygenerowany `oracle.json`. Od tego momentu daemon
jest autonomiczny; rotacja, submisja i cleanup są podpisywane plikiem.

---

## Format Memo (v1)

Każda transakcja `submit_time` niesie instrukcję Solana Memo z
proweniencją submisji. Format memo jest stabilny w ramach majora v1:

```
X1Strontium:v1:w=5921961:nts=08:45:00.003:sys=08:45:00.005:chain=08:45:00.000:drift=3:sysdrift=-2:c=97:s=10:st=1
```

| Pole         | Znaczenie                                                  |
|--------------|------------------------------------------------------------|
| `w=`         | Numer okna rotacji                                         |
| `<tier>=`    | Czas konsensusu (HH:MM:SS.mmm); prefix to `gps`/`nts`/`s1`/`ntp` |
| `sys=`       | Zegar systemowy daemona w momencie konsensusu              |
| `chain=`     | `Clock::unix_timestamp` w momencie wysyłki (lub `??`)      |
| `drift=`     | Różnica w ms między naszym estymatorem a `chain=` (lub `null`) |
| `sysdrift=`  | Różnica w ms między naszym estymatorem a `sys=`               |
| `c=`         | Confidence (procent, 60–99)                                |
| `s=`         | Liczba użytych źródeł                                      |
| `st=`        | Najlepszy stratum wśród źródeł                             |

Żadnych pól STAMP. Cokolwiek podające się za nowszą wersję memo lub
niosące `:ppm=` / `:off=` / `:tsc=` / `:ent=` / `:stamp=` nie jest
emitowane przez tego daemona.

Pole `sysdrift` ujawnia kondycję lokalnego zegara każdego operatora:
duże odchylenia od konsensusu NTP (dodatnie lub ujemne) to wczesny
sygnał, że `systemd-timesyncd` lub chrony hosta walidatora jest źle
zdyscyplinowany — nawet wtedy gdy własny poll NTP daemona daje
akceptowalne wyniki.

---

## Kluczowe decyzje projektowe

- **Konsensus offset-based** — daemon odpytuje 45 źródeł NTP, stosuje
  filtr odstających 3× IQR na offsetach (nie na timestampach), uruchamia
  detekcję leap-second smear i wymaga zgodności cross-tier (co najmniej
  jedno źródło Stratum-1 / NTS w obrębie 50 ms od mediany). Confidence
  to ważona mieszanka jakości źródła (40 %), spreadu (40 %) i tieru
  (20 %).

- **Wyrównanie wall-clock window** — submisje są emitowane dokładnie na
  granicach 5-minutowych (np. `12:35:00.000`), z korektą TSC-stopwatch
  zaaplikowaną tak, by timestamp on-chain odzwierciedlał moment, gdy TX
  opuszcza daemona (a nie moment zakończenia konsensusu NTP, ~100–
  2000 ms wcześniej). Memo i on-chain zgadzają się z konstrukcji.

- **Wymuszanie anti-farm off-chain** — daemon odmawia rejestracji lub
  submisji, jeśli walidator ma mniej niż 64 epoki historii głosowania
  lub nie ma self-stake'a z pasującym withdraw authority (withdrawer-
  match gate). Kontrakt nie zawiera parserów; gates żyją w open-sourcowym
  kodzie daemona, który każdy może zaudytować.

- **Auto-cleanup nieaktywnych operatorów** — operatorzy, którzy nie
  wysyłają `submit_time` przez ~24 godziny, są usuwani z aktywnego
  zbioru przez `cleanup_inactive`, niezależnie od rozmiaru fleeta.
  Jeden dzień tolerancji pokrywa reboot'y, okna serwisowe i
  przejściowe outage'y sieci bez ręcznej interwencji. (Zachowanie
  v1.3+; v1.2.x używał matematyki per-turn missed-count, która dawała
  tylko ~22 min tolerancji przy n=2 i ~14 h przy n=100 — naprawione w
  changelogu v1.3.) Permissionless: każdy może wywołać instrukcję
  `cleanup_inactive` z batchem rejestracji w `remaining_accounts`, a
  rent odzyskany z każdego zamkniętego PDA wraca do payera cleanup-TX.
  Brak usuwania administracyjnego, brak głosowania governance.

- **Jedna rejestracja na klucz oracle** — rotacja = wygeneruj świeży
  `oracle.json`, zasil go i zarejestruj się ponownie. Stara
  rejestracja auto-cleanuje się po 24 h ciszy. v1.3+ auto-recoveruje
  przy starcie: jeśli daemon znajdzie swoje PDA brakujące lub
  nieaktywne, sam buduje i wysyła 2-podpisową transakcję
  `register_submitter` (gate'owaną przez balance oracle, dostępność
  vote keypair i ten sam anti-farm self-stake check co manualna
  podkomenda `register`). Brak on-chainowej instrukcji "rotate"; brak
  ceremonii portfela sprzętowego dla rutynowej rotacji klucza.

---

## Roadmap

- **v1.3** (ten release) — 24-godzinne wall-clock okno cleanup
  (`CLEANUP_GRACE_WINDOWS = 1440`, niezależne od rozmiaru fleeta),
  auto-recover przy starcie gdy rejestracja PDA jest brakująca lub
  oznaczona jako nieaktywna (gate'owane przez 0,6 XNT minimalnego
  balance + withdrawer-match self-stake), pole `sysdrift=` w memo czyta
  zcache'owany snapshot dryfu z momentu pollowania NTP (naprawia
  phantom offset ~30 s pod architekturą pre-poll), dwa nowe źródła
  Stratum-1 NTP (`hora.roa.es`, `time2.kriss.re.kr`), endpointy
  System76 przeniesione na Stratum 2 zgodnie z faktycznymi odpowiedziami.

- **v1.2.1** (poprzedni) — fix DNS-fallback w `RpcClient` (bypass
  cooldown'ów gdy każdy URL jest cold), defensywny guard na rendererze
  drift w `x1sr status`, `cleanup_inactive` zamyka PDA zamiast tylko
  flagować `is_active = false` (więc ten sam `oracle_keypair` może
  rejestrować się ponownie czysto).

- **v1.2.0** (początek linii v1.2) — kalkulacja runway uwzględnia
  rozmiar fleeta n, naprawa install (unit file zawsze zapisany), cichy
  fallback RPC, chain drift + sysdrift w outpucie status,
  pre-computation NTP polling (sub-200ms timing TX), withdrawer-match
  gate stake.

- **v1.4 (proponowane)** — prawdziwa autoryzacja NTS-KE na endpointach
  z obsługą NTS. Dziś daemon odpytuje te serwery zwykłym NTP; label
  tieru `nts` jest informacyjny do czasu wdrożenia handshake'u
  session-key. Prawdopodobnie również: re-probe USNO×2 + INRIM +
  named-region fallbacków z produkcyjnej sieci Sentinel, dodanie tych,
  które odpowiedzą.

- **v∞ — lock kontraktu.** Po dołączeniu wielu operatorów ponad Prime +
  Sentinel oraz wdrożeniu update'u walidatora Tachyon, upgrade
  authority zostanie usunięta i kontrakt stanie się niemodyfikowalny.
  Wszelka przyszła rozbudowa odbędzie się jako program Strontium v2
  obok v1, po dyskusji w grupie X1 builders.

**Kierunek badań (poza roadmapą) — retrospektywna atestacja konsensusu
czasowego.** On-chainowy ring buffer to kryptograficznie zakotwiczona
24 h historia median UTC, podpisana przez cały fleet operatorów.
Sprawdzamy czy można tego używać jako zewnętrznego dowodu timestamp'u
dla *przeszłych* zdarzeń (np. dApp udowadniający "zarejestrowałem ten
stan o UTC T, a oto korespondujący wpis oracle w oknie W"). To otwarte
badanie, nie zaplanowana praca.

---

## Skąd nazwa "Strontium"?

Stront-87 to atom, którego przejście 5s² → 5s5p stanowi podstawę
najdokładniejszych zegarów optycznych zbudowanych do tej pory — tych,
które definiują sekundę z precyzją kilku części na 10⁻¹⁸. Nazwa jest
aspiracyjna, nie roszczeniem do porównywalnej precyzji: zadaniem oracle
jest dostarczyć UTC z dokładnością milisekundową dla aplikacji on-chain
wymagających sub-sekundowego timingu. Ten sam duch, dramatycznie inna
skala.

---

## Licencja

MIT. Patrz [LICENSE](LICENSE).
