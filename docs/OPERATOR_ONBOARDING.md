# X1 Strontium v1.0 — Operator Onboarding

This document walks a validator operator through on-boarding onto the
X1 Strontium v1.0 oracle network. Every step is designed so that the
high-privilege key (Ledger, = vote account's `authorized_withdrawer`)
stays cold for admin ops, and a fresh low-privilege hot key signs the
every-5-minute `submit_time` TXs on the server.

Scope:

* Things you do **once**, by hand, with a Ledger plugged into your
  workstation (not the validator).
* Things the daemon does **continuously**, with only the hot signer.

For a dApp developer wanting to *read* time from the oracle, see the
`read_time` CPI example in [`README.md`](../README.md).

---

## 0. Preflight

Before starting, make sure you already have:

1. **An X1 validator running** — has voted in recent epochs, has a
   reasonable skip rate (roughly ≥ 58 % of max credits per epoch
   sustained for months). See `docs.x1.xyz/validating/create-a-validator-node`.

2. **Vote account's `authorized_withdrawer` on a Ledger** — the single
   most important precondition. Follow
   `docs.x1.xyz/validating/secure-validator-with-hw-wallet` if you haven't
   done this yet. X1 Strontium's entire trust chain for operator control
   hangs on this equivalence.

3. **≥ 128 XNT of self-stake** delegated to your vote account, with
   `withdrawer = <ledger_pubkey>`, active ≥ 2 epochs, not currently
   deactivating. Delegations from the X1 Labs foundation don't count —
   those have a different withdrawer.

4. **~5–10 XNT on the Ledger wallet itself** for the occasional admin TX
   (Anchor init PDA rent is ~0.08 XNT; covers many rotations + deactivations).

Quick sanity:

```bash
# Replace with your values.
export RPC=https://rpc.mainnet.x1.xyz
export VOTE_ACCOUNT=<your_vote_account_pubkey>
export LEDGER_PATH="usb://ledger?key=0/0"     # typical; adjust if needed
export LEDGER_PUBKEY=$(solana-keygen pubkey "$LEDGER_PATH")

# (a) Ledger must match vote's withdrawer.
solana vote-account "$VOTE_ACCOUNT" --url "$RPC" | grep -i "withdraw"
#  → "Authorized Withdrawer: <should equal $LEDGER_PUBKEY>"

# (b) Ledger has enough XNT for admin ops (>= 5 XNT is comfortable).
solana balance "$LEDGER_PUBKEY" --url "$RPC"
```

If any of the above doesn't match, stop. The on-chain
`initialize_operator` gate will reject you and your XNT is wasted on
failed TXs.

---

## 1. Gather the identifiers X1 Strontium needs

You'll need these four values later in every step:

| Variable           | How to get it                                                            |
|--------------------|--------------------------------------------------------------------------|
| `$VOTE_ACCOUNT`    | Your validator's vote account pubkey — already in `solana-validator` args |
| `$LEDGER_PUBKEY`   | `solana-keygen pubkey "$LEDGER_PATH"` (hardware wallet)                  |
| `$PROGRAM_ID`      | `2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch` (v1.0 mainnet)             |
| `$ORACLE_PDA`      | `EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy` (v1.0 mainnet singleton)   |

Retired (closed on chain) v0.5 Program ID — do **not** use:
`2FgHeEQfY1C774uyo8RDKHcjTRz2mVPJ6wotrD9P3YgJ`.

Derive your per-operator PDA (optional sanity check — the daemon does
this automatically at runtime):

```bash
# There is no standalone `solana find-program-address` CLI — but you can
# read the derived PDA back from `x1-strontium start` startup banner
# once the daemon is configured. It prints:
#   operator pda:    <base58>
```

---

## 2. Generate the hot signer

The hot signer is a fresh, low-privilege keypair that lives on the
validator itself. It signs `submit_time` every cycle. If it's ever
compromised, you rotate it from the Ledger side (Section 5); stake is
not at risk.

```bash
# On the VALIDATOR (not on your workstation / Ledger host).
mkdir -p ~/.config/x1-strontium
solana-keygen new \
  --no-bip39-passphrase \
  -o ~/.config/x1-strontium/hot-signer.json
export HOT_SIGNER=$(solana-keygen pubkey ~/.config/x1-strontium/hot-signer.json)
echo "$HOT_SIGNER"

# Fund with ~5 XNT from the Ledger wallet. Submission cost is ~0.004 XNT
# per TX at 300 s cadence → 5 XNT ≈ 1 year runway solo, 2 years with
# Prime+Sentinel rotation.
solana transfer "$HOT_SIGNER" 5 --keypair "$LEDGER_PATH" --url "$RPC"
```

The hot-signer file should be readable only by the systemd service user:

```bash
chmod 600 ~/.config/x1-strontium/hot-signer.json
```

---

## 3. Run `initialize_operator` from the Ledger

This is the one TX that creates your `OperatorPDA` on chain. It's signed
by the Ledger and runs all four contract gates (vote ownership,
64-epoch credits window, ≥ 128 XNT self-stake, max operator cap). For
v1.0 there is **no CLI helper** — you assemble it by hand with
`solana program invoke` or with a short Python script using
`solana-py` + `anchorpy`. A first-class `x1sr-admin` CLI is on the
v1.3 roadmap.

### 3a. Find your qualifying self-stake accounts

The contract needs them in `remaining_accounts` so the on-chain stake
parser can sum them. Filter: owner = stake program, variant = Stake,
`withdrawer == $LEDGER_PUBKEY`, `voter_pubkey == $VOTE_ACCOUNT`,
`deactivation_epoch == u64::MAX`, activation_epoch ≤ current_epoch - 2.

```bash
solana stakes "$LEDGER_PUBKEY" --url "$RPC" --verbose \
  | awk '/^Stake Pubkey:/ { pk=$3 } /Delegated Vote Account:/ && $5=="'"$VOTE_ACCOUNT"'" { print pk }'
```

This prints the stake account pubkeys. You'll add them as additional
accounts on the `initialize_operator` TX.

### 3b. Build and sign the TX

Minimal sketch (Python with anchorpy; adjust for your toolchain):

```python
from solders.pubkey import Pubkey
from anchorpy import Program, Provider

program_id   = Pubkey.from_string("2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch")
vote_account = Pubkey.from_string("<your vote account>")
authority    = Pubkey.from_string("<your ledger pubkey>")
hot_signer   = Pubkey.from_string("<hot signer pubkey from step 2>")
stakes       = [Pubkey.from_string(s) for s in QUALIFYING_STAKE_ACCOUNTS]

operator_pda, _bump = Pubkey.find_program_address(
    [b"operator", bytes(vote_account)], program_id,
)

ix = program.instruction["initialize_operator"](
    hot_signer,
    ctx=Context(
        accounts={
            "operator_pda":  operator_pda,
            "oracle_state":  Pubkey.from_string("EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy"),
            "vote_account":  vote_account,
            "authority":     authority,
            "system_program": SystemProgram.ID,
        },
        remaining_accounts=[AccountMeta(pk, is_signer=False, is_writable=False) for pk in stakes],
    ),
)
# ... sign with Ledger via `solana sign-offchain-message` or solana-py's
# LedgerKeypair wrapper, then submit as a single-signer TX.
```

### 3c. Verify on chain

```bash
OPERATOR_PDA=<from find_program_address in 3b>
solana account "$OPERATOR_PDA" --url "$RPC" --output json
```

You should see 168 bytes of data (8-byte Anchor discriminator + 160-byte
`OperatorPDA`). The daemon's `x1-strontium status` will also show it on
the first cycle once you start it.

---

## 4. Configure and start the daemon

On the validator:

```bash
# Install the binary + systemd unit + x1sr symlink.
sudo x1-strontium install

# Configure the daemon.
x1-strontium config set hot_signer_keypair ~/.config/x1-strontium/hot-signer.json
x1-strontium config set vote_account        "$VOTE_ACCOUNT"
x1-strontium config set program_id          2thzsm9z31MPEvDWHuuSGqAcjrr5ek4pS78EgPAT4Fch
x1-strontium config set oracle_pda          EQ9CgHkx34AL7gaBHSX9nEWbwBtEfktbVGyQWEsTEtEy
x1-strontium config set interval            300
x1-strontium config set memo                on
# Optional — alert webhook (Telegram/Discord/Slack-compatible).
x1-strontium config set alert_webhook       https://hooks.slack.com/services/...
# Optional — advisory reminder of which Ledger slot owns this operator.
x1-strontium config set ledger_derivation_path "m/44'/501'/0'/0'"
```

First dry run (no TX):

```bash
x1-strontium start --dry-run
```

You should see 3+ healthy NTP sources, a consensus time within ~50 ms
spread, confidence ≥ 60 %. If any of that is off, read § 7
**Troubleshooting** before going live.

Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now x1-strontium
sudo journalctl -u x1-strontium -f
```

Within one cycle (≤ 5 min) you should see `✅ submit OK — tx: <sig>`.

---

## 5. Rare admin ops (all Ledger-signed, out-of-band)

All four instructions below are built and signed **exactly like
`initialize_operator` in § 3b** — the only differences are which
instruction, which accounts, and which signer context. The daemon does
not invoke any of them.

### Rotate the hot signer (compromise recovery)

Instruction: `rotate_hot_signer(new_hot_signer: Pubkey)`.
Accounts: `operator_pda`, `vote_account` (seed source only), `authority`
(signer).

```bash
# 1. Generate the new hot signer on the validator.
solana-keygen new --no-bip39-passphrase \
  -o ~/.config/x1-strontium/hot-signer.new.json
solana-keygen pubkey ~/.config/x1-strontium/hot-signer.new.json
# 2. Build + sign `rotate_hot_signer(<new_pubkey>)` from the Ledger.
# 3. Swap the file:
mv ~/.config/x1-strontium/hot-signer.new.json \
   ~/.config/x1-strontium/hot-signer.json
# 4. Restart the daemon to pick up the new key.
sudo systemctl restart x1-strontium
```

### Deactivate the operator (temporarily silence)

Instruction: `deactivate_operator()`.
Accounts: `operator_pda`, `oracle_state`, `vote_account`, `authority`
(signer).

Use this when taking the validator offline for more than ~1 day — it
decrements `n_operators` and relaxes the quorum for the remaining fleet.
The PDA is preserved; you can re-activate by running `initialize_operator`
again (same pubkey, same TX shape; it will pass the gates and re-create
`active = true`).

### Close the operator (permanent)

Instruction: `close_operator()`.
Accounts: `operator_pda`, `oracle_state`, `vote_account`, `authority`
(signer, receives PDA rent back).

Permanently removes your `OperatorPDA`. The rent (~0.002 XNT) is
refunded to `authority`. You cannot reopen without running
`initialize_operator` again from scratch.

### `set_operators_count` (emergency override, X1 Strontium admin only)

This is the one admin op **not** signed by your Ledger — it's signed by
the global `oracle_state.authority` key held by the X1 Strontium admin
(the key that ran `x1-strontium init` at deploy time). It's only used if
the on-chain `n_operators` counter drifts from reality and the dynamic
quorum needs manual correction. Ignore unless the admin contacts you.

---

## 6. Monitoring

Three complementary signals:

| Signal                 | Where to look                                              |
|------------------------|------------------------------------------------------------|
| Daemon status          | `x1-strontium status` — last TX, consensus, spread, balance |
| NTP source health      | `x1-strontium sources` — RTT / offset / stratum per server |
| Ring buffer history    | `x1-strontium read --last 30` — last 30 aggregated entries |
| On-chain balance       | `x1-strontium balance` — XNT balance + runway estimate     |
| Webhook alerts         | `alert_webhook` fires after 3 silent cycles, then every 10 |

Typical healthy output:

```
Daemon          : ● running  (PID 12345)
Oracle          : 5NoKHzd3...ChVL
Mode            : live  |  interval: 300s

── Balance & Runway ──────────────────────────
Balance         : 4.783 XNT
Runway          : ~970 days

── Last Submission ────────────────────────────
Time            : 2026-04-24 08:45:00 UTC  (42s ago)
TX              : 3aBc...xyz
Result          : ✓ success

── NTP Consensus ──────────────────────────────
Consensus time  : 08:45:00.003 UTC
Spread          : 3 ms   (limit: 50ms)
Confidence      : 97%    (min: 60%)
Sources active  : 10 / 40+
```

---

## 7. Troubleshooting

| Symptom                                         | Likely cause & fix                                                                          |
|-------------------------------------------------|----------------------------------------------------------------------------------------------|
| `initialize_operator` TX rejects                | One of the four gates failed. Re-check § 0 preflight. The failing gate is in the TX error.   |
| Hot signer balance drops fast                   | Check `x1-strontium balance` — runway <30 days means fund the hot wallet.                    |
| `silent for 3 cycles (not_elected)`             | Normal in a rotating fleet — you only submit on your window. Not an error.                   |
| `silent (spread_too_high)`                      | NTP network unstable. Check `x1-strontium sources`; worst sources often resolve within 1 h.  |
| `silent (insufficient_sources)`                 | Firewall blocking UDP/123 outbound? Test with `sudo ntpdate -q pool.ntp.org`.                |
| `self-stake N XNT < 128 XNT — next recheck will FAIL` | Add stake (withdrawer = Ledger) OR rotate some foundation stake to your Ledger authority. |
| Daemon won't start, `config.hot_signer_keypair_path is not set` | Re-run `x1-strontium config set hot_signer_keypair ...`.                            |
| `cargo build` fails with zeroize feature conflict | You're building `programs/x1-strontium` inside the daemon workspace. Use `Anchor.toml` / run `cargo build-sbf -p x1-strontium` from the contract directory. |

---

## Appendix — reading the on-chain `OperatorPDA`

Useful for manual sanity checks (the daemon reads this every cycle to
gate the 24 h self-stake recheck):

| Field                   | Offset (account-relative) | Size | Type    |
|-------------------------|---------------------------|------|---------|
| Anchor discriminator    | 0                         | 8    | [u8; 8] |
| `authority`             | 8                         | 32   | Pubkey  |
| `hot_signer`            | 40                        | 32   | Pubkey  |
| `vote_account`          | 72                        | 32   | Pubkey  |
| `validator_identity`    | 104                       | 32   | Pubkey  |
| `registered_at`         | 136                       | 8    | i64     |
| `last_stake_check_slot` | 144                       | 8    | u64     |
| `self_stake_amount`     | 152                       | 8    | u64     |
| `active`                | 160                       | 1    | bool    |
| `bump`                  | 161                       | 1    | u8      |
| `_pad`                  | 162                       | 6    | [u8; 6] |

Total: 168 bytes.
