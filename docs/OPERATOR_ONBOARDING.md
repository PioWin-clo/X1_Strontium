# X1 Strontium v1.1 — Operator Onboarding

This document walks a validator operator through joining the X1
Strontium v1.1 oracle network. The model is intentionally simple: a
fresh server-local `oracle.json` keypair signs every `submit_time`
transaction, and your hardware wallet only ever signs **one** XNT
transfer that funds that keypair at register time.

Scope:

* Things you do **once**, by hand, with a hardware wallet plugged into
  your workstation (not the validator).
* Things the daemon does **continuously** with only the
  daemon-generated `oracle.json` keypair.

For a dApp developer wanting to *read* time from the oracle, see the
`read_time` CPI example in [`../README.md`](../README.md).

---

## 0. Preflight

Before starting, make sure you already have:

1. **An X1 validator running**, voting consistently. The daemon's
   off-chain anti-farm gate requires at least **64 epochs of voting
   history** (~2 months) on the vote account. Brand-new validators
   need to wait a few weeks before they can register.

2. **≥ 128 XNT of qualifying self-stake** delegated to your vote
   account, where the stake's withdraw authority equals the vote
   account's `authorized_withdrawer`. Stake must be active ≥ 2 epochs
   and not deactivating. Delegations from the X1 Labs foundation
   don't count — those have a different withdraw authority.

3. **Access to the hardware wallet** (Ledger, Trezor, or any other)
   that holds your validator's withdraw authority key. You'll only use
   it once, to sign the funding transfer in Section 3.

4. **A small XNT balance** on the wallet — about 0.5 XNT covers the
   one-time transfer plus the on-chain rent for the
   `ValidatorRegistration` PDA. Topping up further is harmless: the
   funds end up on the daemon-side `oracle.json`, paying for fees over
   the operator's lifetime.

Quick sanity:

```bash
# Replace with your values.
export RPC=https://rpc.mainnet.x1.xyz
export VOTE_ACCOUNT=<your_vote_account_pubkey>

# (a) Validator has been voting for ≥ 64 epochs. Look at
#     `epoch_credits` length in the vote account dump.
solana vote-account "$VOTE_ACCOUNT" --url "$RPC" | grep -A1 "Epoch"
#  → expect a long list spanning 64+ epochs

# (b) Withdraw authority — note this for the funding step in Section 3.
solana vote-account "$VOTE_ACCOUNT" --url "$RPC" | grep -i "withdraw"
#  → "Authorized Withdrawer: <pubkey of your hardware wallet key>"

# (c) Aggregate self-stake delegated to this vote with the right
#     withdraw authority filter is computed by `x1-strontium register`
#     when you run it — but you can sanity-check by listing delegations:
solana stakes --vote-account-pubkey "$VOTE_ACCOUNT" --url "$RPC"
```

If the validator is too young or self-stake is below 128 XNT,
`x1-strontium register` will refuse to send the transaction and tell
you which gate failed.

---

## 1. Install the daemon

Two paths — pick one.

### 1a. Download from GitHub Releases

Pre-built binaries for `x86_64-linux` and `aarch64-linux` are attached
to each tagged release.

```bash
# Replace v1.1.0 with the latest tag.
curl -L -o x1-strontium \
  https://github.com/PioWin-clo/X1_Strontium/releases/download/v1.1.0/x1-strontium-linux-x86_64
chmod +x x1-strontium
sudo ./x1-strontium install
```

`install` copies the binary to `/usr/local/bin/x1-strontium`, creates
the `x1sr` symlink, and writes a systemd unit at
`/etc/systemd/system/x1-strontium.service`. Don't `systemctl start`
yet — the daemon needs config and on-chain registration first.

### 1b. Compile from source

```bash
git clone https://github.com/PioWin-clo/X1_Strontium.git
cd X1_Strontium
cargo build --release -p x1-strontium-daemon
sudo ./target/release/x1-strontium install
```

---

## 2. Configure the daemon

The daemon reads `~/.config/x1-strontium/config.json`. Set the two
required keys plus any optional knobs you want.

```bash
# 2a. Path to the validator's vote-account keypair (typically
#     ~/.config/solana/vote.json). Used by `register` to co-sign the
#     register_submitter TX and to derive the vote pubkey for
#     off-chain anti-farm gates.
x1-strontium config set vote_keypair ~/.config/solana/vote.json

# 2b. Path where the daemon should keep oracle.json. The file does NOT
#     have to exist yet — `register` will generate one with strong
#     entropy from /dev/urandom and chmod 600 it for you.
x1-strontium config set oracle_keypair /etc/x1-strontium/oracle.json

# 2c. Optional — webhook for low-balance / silent-cycle alerts.
x1-strontium config set alert_webhook https://hooks.slack.com/...

# 2d. Optional — extra RPC endpoints (comma-separated). The daemon
#     already ships with the two primary X1 mainnet RPCs.
x1-strontium config set rpc https://rpc.mainnet.x1.xyz,https://api.mainnet.x1.xyz

# Sanity check.
x1-strontium config show
```

Defaults you almost certainly want to leave alone: `interval_s = 300`,
`memo_enabled = true`, `tier_consensus_threshold_ms = 50`,
`alert_balance_threshold = 1.0` XNT.

---

## 3. Fund the oracle keypair

The first run of `x1-strontium register` (next section) generates
`oracle.json`. To fund it, you need its public key. The simplest path
is to run `register` first — it will refuse to send the registration
transaction because `oracle.json` has zero balance, but in doing so
it'll print the pubkey you need to fund.

Alternatively, generate the keypair manually and read the pubkey:

```bash
# Manually generate (skip if you'll let `register` do it):
sudo mkdir -p /etc/x1-strontium
sudo solana-keygen new --no-bip39-passphrase \
  -o /etc/x1-strontium/oracle.json
sudo chmod 600 /etc/x1-strontium/oracle.json
sudo chown x1pio:x1pio /etc/x1-strontium/oracle.json   # adjust user

# Read the pubkey.
solana-keygen pubkey /etc/x1-strontium/oracle.json
#  → e.g. 7xhP...ABcd
```

Now do the **single** funding transfer from your hardware wallet:

```bash
# On your WORKSTATION with the hardware wallet plugged in.
# Replace usb://ledger?key=0/0 with whatever derivation path your
# wallet uses.
solana transfer 0.5 <oracle_pubkey> \
  --keypair usb://ledger?key=0/0 \
  --url https://rpc.mainnet.x1.xyz \
  --allow-unfunded-recipient
```

0.5 XNT is enough for the registration rent (~0.001 XNT) plus
~250 days of `submit_time` fees at the default 5-minute cadence. Send
more if you want a longer runway between top-ups; you can always come
back and add XNT later, the daemon picks up the new balance on its
next cycle.

This transfer is the **only** moment in the operator's lifecycle that
the hardware wallet is involved. Daemon-side rotation, daily fee
spend, and emergency stops (Section 7) all use other paths.

---

## 4. Register on chain

Run `register` on the validator host — not on your workstation. This
command runs the off-chain anti-farm gates and, on success, sends the
2-signer `register_submitter` transaction.

```bash
x1-strontium register
```

What happens:

1. Generates `oracle.json` if missing (chmod 600, secret 32 bytes from
   `/dev/urandom`).
2. Loads `vote.json` from the path you configured.
3. Fetches the vote account on chain, parses the voting-history length.
   Refuses if **< 64 epochs**.
4. Computes qualifying self-stake (filter: voter = your vote account,
   withdrawer = `authorized_withdrawer`, age ≥ 2 epochs, not
   deactivating). Refuses if **< 128 XNT**.
5. Derives the registration PDA (seeds `[b"reg", oracle_keypair_pubkey]`).
6. Builds, signs (oracle.json + vote.json), and sends the
   `register_submitter` transaction.

A successful run looks like:

```
[register] Oracle keypair:    7xhP...ABcd
[register] Vote keypair:      Edgr...0Pq9
[register] Registration PDA:  9s4B...XXXX
[register] Oracle PDA:        cfm1Tc7CNdTa8Hm8FGWAuHXaaozSjQHNmdBD5mEVN9P

[register] Off-chain anti-farm gates:
       ✓ epoch_credits = 87 (≥ 64)
       authorized_withdrawer: <your withdrawer pubkey>
       ✓ qualifying self-stake = 256 XNT (≥ 128 XNT)

[register] Sending register_submitter ...
[register] ✅ Success — Signature: <tx-sig>
[register] You can now start the daemon: `systemctl start x1-strontium`.
```

---

## 5. Start the daemon and verify

```bash
sudo systemctl start x1-strontium
sudo systemctl enable x1-strontium     # auto-start at boot

# Watch the journal for the first cycle (5-minute window alignment +
# the first NTP poll round + the first submit_time TX if it's your
# turn this window).
journalctl -u x1-strontium -f
```

The daemon prints a startup banner with your registration PDA and
oracle pubkey, then aligns to the next wall-clock 5-minute boundary.
Within a single rotation cycle (depending on fleet size you may have
to wait one or two windows for your first turn) you'll see something
like:

```
[cycle] 12 sources responded — best RTT 18 ms
[consensus] ts=1740491100.003s spread=4ms confidence=0.97 sources=12 bitmap=0x...
✅ submit OK — tx: <signature>
```

Status snapshots and read-back:

```bash
# Daemon-side view: last submit, balance, rotation index, silent
# reasons (if any), recent NTP source health.
x1-strontium status

# Recent on-chain ring buffer entries — confirms the chain saw your
# submission and aggregated it with the rest of the fleet.
x1-strontium read --last 5
```

A healthy operator shows `silent_cycles: 0` and a recent `last_submit_tx`.

---

## 6. Operator hygiene

### 6a. Rotating `oracle.json`

If you suspect the daemon-side keypair is compromised (e.g. server
breach), rotate by registering a fresh one:

```bash
# 1. Stop the daemon so it doesn't keep submitting with the old key.
sudo systemctl stop x1-strontium

# 2. Move the old keypair aside (do NOT delete — you might want the
#    audit trail).
sudo mv /etc/x1-strontium/oracle.json \
       /etc/x1-strontium/oracle.json.compromised-YYYYMMDD

# 3. Re-run register. It will generate a fresh oracle.json, run the
#    same anti-farm gates, and create a NEW ValidatorRegistration PDA
#    (different seeds, different address). Make sure the new pubkey is
#    funded BEFORE you run register — same hardware-wallet transfer
#    pattern as Section 3.
solana transfer 0.5 <new_oracle_pubkey> \
  --keypair usb://ledger?key=0/0 --url https://rpc.mainnet.x1.xyz \
  --allow-unfunded-recipient
x1-strontium register

# 4. Restart the daemon — it'll pick up the new keypair via
#    config.oracle_keypair_path (the path is unchanged; only the file
#    contents are new).
sudo systemctl start x1-strontium
```

The old `ValidatorRegistration` PDA is now stranded — within 10 of
its own rotation turns (depends on fleet size; ~50 min at n=1, ~100 min
at n=2, ~14 h at n=100) the contract's `cleanup_inactive` instruction
will mark `is_active = false`, and the on-chain state is consistent
again. No manual deactivation TX needed.

### 6b. Topping up the oracle

The daemon prints a low-balance warning at < 1 XNT and silences itself
at < 0.05 XNT. Top up from the same hardware wallet whenever the
runway falls below your comfort threshold:

```bash
solana transfer 1.0 <oracle_pubkey> \
  --keypair usb://ledger?key=0/0 \
  --url https://rpc.mainnet.x1.xyz
```

No registration changes needed — the daemon picks up the new balance
on its next cycle.

### 6c. Updating the daemon

```bash
cd ~/X1_Strontium
git pull
sudo /usr/local/bin/x1-strontium update
```

`update` pulls the repo, rebuilds the daemon as the original (non-root)
user, atomically swaps the binary at `/usr/local/bin/x1-strontium`, and
restarts the systemd service. If the new build fails to compile, the
old binary stays in place and the service keeps running on the previous
version.

---

## 7. Panic stop

If you need to take an operator offline urgently — server compromised,
validator going down for extended maintenance, jurisdiction change,
etc. — the cleanest path is to deactivate the underlying stake from
your hardware wallet. The off-chain self-stake check then drops below
128 XNT at the next 24 h refresh, the daemon silences itself, and the
contract's missed-turns cleanup deregisters within 10 of the
operator's own rotation turns.

```bash
# On your WORKSTATION with the hardware wallet plugged in.
solana deactivate-stake <stake_account_pubkey> \
  --stake-authority usb://ledger?key=0/0 \
  --url https://rpc.mainnet.x1.xyz
```

The stake enters "deactivating" state. The daemon's filter excludes
deactivating stakes from the qualifying-stake total, so on the next
24 h refresh the daemon flips to silent mode and stops emitting
`submit_time` TXs. From there:

* If you want to come back later: re-activate the stake, re-fund
  oracle.json if needed, run `x1-strontium register` again to get a
  fresh on-chain registration. The previous one will have been
  cleaned up by then.
* If this is permanent: nothing more to do. The auto-cleanup is
  decentralized — no admin removal, no governance vote.

For an instant on-server stop (without touching stake), just
`systemctl stop x1-strontium`. The daemon goes silent immediately;
within 10 own rotation turns the contract auto-cleans your
registration. This is faster but leaves the stake in place — usually
appropriate for "I'm rebooting the validator for a few hours" rather
than "I'm exiting the operator set".

---

## 8. Troubleshooting

### "registration PDA not found on chain — Run `x1-strontium register` first"

Daemon refused to start because the `ValidatorRegistration` PDA
doesn't exist on chain. Either you haven't run `register` yet, or the
contract's `cleanup_inactive` removed the registration after 10
missed turns. Re-run `register` — same flow as Section 4.

### "registration ... is_active = false (cleaned up after missed turns)"

The contract marked your registration inactive after a long silent
period (10 of your own rotation turns missed in a row). Same
remediation: re-run `register` to create a new registration. The old
PDA stays around but is harmless — it's just rent locked at the old
seeds.

### "epoch_credits has N entries, need ≥ 64"

Your validator hasn't been voting long enough to clear the off-chain
anti-farm gate. Wait for the validator to accumulate more epochs —
about 64 epochs ≈ 2 months on X1.

### "qualifying self-stake = X XNT, need ≥ 128 XNT"

Either the total stake delegated to your vote account is below 128
XNT, or the stake doesn't pass the filters (wrong withdraw authority,
recently activated, deactivating). Check with:

```bash
solana stakes --vote-account-pubkey "$VOTE_ACCOUNT" --url "$RPC"
```

Common cause: stake was just delegated and is still in the warm-up
period (< 2 epochs old).

### Daemon silent for many cycles, status shows `silent_reason: insufficient_self_stake`

The 24 h off-chain refresh detected qualifying self-stake below the
128 XNT floor. Daemon stays silent until either (a) stake recovers,
or (b) the contract's missed-turns cleanup deregisters the operator.
Re-fund or restake to recover.

### "balance dropped to X XNT — silent_reason: insufficient_balance"

The oracle keypair is running out of fees. Top up from your hardware
wallet (Section 6b) — once the balance crosses the warn threshold
back upward, the daemon resumes submitting.

### Daemon crashed (last_crash.log)

The panic hook installed by `main()` writes a crash log to
`~/.config/x1-strontium/last_crash.log` (or root's home if running as
root via systemd). Inspect with `cat`. systemd's `Restart=on-failure`
brings the daemon back automatically; the crash log is the post-mortem.

---

For protocol-level questions and the design rationale behind v1.1, see
[`../README.md`](../README.md).
