# 👻 GhostKey — spooky secrets for Tari addresses

[![CI](https://github.com/Alex20Sas12/ghostkey/actions/workflows/ci.yml/badge.svg)](https://github.com/Alex20Sas12/ghostkey/actions/workflows/ci.yml)

A **zero-dependency, pure-Python** implementation of the full Tari address
format — a demonstration of Tari's privacy model taken to its logical end:
**keys are private from birth**. Every keypair is generated offline, on your
machine, with no server, no dependency, no telemetry, no network access at
all. Nothing to leak, because nothing ever leaves.

Built for the [Tari October Build Contest 2026 — "Spooky
Secrets"](https://community.tari.com/t/october-build-contest-thread-spooky-secrets/396)
(theme: *best demonstration of Tari's privacy capabilities*).

## Why this demonstrates Tari privacy

Tari is the programmable privacy chain — your wallet *is* a secret: a
ristretto255 point nobody but you can spend from. GhostKey makes that
property tangible:

- **Privacy from birth** — keygen is 100% offline (OS CSPRNG → ristretto255
  scalar reduction → address). No key ever touches a server or the network
  before you choose to use it.
- **Stealth memos** — payment-IDs are embedded into dual addresses exactly
  the way Tari's confidential transactions carry encrypted memos: the payer
  proves *why* they paid without revealing it on-chain.
- **Emoji encoding** — Tari's most playful unique feature, fully implemented
  (encode/decode/validate), letting you *see* an address as 66 emoji.
- **Dissect anything** — `inspect` decodes network, feature flags, spend and
  view keys from any address, and verifies the DammSum checksum, so you can
  audit addresses before trusting them.

Everything is implemented from the specs, in one file, stdlib only:

| Piece | Spec |
|---|---|
| ristretto255 group (decode/encode/map/derive, scalar mult) | RFC 9496 |
| DammSum checksum | tari-project DammSum |
| Address layout (single/dual, features byte, base58/hex/emoji) | tari-project/tari `utilities/tari_address` |

## Install

Nothing to install. Python 3.8+, zero dependencies.

```
git clone https://github.com/Alex20Sas12/ghostkey
cd ghostkey
python ghostkey.py --help
```

## Usage

```bash
# generate a fresh mainnet dual address (secrets printed once)
python ghostkey.py generate --network mainnet

# keep the keys in a mode-600 keyfile
python ghostkey.py generate --network mainnet --save wallet.json

# single address, esmeralda testnet
python ghostkey.py generate --single --network esmeralda

# confidential payment-id (stealth memo)
python ghostkey.py generate --payment-id "trick-or-treat"

# inspect any address (base58 / emoji / hex all accepted)
python ghostkey.py inspect ADDRESS

# convert encodings
python ghostkey.py convert ADDRESS --to emoji

# vanity-mine an address whose emoji encoding contains ghosts
python ghostkey.py vanity --emoji "👻🎃" --network mainnet

# full self-test: every RFC 9496 vector + Tari golden vectors
python ghostkey.py selftest
```

## 🎃 Spooky artifact: mined 👻🎃 address

The contest theme, materialised. Mined with GhostKey's own `vanity` command
(`python ghostkey.py vanity --emoji "👻🎃" --network mainnet`): a mainnet
dual address whose emoji encoding contains the adjacent pair 👻🎃 — ghost
*and* pumpkin, side by side, in one address:

```
$ python ghostkey.py inspect 14ChBztPxdA9ahJSCRgCLxu7J7NcrAjpsGCtNKTBkUKhp9VLPfvrDd7sseZSeYmiHVwXfsxPhgEeNPzwQybefaLJ9RR
network   : mainnet
type      : dual
features  : interactive, one-sided (byte 0x03)
checksum  : valid (DammSum)
ghost score: 2 spooky emoji 👻

emoji  : 🐢🌊🐮🐪🌈🎹🐭🎭🌽🍌🎂⭐🌰🚀👟🤔🤢🐔📈👘🐜🍔😂👻🎃👾💣🎻🎈🎺🏠🐛🚦🐙🎠🎿🚒💅🍆🍕🚜🍵🐷🐐🎉🐵👾🍟🚂🦋🍳🎠🏥🌲👶➕🐺🌻🎂🐬🐚🌹🎋🍗📿🐊🍐
```

The secrets behind it were discarded — like all good ghosts, it only haunts,
it never holds funds.

## Inspect the author's Tari payment address

The same tool audits the address this project uses for contest payments —
public key material only, as designed:

```
$ python ghostkey.py inspect 14DY79813nUENFkDJHWXWsJ8cMiTwBSow15mJqWjnXJC4PU9gTXbqp3MHQsffBpNPKrSz5Jj3LZ5qhdknDme6BtCQhY
network   : mainnet
type      : dual
features  : interactive, one-sided (byte 0x03)
checksum  : valid (DammSum)
spend key : d499e156b4c82b42a9e27a97c833e064e0c92b1160cc124d61c8063d1dc9781d
view key  : 8e0fa719dc266f4ad3a52aa6f0a79171470ae66266be114b50f35538a14d4f03
ghost score: 3 spooky emoji 👻

base58 : 14DY79813nUENFkDJHWXWsJ8cMiTwBSow15mJqWjnXJC4PU9gTXbqp3MHQsffBpNPKrSz5Jj3LZ5qhdknDme6BtCQhY
hex    : 00038e0fa719dc266f4ad3a52aa6f0a79171470ae66266be114b50f35538a14d4f03d499e156b4c82b42a9e27a97c833e064e0c92b1160cc124d61c8063d1dc9781d53
emoji  : 🐢🌊🐺🌸👻🍈🔬🍗🐍🎤🔑👣🥝🤡🚑👻🐽🐐🎡🎋😎🏁🏠➕🌻🎥🎬🛵🎲🍷👟🎨🎪🌊🔔👕😂🎳💐📌🍣🎈👾😇🐜🧢📌🥐🗽🏈🗽📎🍣🌻🎿📡🌽🎨🏀📌🌙🎀🍌📎🐚🍌🎰
```

**Tari payment address:**
`14DY79813nUENFkDJHWXWsJ8cMiTwBSow15mJqWjnXJC4PU9gTXbqp3MHQsffBpNPKrSz5Jj3LZ5qhdknDme6BtCQhY`

## Verification

```
python ghostkey.py selftest
```

**107 checks passed, 0 failed** — reproducible on any machine with Python
3.8+, and on every push by GitHub Actions on Python 3.8 / 3.11 / 3.13 (see
CI badge above):

- all RFC 9496 test vectors (SQRT_RATIO_M1, generator multiples B[0..15],
  invalid encodings, element derivation, same-output derivation);
- Tari golden vectors taken byte-for-byte from the `tari-project/tari` Rust
  test suite (dual mainnet address, payment-id addresses, emoji vectors,
  DammSum);
- keygen round-trips and feature-flag validation.

Byte-for-byte agreement with the official Rust vectors means any Python
project (bots, analytics, tests) can now validate and generate Tari
addresses with zero trust in this codebase — and zero Rust toolchain.

## Security notes (honest boundaries)

- `secrets.token_bytes` (OS CSPRNG) for key material; secret keys are
  reduced mod the ristretto255 group order per RFC 9496 §4.4.
- Keyfiles are written with mode 600.
- `generate` without `--save` prints the warning that secrets are shown
  once and not stored.
- Pure-Python scalar math is **not** constant-time against side-channel
  observation of *your own process*; it is perfectly fine for offline
  keygen on a trusted machine. Documented honestly in the code.

## License

MIT — see [LICENSE](LICENSE).
