# 👻 GhostKey — spooky secrets for Tari addresses

A **zero-dependency, pure-Python** implementation of the full Tari address
format — generated entirely offline, no keys ever leave your machine.

Built for the [Tari October Build Contest 2026 — "Spooky
Secrets"](https://community.tari.com/t/october-build-contest-thread-spooky-secrets/396).

## What it does

- **Generate** Tari addresses locally (dual & single, all networks:
  mainnet `0x00`, esmeralda `0x26`, iggor, dangeralert), from fresh
  cryptographically-random ed25519 keypairs.
- **Inspect** any address: decode network, feature flags (interactive /
  one-sided / payment-id), spend & view keys, and verify the DammSum
  checksum.
- **Convert** between the three official encodings: base58, hex, emoji 😜.
- **Vanity mine** addresses whose emoji encoding contains your favourite
  spooky ghosts (👻🎃🦇…) — a little Halloween fun with real ristretto255
  math behind it.
- **Payment IDs** — attach a stealth memo to dual addresses, exactly like
  Tari's confidential transactions do.

Everything is implemented from the specs, in one file, with only the Python
standard library:

| Piece | Spec |
|---|---|
| ristretto255 group (decode/encode/map/derive, scalar mult) | RFC 9496 |
| DammSum checksum | tari-project DammSum |
| Address layout (single/dual, features byte, base58/hex/emoji) | tari-project/tari `utilities/tari_address` |

## Why it's spooky

Tari is the programmable privacy chain. Your wallet *is* a secret — a
ristretto255 point that nobody but you can spend from. GhostKey lets you
forge, dissect and haunt those secrets entirely offline: no server, no
dependencies, no telemetry. Just math and ghosts. 👻

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

# confidential payment-id
python ghostkey.py generate --payment-id "trick-or-treat"

# inspect any address (base58 / emoji / hex all accepted)
python ghostkey.py inspect 14DY79813nUENFkDJHWXWsJ8...

# convert encodings
python ghostkey.py convert ADDRESS --to emoji

# vanity-mine an address whose emoji starts with ghosts
python ghostkey.py vanity --emoji "👻🎃" --tries 500000

# full self-test: every RFC 9496 vector + Tari golden vectors
python ghostkey.py selftest
```

## Verification

`python ghostkey.py selftest` runs:

- all RFC 9496 test vectors (SQRT_RATIO_M1, generator multiples B[0..15],
  invalid encodings, element derivation, same-output derivation);
- Tari golden vectors taken from the `tari-project/tari` Rust test suite
  (dual mainnet address, payment-id addresses, emoji vectors, DammSum);
- keygen round-trips and feature-flag validation.

## Security notes

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
