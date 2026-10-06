#!/usr/bin/env python3
"""
GhostKey 👻 — spooky secrets for Tari addresses.

A zero-dependency, pure-Python implementation of the Tari address format
(TariAddress: single & dual, base58 / hex / emoji encodings) including a
full ristretto255 group implementation (RFC 9496) and the DammSum checksum
used by Tari.

Everything runs locally. No network calls, no dependencies beyond the
Python 3.8+ standard library. Secret keys never leave your machine.

Built for the Tari October Build Contest 2026 — "Spooky Secrets".

CLI:
    python ghostkey.py generate [--network mainnet|esmeralda|...] [--single]
                                [--features interactive,onesided]
                                [--payment-id TEXT] [--save FILE]
    python ghostkey.py inspect ADDRESS
    python ghostkey.py convert ADDRESS --to emoji|base58|hex
    python ghostkey.py vanity --emoji "👻🎃" [--network esmeralda] [--tries N]
    python ghostkey.py selftest
"""

import argparse
import json
import os
import secrets
import sys
import time

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# ristretto255 (RFC 9496, section 4)
# ---------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952

IDENTITY = (0, 1, 1, 0)
# RFC 9496 A.1 B[1] — the canonical generator encoding
GENERATOR_ENC = bytes.fromhex(
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
)


def _is_negative(x):
    # RFC 9496: IS_NEGATIVE(x) is TRUE iff the least significant bit of the
    # canonical representative of x is 1.
    return (x % P) & 1


def _ct_abs(x):
    x %= P
    return (-x) % P if x & 1 else x


def sqrt_ratio_m1(u, v):
    """RFC 9496 section 4.2."""
    u %= P
    v %= P
    r = (u * pow(v, 3, P)) % P * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    check = v * r * r % P
    correct_sign_sqrt = check == u
    flipped_sign_sqrt = check == (-u) % P
    flipped_sign_sqrt_i = check == (-u * SQRT_M1) % P
    if flipped_sign_sqrt or flipped_sign_sqrt_i:
        r = r * SQRT_M1 % P
    r = _ct_abs(r)
    return correct_sign_sqrt or flipped_sign_sqrt, r


def ristretto_decode(b):
    """RFC 9496 section 4.3.1. Returns internal (x, y, z, t) or None."""
    if len(b) != 32:
        return None
    s = int.from_bytes(b, "little")
    if s >= P or _is_negative(s):
        return None
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 % P * u1 % P) - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr % P)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = _ct_abs(2 * s % P * den_x % P)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or _is_negative(t) or y == 0:
        return None
    return (x, y, 1, t)


def ristretto_encode(pt):
    """RFC 9496 section 4.3.2. Returns 32-byte canonical encoding."""
    x0, y0, z0, t0 = (c % P for c in pt)
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 % P * u2 % P)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    ix0 = x0 * SQRT_M1 % P
    iy0 = y0 * SQRT_M1 % P
    enchanted_denominator = den1 * INVSQRT_A_MINUS_D % P
    rotate = _is_negative(t0 * z_inv)
    x = iy0 if rotate else x0
    y = ix0 if rotate else y0
    z = z0
    den_inv = enchanted_denominator if rotate else den2
    if _is_negative(x * z_inv % P):
        y = (-y) % P
    s = _ct_abs(den_inv * (z - y) % P)
    return s.to_bytes(32, "little")


def edwards_add(p1, p2):
    """Unified extended-coordinate addition on edwards25519 (a = -1).
    Correct for doubling and identity as well (add-2008-hwcd-3)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D % P * t2 % P
    d = z1 * 2 * z2 % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def ristretto_map(b):
    """RFC 9496 section 4.3.4 MAP on a 32-byte string."""
    t = int.from_bytes(b, "little") % (2**255) % P
    r = SQRT_M1 * t % P * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D % P) * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    s_prime = (-_ct_abs(s * t)) % P
    if not was_square:
        s = s_prime
    c = (-1) % P if was_square else r
    n = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s % P * v % P
    w1 = n * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def ristretto_derive(b64):
    """RFC 9496 element derivation from a 64-byte string."""
    return edwards_add(ristretto_map(b64[:32]), ristretto_map(b64[32:]))


_GENERATOR = ristretto_decode(GENERATOR_ENC)
assert _GENERATOR is not None, "generator must decode"

# ponytail: 4-bit fixed-base window for the generator only; a full wNAF /
# precomputed comb table is the upgrade path if bulk scalar mults get hot.
_BASE_TABLE = [_GENERATOR]
for _i in range(14):
    _BASE_TABLE.append(edwards_add(_BASE_TABLE[-1], _GENERATOR))


def scalar_mul_base(k):
    """k * G using a precomputed 16-entry window over the generator."""
    k %= L
    acc = IDENTITY
    for i in range(63, -1, -1):
        for _ in range(4):
            acc = edwards_add(acc, acc)
        nib = (k >> (4 * i)) & 0xF
        if nib:
            acc = edwards_add(acc, _BASE_TABLE[nib - 1])
    return acc


def scalar_mul(k, pt):
    """k * pt, plain double-and-add (used in selftests only)."""
    k %= L
    acc = IDENTITY
    for i in range(k.bit_length() - 1, -1, -1):
        acc = edwards_add(acc, acc)
        if (k >> i) & 1:
            acc = edwards_add(acc, pt)
    return acc


def compressed_pubkey(secret_bytes32):
    """Tari CompressedPublicKey::from_secret_key: ristretto(k*G), 32 bytes."""
    k = int.from_bytes(secret_bytes32, "little") % L
    return ristretto_encode(scalar_mul_base(k))


# ---------------------------------------------------------------------------
# DammSum checksum (tari/base_layer/common_types/src/dammsum.rs)
# ---------------------------------------------------------------------------

_DAMM_MASK = 1 + (1 << 4) + (1 << 3) + (1 << 1)  # coefficients [4, 3, 1]


def damm_checksum(data):
    result = 0
    for digit in data:
        result ^= digit
        overflow = result & 0x80
        result = (result << 1) & 0xFF
        if overflow:
            result ^= _DAMM_MASK
    return result


def damm_validate(data):
    """True if data ends with a valid checksum byte (whole-slice check == 0)."""
    return len(data) >= 2 and damm_checksum(data) == 0


# ---------------------------------------------------------------------------
# Base58 (Bitcoin alphabet, bs58-crate compatible)
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


def b58encode(data):
    zeros = len(data) - len(data.lstrip(b"\x00"))
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    return "1" * zeros + out


def b58decode(s):
    if not s or any(c not in _B58_INDEX for c in s):
        return None
    zeros = len(s) - len(s.lstrip("1"))
    n = 0
    for c in s:
        n = n * 58 + _B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * zeros + body


# ---------------------------------------------------------------------------
# Emoji table (tari/base_layer/common_types/src/emoji.rs, 256 symbols)
# ---------------------------------------------------------------------------

EMOJI_TABLE = "🐢📟🌈🌊🎯🐋🌙🤔🌕⭐🎋🌰🌴🌵🌲🌸🌹🌻🌽🍀🍁🍄🥑🍆🍇🍈🍉🍊🍋🍌🍍🍎🍐🍑🍒🍓🍔🍕🍗🍚🍞🍟🥝🍣🍦🍩🍪🍫🍬🍭🍯🥐🍳🥄🍵🍶🍷🍸🍾🍺🍼🎀🎁🎂🎃🤖🎈🎉🎒🎓🎠🎡🎢🎣🎤🎥🎧🎨🎩🎪🎬🎭🎮🎰🎱🎲🎳🎵🎷🎸🎹🎺🎻🎼🎽🎾🎿🏀🏁🏆🏈⚽🏠🏥🏦🏭🏰🐀🐉🐊🐌🐍🦁🐐🐑🐔🙈🐗🐘🐙🐚🐛🐜🐝🐞🦋🐣🐨🦀🐪🐬🐭🐮🐯🐰🦆🦂🐴🐵🐶🐷🐸🐺🐻🐼🐽🐾👀👅👑👒🧢💅👕👖👗👘👙💃👛👞👟👠🥊👢👣🤡👻👽👾🤠👃💄💈💉💊💋👂💍💎💐💔🔒🧩💡💣💤💦💨💩➕💯💰💳💵💺💻💼📈📜📌📎📖📿📡⏰📱📷🔋🔌🚰🔑🔔🔥🔦🔧🔨🔩🔪🔫🔬🔭🔮🔱🗽😂😇😈🤑😍😎😱😷🤢👍👶🚀🚁🚂🚚🚑🚒🚓🛵🚗🚜🚢🚦🚧🚨🚪🚫🚲🚽🚿🧲"
assert len(EMOJI_TABLE) == 256, "emoji table must have exactly 256 symbols"
REVERSE_EMOJI = {c: i for i, c in enumerate(EMOJI_TABLE)}
assert len(REVERSE_EMOJI) == 256, "emoji table must be injective"

# Ghost score: the spookiest residents of the 256-symbol table
SPOOKY = [c for c in "👻🎃💀☠🔮👽🦇🕷🕸🧛🧟🌚🕯⚰🌙" if c in REVERSE_EMOJI]


# ---------------------------------------------------------------------------
# TariAddress
# ---------------------------------------------------------------------------

NETWORKS = {
    0x00: "mainnet",
    0x01: "stagenet",
    0x02: "nextnet",
    0x10: "localnet",
    0x24: "igor",
    0x26: "esmeralda",
}
NETWORK_BYTES = {v: k for k, v in NETWORKS.items()}

FEAT_PAYMENT_ID = 0b100
FEAT_INTERACTIVE = 0b010
FEAT_ONE_SIDED = 0b001
FEAT_ALL = 0b111

SINGLE_SIZE = 35
DUAL_SIZE = 67
MAX_PAYMENT_ID_SIZE = 256
B58_MIN = 45
B58_MAX = 443


class TariAddressError(Exception):
    """Mirrors the Rust TariAddressError variants."""


def _err(name):
    return TariAddressError(name)


class TariAddress:
    """A parsed/constructed Tari address (single or dual)."""

    def __init__(self, network_byte, features, spend_key, view_key=None,
                 payment_id=b""):
        self.network_byte = network_byte
        self.features = features
        self.spend_key = spend_key          # 32 bytes, ristretto-compressed
        self.view_key = view_key            # 32 bytes or None (single)
        self.payment_id = payment_id

    # -- properties ---------------------------------------------------------
    @property
    def is_dual(self):
        return self.view_key is not None

    @property
    def network(self):
        return NETWORKS[self.network_byte]

    @property
    def feature_names(self):
        out = []
        if self.features & FEAT_INTERACTIVE:
            out.append("interactive")
        if self.features & FEAT_ONE_SIDED:
            out.append("one-sided")
        if self.features & FEAT_PAYMENT_ID:
            out.append("payment-id")
        return out or ["none"]

    def ghost_score(self):
        return sum(1 for c in self.to_emoji() if c in SPOOKY)

    # -- encodings ------------------------------------------------------------
    def to_bytes(self):
        if self.is_dual:
            body = (bytes([self.network_byte, self.features])
                    + self.view_key + self.spend_key + self.payment_id)
        else:
            body = bytes([self.network_byte, self.features]) + self.spend_key
        return body + bytes([damm_checksum(body)])

    def to_base58(self):
        b = self.to_bytes()
        return (B58_ALPHABET[b[0]] + B58_ALPHABET[b[1]] + b58encode(b[2:]))

    def to_hex(self):
        return self.to_bytes().hex()

    def to_emoji(self):
        return "".join(EMOJI_TABLE[x] for x in self.to_bytes())

    # -- parsing --------------------------------------------------------------
    @classmethod
    def from_bytes(cls, data):
        n = len(data)
        if not (n == SINGLE_SIZE or DUAL_SIZE <= n <= DUAL_SIZE + MAX_PAYMENT_ID_SIZE):
            raise _err("InvalidSize")
        if not damm_validate(data):
            raise _err("InvalidChecksum")
        net = data[0]
        if net not in NETWORKS:
            raise _err("InvalidNetwork")
        features = data[1]
        if features & ~FEAT_ALL:
            raise _err("InvalidFeatures")
        if n == SINGLE_SIZE:
            if features & FEAT_PAYMENT_ID:
                raise _err("InvalidFeatures")
            spend = data[2:34]
            if ristretto_decode(spend) is None:
                raise _err("CannotRecoverPublicKey")
            return cls(net, features, spend)
        view, spend = data[2:34], data[34:66]
        payment_id = data[66:-1]
        if ristretto_decode(view) is None or ristretto_decode(spend) is None:
            raise _err("CannotRecoverPublicKey")
        if payment_id and not features & FEAT_PAYMENT_ID:
            raise _err("InvalidFeatures")
        return cls(net, features, spend, view, payment_id)

    @classmethod
    def from_base58(cls, s):
        if not B58_MIN <= len(s) <= B58_MAX:
            raise _err("InvalidSize")
        if s[0] not in _B58_INDEX:
            raise _err("CannotRecoverNetwork")
        if s[1] not in _B58_INDEX:
            raise _err("CannotRecoverFeature")
        rest = b58decode(s[2:])
        if rest is None:
            raise _err("CannotRecoverPublicKey")
        return cls.from_bytes(bytes([_B58_INDEX[s[0]], _B58_INDEX[s[1]]]) + rest)

    @classmethod
    def from_hex(cls, s):
        s = s.strip()
        if len(s) % 2 or any(c not in "0123456789abcdefABCDEF" for c in s):
            raise _err("CannotRecoverPublicKey")
        return cls.from_bytes(bytes.fromhex(s))

    @classmethod
    def from_emoji(cls, s):
        s = s.strip().replace("|", "")
        n = len(s)
        if not (n == SINGLE_SIZE or DUAL_SIZE <= n <= DUAL_SIZE + MAX_PAYMENT_ID_SIZE):
            raise _err("InvalidSize")
        try:
            data = bytes(REVERSE_EMOJI[c] for c in s)
        except KeyError:
            raise _err("InvalidEmoji") from None
        return cls.from_bytes(data)

    @classmethod
    def parse(cls, s):
        """TariAddress::from_str — try emoji, then base58, then hex."""
        s = s.strip().replace("|", "")
        for parser in (cls.from_emoji, cls.from_base58, cls.from_hex):
            try:
                return parser(s)
            except TariAddressError:
                pass
        raise _err("InvalidAddressString")

    def __eq__(self, other):
        return isinstance(other, TariAddress) and self.to_bytes() == other.to_bytes()

    def __str__(self):
        return self.to_base58()


# ---------------------------------------------------------------------------
# Key generation (keyless — pure local randomness)
# ---------------------------------------------------------------------------

def new_secret():
    return secrets.token_bytes(32)


def generate(network="esmeralda", dual=True, features=FEAT_INTERACTIVE | FEAT_ONE_SIDED,
             payment_id=b""):
    net = NETWORK_BYTES[network]
    features &= ~FEAT_PAYMENT_ID
    if payment_id:
        if len(payment_id) > MAX_PAYMENT_ID_SIZE:
            raise _err("PaymentIdTooLarge")
        features |= FEAT_PAYMENT_ID
    if dual:
        view_secret, spend_secret = new_secret(), new_secret()
        addr = TariAddress(net, features, compressed_pubkey(spend_secret),
                           compressed_pubkey(view_secret), payment_id)
        return addr, {"view_secret_hex": view_secret.hex(),
                      "spend_secret_hex": spend_secret.hex()}
    spend_secret = new_secret()
    addr = TariAddress(net, features, compressed_pubkey(spend_secret), None, b"")
    return addr, {"spend_secret_hex": spend_secret.hex()}


def save_keyfile(path, addr, keydict):
    payload = {
        "version": 1,
        "type": "dual" if addr.is_dual else "single",
        "network": addr.network,
        "features": addr.features,
        "address_base58": addr.to_base58(),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **keydict,
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(payload, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows: best effort


# ---------------------------------------------------------------------------
# Ghost mining — vanity addresses with spooky emoji
# ---------------------------------------------------------------------------

def mine(target_emoji, network="esmeralda", tries=300_000, progress=True):
    """Search for an address whose emoji id contains `target_emoji` inside the
    minable (key) region. The first two emoji are fixed by network/features."""
    for c in target_emoji:
        if c not in REVERSE_EMOJI:
            raise _err(f"InvalidEmoji: {c!r} is not in the Tari emoji table")
    if len(target_emoji) > 3:
        raise ValueError("targets longer than 3 emoji take ~days in pure "
                         "Python; use 1-3 (see README)")
    start = time.time()
    for i in range(1, tries + 1):
        addr, keys = generate(network=network)
        emoji = addr.to_emoji()
        if target_emoji in emoji[2:]:
            if progress:
                print(f"\n⛏️  struck gold after {i} attempts "
                      f"({time.time() - start:.1f}s)")
            return addr, keys, i
        if progress and i % 2500 == 0:
            print(f"\r⛏️  {i} ghosts summoned… ({i / (time.time() - start):.0f}/s)",
                  end="", flush=True)
    return None, None, tries


# ---------------------------------------------------------------------------
# Self-test: RFC 9496 test vectors + Tari golden vectors
# ---------------------------------------------------------------------------

_RISTRETTO_MULTIPLES = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
    "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
    "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
    "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
    "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
    "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
    "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
]

_RISTRETTO_INVALID = [
    # non-canonical field encodings
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    # negative field elements
    "0100000000000000000000000000000000000000000000000000000000000000",
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
    "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
    "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
    "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
    "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
    "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
    # non-square x^2
    "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
    "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
    "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
    "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
    "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
    "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
    "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
    "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
    # negative x*y
    "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
    "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
    "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
    "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
    "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
    "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
    "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
    "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
    # s = -1 causes y = 0
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]

_RISTRETTO_DERIVE = [
    ("5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1"
     "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
     "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46"),
    ("f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27"
     "0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
     "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b"),
    ("8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c"
     "27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
     "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826"),
    ("ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2"
     "150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
     "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a"),
    ("165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767"
     "5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
     "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179"),
    ("a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2"
     "979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
     "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628"),
    ("2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462"
     "2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
     "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065"),
]

_RISTRETTO_DERIVE_SAME = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "1200000000000000000000000000000000000000000000000000000000000000",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000080"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000"
    "1200000000000000000000000000000000000000000000000000000000000080",
]
_RISTRETTO_DERIVE_SAME_OUT = \
    "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"

# Tari golden vectors (from the tari-project/tari Rust test suite)
_GOLDEN_DUAL_MAINNET = (
    "126J92Yow5y9UoRFd1DNujPmVFq9C1ZeiYWT95UKxz5Y1rzbfjtHg4SCZS1dk83ivzt3m2XRQHTaYUk9SwmyeCvy5BJ",
    "3c0223f2be5917384926cbe1a3cd32a907963a933c035801e3f99d1902f3e924",
    "d09dfde45e45456b7a8935fecfc0ebea431548d105d2f098a488820526395a61",
)
_GOLDEN_PAYMENT_ID = [
    ("f75xWw72BhjRuSatHg4MtqgqzejhZJEmHH7DyYceQDVfKdepfY22CfPJUFQyhkao28gp7cbVqVdR9zczg9eKpoYjGUBH6G32SB", b"vgfve"),
    ("f65xWw72BhjRuSatHg4MtqgqzejhZJEmHH7DyYceQDVfKdfPq5FDo1y7d7pnkm7nxfLy5JpcJMAoX2eiSvHmV7TeTo9k5tsAuR", b"vgfve"),
]
_GOLDEN_SINGLE_BASE = "f23KSMumnDPez4mX9Lxxr1tFDvnkt6aJbsxYLps6sp53PSEHeFXggaGdL3vA4sCHjjbX9Q9KxqyYKUqmeyiWqgUuwFz"

# Tari Rust-suite emoji vectors (single address, 35 emoji)
_E_BAD_CHECKSUM = "🍗🌈🚓🧲📌🐺🐣🙈💰🍇🎓👂📈⚽🚧🚧🚢🍫💋👽🌈🎪🚽🍪🎳💼🙈🎪😎🏠🎳👍📷🎲🎒"
_E_BAD_EMOJI = "🍗🌊🐉🦋🎪👛🌲🐭🦂🔨💺🎺🌕💦🚨🎼🍪⏰🍬🍚🎱💳🔱🐵🛵💡📱🌻📎🎻🐌😎👙🎹🎅"


def selftest(verbose=True):
    def check(name, cond):
        assert cond, f"FAILED: {name}"
        if verbose:
            print(f"  ✓ {name}")

    print("RFC 9496 ristretto255:")
    # A.4 sqrt_ratio vectors
    for u, v, sq, r in [
        (0, 0, True, 0), (0, 1, True, 0), (1, 0, False, 0),
        (4, 1, True, 2),
        (1, 4, True, int.from_bytes(bytes.fromhex(
            "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"), "little")),
    ]:
        got_sq, got_r = sqrt_ratio_m1(u, v)
        check(f"sqrt_ratio_m1({u},{v})", got_sq == sq and got_r == r)
    got_sq, got_r = sqrt_ratio_m1(2, 1)
    check("sqrt_ratio_m1(2,1)", not got_sq and got_r == int.from_bytes(
        bytes.fromhex("3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54"),
        "little"))

    # A.1 generator multiples via decode/encode and scalar mult
    pts = []
    for i, h in enumerate(_RISTRETTO_MULTIPLES):
        b = bytes.fromhex(h)
        pt = ristretto_decode(b)
        if i == 0:
            check("B[0] identity decodes", pt is not None)
        else:
            assert pt is not None, f"B[{i}] must decode"
        check(f"encode(B[{i}])", ristretto_encode(pt) == b)
        pts.append(pt)
    acc = IDENTITY
    for i in range(1, 16):
        acc = edwards_add(acc, pts[1])
        check(f"sum matches B[{i}]",
              ristretto_encode(acc) == bytes.fromhex(_RISTRETTO_MULTIPLES[i]))
    check("scalar_mul matches B[15]",
          ristretto_encode(scalar_mul(15, pts[1])) == bytes.fromhex(_RISTRETTO_MULTIPLES[15]))
    check("scalar_mul_base matches B[7]",
          ristretto_encode(scalar_mul_base(7)) == bytes.fromhex(_RISTRETTO_MULTIPLES[7]))
    check("scalar_mul_base matches B[15]",
          ristretto_encode(scalar_mul_base(15)) == bytes.fromhex(_RISTRETTO_MULTIPLES[15]))

    # A.2 invalid encodings
    for i, h in enumerate(_RISTRETTO_INVALID):
        check(f"reject invalid encoding #{i}",
              ristretto_decode(bytes.fromhex(h)) is None)

    # A.3 derivation
    for i, (inp, out) in enumerate(_RISTRETTO_DERIVE):
        check(f"derive vector #{i}",
              ristretto_encode(ristretto_derive(bytes.fromhex(inp))) == bytes.fromhex(out))
    for i, inp in enumerate(_RISTRETTO_DERIVE_SAME):
        check(f"derive same-output #{i}",
              ristretto_encode(ristretto_derive(bytes.fromhex(inp)))
              == bytes.fromhex(_RISTRETTO_DERIVE_SAME_OUT))

    print("Tari golden vectors:")
    check("dammsum all-zero == 0", damm_checksum(bytes(33)) == 0)
    b58, view_hex, spend_hex = _GOLDEN_DUAL_MAINNET
    a = TariAddress.from_base58(b58)
    check("dual mainnet: network", a.network == "mainnet" and a.is_dual)
    check("dual mainnet: features == ONE_SIDED", a.features == FEAT_ONE_SIDED)
    check("dual mainnet: view key", a.view_key.hex() == view_hex)
    check("dual mainnet: spend key", a.spend_key.hex() == spend_hex)
    check("dual mainnet: base58 round-trip", a.to_base58() == b58)
    check("dual mainnet: hex round-trip", TariAddress.from_hex(a.to_hex()) == a)
    check("dual mainnet: emoji round-trip", TariAddress.from_emoji(a.to_emoji()) == a)
    check("dual mainnet: emoji length 67", len(a.to_emoji()) == DUAL_SIZE)
    check("dual mainnet: parse() dispatch", TariAddress.parse(b58) == a and
          TariAddress.parse(a.to_emoji()) == a and TariAddress.parse(a.to_hex()) == a)

    for b58p, pid in _GOLDEN_PAYMENT_ID:
        ap = TariAddress.from_base58(b58p)
        check(f"payment-id address {b58p[:12]}…", ap.payment_id == pid and
              ap.features & FEAT_PAYMENT_ID and ap.network == "esmeralda" and
              ap.to_base58() == b58p and
              TariAddress.from_emoji(ap.to_emoji()) == ap)

    base = TariAddress.from_base58(_GOLDEN_SINGLE_BASE)
    check("f23KSM… is dual esmeralda one-sided, no payment id",
          base.is_dual and base.network == "esmeralda" and
          base.features == FEAT_ONE_SIDED and base.payment_id == b"")
    hello = TariAddress(base.network_byte, base.features | FEAT_PAYMENT_ID,
                        base.spend_key, base.view_key, b"Hello")
    check("with payment-id 'Hello' round-trips",
          TariAddress.from_base58(hello.to_base58()).payment_id == b"Hello")

    def expect_err(name, fn, err):
        try:
            fn()
            raise AssertionError(f"FAILED: {name} did not raise")
        except TariAddressError as e:
            check(name, str(e) == err)

    expect_err("emoji: invalid checksum", lambda: TariAddress.from_emoji(_E_BAD_CHECKSUM), "InvalidChecksum")
    expect_err("emoji: invalid emoji", lambda: TariAddress.from_emoji(_E_BAD_EMOJI), "InvalidEmoji")
    expect_err("emoji: invalid size (33)", lambda: TariAddress.from_emoji("🦀🌴🔌📌🚑🌰🎓🌴🐊🐌🔒💡🐜📜👛🍵👛🐽🎂🐻🐢🍓👶🐭🐼🏀🎪💔💵🥑🔋🎒🥊"), "InvalidSize")
    expect_err("base58: bad checksum rejected", lambda: TariAddress.from_base58(b58[:-2] + "zz"), "InvalidChecksum")
    tampered = bytearray(a.to_bytes())
    tampered[0] = 123  # invalid network, recompute checksum like the Rust test
    tampered[-1] = damm_checksum(bytes(tampered[:-1]))
    expect_err("bytes: invalid network", lambda: TariAddress.from_bytes(bytes(tampered)), "InvalidNetwork")
    tampered = bytearray(a.to_bytes())
    tampered[1] = 8  # unknown feature bits
    tampered[-1] = damm_checksum(bytes(tampered[:-1]))
    expect_err("bytes: invalid features", lambda: TariAddress.from_bytes(bytes(tampered)), "InvalidFeatures")
    expect_err("parse: garbage", lambda: TariAddress.parse("🦊🦊🦊 not an address"), "InvalidAddressString")

    print("generate / keygen:")
    addr, keys = generate(network="mainnet")
    check("generated dual mainnet parses back", TariAddress.parse(addr.to_base58()) == addr)
    check("secret -> pubkey is deterministic",
          compressed_pubkey(bytes.fromhex(keys["spend_secret_hex"])) == addr.spend_key)
    addr2, _ = generate(network="esmeralda", dual=False,
                        features=FEAT_INTERACTIVE | FEAT_ONE_SIDED)
    check("generated single is 35 bytes / parses", len(addr2.to_bytes()) == SINGLE_SIZE
          and TariAddress.parse(addr2.to_emoji()) == addr2)
    def _single_pid_flag_bytes():
        body = bytes([0x26, FEAT_INTERACTIVE | FEAT_PAYMENT_ID]) + bytes(32)
        return body + bytes([damm_checksum(body)])
    check("single rejects payment-id flag",
          _raises(lambda: TariAddress.from_bytes(_single_pid_flag_bytes()),
                  "InvalidFeatures"))
    addr3, _ = generate(payment_id=b"BOO!")
    check("payment-id generate round-trip", TariAddress.parse(addr3.to_base58()).payment_id == b"BOO!")

    if verbose:
        print("\nall checks passed 👻")
    return True


def _raises(fn, err):
    try:
        fn()
        return False
    except TariAddressError as e:
        return str(e) == err


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_address(addr, keys=None):
    print(f"network   : {addr.network}")
    print(f"type      : {'dual' if addr.is_dual else 'single'}")
    print(f"features  : {', '.join(addr.feature_names)} (byte 0x{addr.features:02x})")
    if addr.payment_id:
        pid = addr.payment_id
        printable = all(32 <= c < 127 for c in pid)
        print(f"payment id: {pid.decode() if printable else pid.hex()!r} ({len(pid)} bytes)")
    print(f"checksum  : valid (DammSum)")
    print(f"spend key : {addr.spend_key.hex()}")
    if addr.is_dual:
        print(f"view key  : {addr.view_key.hex()}")
    print(f"ghost score: {addr.ghost_score()} spooky emoji 👻")
    print()
    print(f"base58 : {addr.to_base58()}")
    print(f"hex    : {addr.to_hex()}")
    print(f"emoji  : {addr.to_emoji()}")
    if keys:
        for k, v in keys.items():
            print(f"{k.replace('_hex',''):13s}: {v}")


def cmd_generate(args):
    network = args.network.lower()
    if network not in NETWORK_BYTES:
        sys.exit(f"unknown network {network!r}; pick one of {', '.join(NETWORK_BYTES)}")
    features = 0
    for f in args.features.split(","):
        f = f.strip().lower().replace("-", "").replace("_", "")
        val = {"interactive": FEAT_INTERACTIVE, "onesided": FEAT_ONE_SIDED,
               "paymentid": FEAT_PAYMENT_ID}.get(f)
        if val is None:
            sys.exit(f"unknown feature {f!r}")
        features |= val
    pid = args.payment_id.encode() if args.payment_id else b""
    addr, keys = generate(network=network, dual=not args.single,
                          features=features, payment_id=pid)
    if args.save:
        if os.path.exists(args.save) and not args.force:
            sys.exit(f"{args.save} exists (use --force to overwrite)")
        save_keyfile(args.save, addr, keys)
        print(f"🔑 keyfile saved: {args.save} (mode 600 — never share it)\n")
        _print_address(addr)
    else:
        _print_address(addr, keys)
        print("\n⚠️  no --save: these secrets are shown once and NOT stored. "
              "Re-run with --save FILE to keep them.")


def cmd_inspect(args):
    addr = TariAddress.parse(args.address)
    _print_address(addr)


def cmd_convert(args):
    addr = TariAddress.parse(args.address)
    print({"emoji": addr.to_emoji, "base58": addr.to_base58, "hex": addr.to_hex}[args.to]())


def cmd_vanity(args):
    t0 = time.time()
    addr, keys, attempts = mine(args.emoji, network=args.network, tries=args.tries)
    if addr is None:
        sys.exit(f"no ghost found in {attempts} attempts — the spirits are restless")
    print(f"👻 {args.emoji} materialised after {attempts} attempts "
          f"({time.time() - t0:.1f}s)")
    if args.save:
        save_keyfile(args.save, addr, keys)
        print(f"🔑 keyfile saved: {args.save}")
        _print_address(addr)
    else:
        _print_address(addr, keys)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ghostkey", description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="generate a new keyless local Tari address")
    g.add_argument("--network", default="esmeralda")
    g.add_argument("--single", action="store_true", help="single-key address (default: dual)")
    g.add_argument("--features", default="interactive,onesided")
    g.add_argument("--payment-id", default=None)
    g.add_argument("--save", default=None, help="save secrets to this JSON file (mode 600)")
    g.add_argument("--force", action="store_true")
    g.set_defaults(fn=cmd_generate)

    i = sub.add_parser("inspect", help="inspect any Tari address (base58/hex/emoji)")
    i.add_argument("address")
    i.set_defaults(fn=cmd_inspect)

    c = sub.add_parser("convert", help="convert between base58 / hex / emoji")
    c.add_argument("address")
    c.add_argument("--to", required=True, choices=["emoji", "base58", "hex"])
    c.set_defaults(fn=cmd_convert)

    v = sub.add_parser("vanity", help="mine a ghost address containing spooky emoji")
    v.add_argument("--emoji", required=True, help="1-3 emoji, e.g. 👻🎃")
    v.add_argument("--network", default="esmeralda")
    v.add_argument("--tries", type=int, default=300_000)
    v.add_argument("--save", default=None)
    v.set_defaults(fn=cmd_vanity)

    s = sub.add_parser("selftest", help="verify against RFC 9496 + Tari test vectors")
    s.set_defaults(fn=lambda a: selftest())

    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except TariAddressError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
