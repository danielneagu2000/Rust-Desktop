"""Ed25519 signing (RFC 8032, section 6 reference algorithm), standard library only.

Used to sign license tokens with the rendezvous server's key (data/id_ed25519), which
clients verify with libsodium's crypto_sign_open. Signing is not constant-time; the
panel signs a few tokens per minute on a machine the operator controls. verify() checks
the device-key signatures apps put on their requests when PyNaCl is not installed.
"""

import hashlib

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _compress(p):
    zinv = _inv(p[2])
    x, y = p[0] * zinv % _P, p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _hash_int(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def public_key(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_mul(a, _G))


def sign(seed, msg):
    """Detached 64-byte signature of msg with the 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = _compress(_mul(a, _G))
    r = _hash_int(h[32:] + msg) % _Q
    big_r = _compress(_mul(r, _G))
    k = _hash_int(big_r + pub + msg) % _Q
    s = (r + k * a) % _Q
    return big_r + int.to_bytes(s, 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def verify(public, msg, signature):
    """True when signature is a valid detached Ed25519 signature of msg by the 32-byte public key."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _Q:
        return False
    h = _hash_int(signature[:32] + public + msg) % _Q
    left, right = _mul(s, _G), _add(r, _mul(h, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (left[1] * right[2] - right[1] * left[2]) % _P == 0
