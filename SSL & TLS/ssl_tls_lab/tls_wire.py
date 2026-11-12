"""TLS 1.2/1.3 framing, key derivation and record protection for the model."""

from __future__ import annotations

import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA = 20, 21, 22, 23
LEGACY_VERSION = b"\x03\x03"
GROUP_IDS = {"ECDHE X25519": 29, "ECDHE P-256": 23, "DHE ffdhe2048": 256}
MAX_FRAGMENT = 16384


def vec(data: bytes, size: int) -> bytes:
    """Length-prefixed vector with a `size`-byte big-endian length."""
    return len(data).to_bytes(size, "big") + data


def record(kind: int, payload: bytes, version: bytes = LEGACY_VERSION) -> bytes:
    return bytes([kind]) + version + vec(payload, 2)


def handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + vec(body, 3)


def extension(kind: int, body: bytes) -> bytes:
    return kind.to_bytes(2, "big") + vec(body, 2)


def parse_extensions(data: bytes) -> dict[int, bytes]:
    found, pos = {}, 0
    while pos + 4 <= len(data):
        kind = int.from_bytes(data[pos : pos + 2], "big")
        size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        found[kind] = data[pos + 4 : pos + 4 + size]
        pos += 4 + size
    return found


def parse_hello(message: bytes, client: bool) -> dict:
    """Read the fields the peer needs from a ClientHello or ServerHello."""
    body = message[4:]
    random = body[2:34]
    pos = 34
    session_id = body[pos + 1 : pos + 1 + body[pos]]
    pos += 1 + len(session_id)
    if client:
        size = int.from_bytes(body[pos : pos + 2], "big")
        suites = body[pos + 2 : pos + 2 + size]
        pos += 2 + size
        pos += 1 + body[pos]
    else:
        suites = body[pos : pos + 2]
        pos += 3
    size = int.from_bytes(body[pos : pos + 2], "big")
    return {
        "random": random,
        "session_id": session_id,
        "suites": [
            int.from_bytes(suites[i : i + 2], "big") for i in range(0, len(suites), 2)
        ],
        "extensions": parse_extensions(body[pos + 2 : pos + 2 + size]),
    }


# --- Key exchange ---------------------------------------------------------


def generate_share(exchange: str):
    """Return (private key object, private value hex, public value as sent)."""
    if exchange == "ECDHE X25519":
        key = x25519.X25519PrivateKey.generate()
        private = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return key, private.hex(), public
    if exchange == "ECDHE P-256":
        key = ec.generate_private_key(ec.SECP256R1())
        public = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return key, f"{key.private_numbers().private_value:064x}", public
    from .dh_group import ffdhe_parameters, parameters

    group = ffdhe_parameters() if exchange == "DHE ffdhe2048" else parameters()
    key = group.generate_private_key()
    numbers = key.private_numbers()
    p = numbers.public_numbers.parameter_numbers.p
    size = (p.bit_length() + 7) // 8
    return key, f"{numbers.x:x}", numbers.public_numbers.y.to_bytes(size, "big")


def shared_secret(exchange: str, private, peer_public: bytes, strip=False) -> bytes:
    """Combine our private key with the public value received from the peer.

    TLS 1.3 keeps the finite-field result at the full length of p; TLS 1.2
    strips its leading zero bytes (`strip=True`).
    """
    if exchange == "ECDHE X25519":
        return private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    if exchange == "ECDHE P-256":
        return private.exchange(
            ec.ECDH(),
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public),
        )
    numbers = private.private_numbers()
    p = numbers.public_numbers.parameter_numbers.p
    y = int.from_bytes(peer_public, "big")
    if not 1 < y < p - 1:
        raise ValueError("Khóa công khai DH của phía kia không hợp lệ")
    secret = pow(y, numbers.x, p).to_bytes((p.bit_length() + 7) // 8, "big")
    return secret.lstrip(b"\x00") if strip else secret


# --- TLS 1.3 key schedule (RFC 8446 section 7.1) ---------------------------


def hkdf_extract(salt: bytes, key: bytes, digest) -> bytes:
    return hmac.new(salt, key, digest).digest()


def hkdf_expand(key: bytes, info: bytes, length: int, digest) -> bytes:
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(key, block + info + bytes([counter]), digest).digest()
        output += block
        counter += 1
    return output[:length]


def hkdf_expand_label(key: bytes, label: str, context: bytes, length: int, digest):
    info = (
        length.to_bytes(2, "big") + vec(b"tls13 " + label.encode(), 1) + vec(context, 1)
    )
    return hkdf_expand(key, info, length, digest)


def _traffic(secret: bytes, digest, key_len: int):
    return (
        hkdf_expand_label(secret, "key", b"", key_len, digest),
        hkdf_expand_label(secret, "iv", b"", 12, digest),
    )


def tls13_handshake_secrets(shared: bytes, hello_hash: bytes, digest, key_len: int):
    size = digest().digest_size
    early = hkdf_extract(bytes(size), bytes(size), digest)
    derived = hkdf_expand_label(early, "derived", digest(b"").digest(), size, digest)
    secret = hkdf_extract(derived, shared, digest)
    client = hkdf_expand_label(secret, "c hs traffic", hello_hash, size, digest)
    server = hkdf_expand_label(secret, "s hs traffic", hello_hash, size, digest)
    client_key, client_iv = _traffic(client, digest, key_len)
    server_key, server_iv = _traffic(server, digest, key_len)
    return {
        "handshake_secret": secret,
        "client_secret": client,
        "server_secret": server,
        "client_key": client_key,
        "client_iv": client_iv,
        "server_key": server_key,
        "server_iv": server_iv,
    }


def tls13_application_secrets(
    handshake_secret: bytes, handshake_hash: bytes, digest, key_len: int
):
    size = digest().digest_size
    derived = hkdf_expand_label(
        handshake_secret, "derived", digest(b"").digest(), size, digest
    )
    master = hkdf_extract(derived, bytes(size), digest)
    client = hkdf_expand_label(master, "c ap traffic", handshake_hash, size, digest)
    server = hkdf_expand_label(master, "s ap traffic", handshake_hash, size, digest)
    client_key, client_iv = _traffic(client, digest, key_len)
    server_key, server_iv = _traffic(server, digest, key_len)
    return {
        "master_secret": master,
        "client_secret": client,
        "server_secret": server,
        "client_key": client_key,
        "client_iv": client_iv,
        "server_key": server_key,
        "server_iv": server_iv,
    }


def tls13_verify_data(traffic_secret: bytes, transcript_hash: bytes, digest) -> bytes:
    size = digest().digest_size
    finished_key = hkdf_expand_label(traffic_secret, "finished", b"", size, digest)
    return hmac.new(finished_key, transcript_hash, digest).digest()


def tls13_nonce(iv: bytes, sequence: int) -> bytes:
    return (int.from_bytes(iv, "big") ^ sequence).to_bytes(12, "big")


def tls13_seal(key: bytes, iv: bytes, sequence: int, kind: int, data: bytes) -> bytes:
    """Wrap `data` in a record disguised as TLS 1.2 application data."""
    inner = data + bytes([kind])
    header = bytes([APPLICATION_DATA]) + LEGACY_VERSION + (len(inner) + 16).to_bytes(
        2, "big"
    )
    return header + AESGCM(key).encrypt(tls13_nonce(iv, sequence), inner, header)


def tls13_open(key: bytes, iv: bytes, sequence: int, wrapped: bytes):
    """Return (inner record type, data); raises InvalidTag if modified."""
    inner = AESGCM(key).decrypt(tls13_nonce(iv, sequence), wrapped[5:], wrapped[:5])
    return inner[-1], inner[:-1]


# --- TLS 1.2 PRF and AEAD records (RFC 5246, RFC 5288) ---------------------


def p_hash(secret: bytes, seed: bytes, length: int, digest) -> bytes:
    """P_hash: HMAC(secret, A(i) || seed), A(0) = seed."""
    result, a = b"", seed
    while len(result) < length:
        a = hmac.new(secret, a, digest).digest()
        result += hmac.new(secret, a + seed, digest).digest()
    return result[:length]


def prf(secret: bytes, label: str, seed: bytes, length: int, digest) -> bytes:
    return p_hash(secret, label.encode() + seed, length, digest)


def tls12_master_secret(premaster, client_random, server_random, digest) -> bytes:
    return prf(premaster, "master secret", client_random + server_random, 48, digest)


def tls12_key_block(master, client_random, server_random, digest, key_len: int):
    block = prf(
        master,
        "key expansion",
        server_random + client_random,
        2 * key_len + 8,
        digest,
    )
    return {
        "client_key": block[:key_len],
        "server_key": block[key_len : 2 * key_len],
        "client_iv": block[2 * key_len : 2 * key_len + 4],
        "server_iv": block[2 * key_len + 4 :],
    }


def tls12_seal(key: bytes, iv: bytes, sequence: int, kind: int, data: bytes) -> bytes:
    explicit = sequence.to_bytes(8, "big")
    aad = explicit + bytes([kind]) + LEGACY_VERSION + len(data).to_bytes(2, "big")
    return record(kind, explicit + AESGCM(key).encrypt(iv + explicit, data, aad))


def tls12_open(key: bytes, iv: bytes, sequence: int, sealed: bytes) -> bytes:
    """Return the plaintext; raises InvalidTag if the record was modified."""
    explicit, protected = sealed[5:13], sealed[13:]
    aad = (
        sequence.to_bytes(8, "big")
        + sealed[:3]
        + (len(protected) - 16).to_bytes(2, "big")
    )
    return AESGCM(key).decrypt(iv + explicit, protected, aad)


# --- Observation of captured legacy handshakes ----------------------------


def negotiated_group(chunks, version="TLS 1.2"):
    """Read the group from a cleartext ServerKeyExchange in captured records."""
    data = b"".join(chunks)
    fragments = b""
    pos = 0
    while pos + 5 <= len(data):
        kind = data[pos]
        size = int.from_bytes(data[pos + 3 : pos + 5], "big")
        if pos + 5 + size > len(data):
            break
        if kind == 20:
            break  # Subsequent records are encrypted.
        if kind == 22:
            fragments += data[pos + 5 : pos + 5 + size]
        pos += 5 + size
    pos = 0
    while pos + 4 <= len(fragments):
        kind = fragments[pos]
        size = int.from_bytes(fragments[pos + 1 : pos + 4], "big")
        body = fragments[pos + 4 : pos + 4 + size]
        if len(body) != size:
            break
        if version == "TLS 1.2" and kind == 12 and len(body) >= 3:
            if body[0] == 3:
                return {23: "ECDHE P-256", 29: "ECDHE X25519"}.get(
                    int.from_bytes(body[1:3], "big")
                )
            p_len = int.from_bytes(body[:2], "big")
            if p_len and len(body) >= 2 + p_len:
                from .dh_group import P

                if int.from_bytes(body[2 : 2 + p_len], "big") == P:
                    return "DHE 2048"
        pos += 4 + size
    return None
