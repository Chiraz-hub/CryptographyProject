"""Versioned header for the FENC file format (version 1).

Layout (38 bytes, big-endian, all fields NON-secret):

    0   4  magic            b"FENC"
    4   1  version          1
    5   1  algorithm id     1 = AES-GCM, 2 = ChaCha20-Poly1305
    6   1  key mode         1 = raw key, 2 = password (scrypt)
    7   1  key length       bytes: 16/24/32
    8   4  chunk size       plaintext bytes per chunk
    12  7  nonce prefix     random, per file
    19 16  scrypt salt      random in password mode, zeros in raw mode
    35  1  scrypt log2(N)   0 in raw mode
    36  1  scrypt r         0 in raw mode
    37  1  scrypt p         0 in raw mode

The whole header is fed to the cipher as associated data (AAD) for every
chunk, so changing any header byte makes authentication fail.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from .errors import FormatError, ParameterError

MAGIC = b"FENC"
VERSION = 1
_STRUCT = struct.Struct(">4sBBBBI7s16sBBB")
HEADER_SIZE = _STRUCT.size  # 38

NONCE_PREFIX_LEN = 7
SALT_LEN = 16

DEFAULT_CHUNK_SIZE = 64 * 1024
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024

# scrypt limits. Encryption defaults sit well inside these; decryption
# REJECTS anything outside them so a hostile file cannot demand huge memory.
DEFAULT_SCRYPT = (15, 8, 1)  # N=2**15, r=8, p=1  -> ~32 MiB
MIN_SCRYPT_LOG2N = 14
MAX_SCRYPT_MEM = 128 * 1024 * 1024  # bytes, estimated as 128 * N * r
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4


class Algorithm(IntEnum):
    AES_GCM = 1
    CHACHA20_POLY1305 = 2

    @property
    def valid_key_lengths(self) -> tuple[int, ...]:
        return (16, 24, 32) if self is Algorithm.AES_GCM else (32,)


class KeyMode(IntEnum):
    RAW = 1
    PASSWORD = 2


@dataclass(frozen=True)
class Header:
    algorithm: Algorithm
    key_mode: KeyMode
    key_length: int
    chunk_size: int
    nonce_prefix: bytes
    salt: bytes
    scrypt_log2n: int = 0
    scrypt_r: int = 0
    scrypt_p: int = 0

    def validate(self) -> None:
        """Raise FormatError if any field is outside the allowed range."""
        if self.key_length not in self.algorithm.valid_key_lengths:
            raise FormatError("invalid key length for algorithm")
        if not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise FormatError("chunk size out of range")
        if len(self.nonce_prefix) != NONCE_PREFIX_LEN or len(self.salt) != SALT_LEN:
            raise FormatError("bad nonce/salt length")
        if self.key_mode is KeyMode.PASSWORD:
            n = 1 << self.scrypt_log2n if self.scrypt_log2n < 32 else 0
            if self.scrypt_log2n < MIN_SCRYPT_LOG2N or not n:
                raise FormatError("scrypt N out of range")
            if not 1 <= self.scrypt_r <= MAX_SCRYPT_R:
                raise FormatError("scrypt r out of range")
            if not 1 <= self.scrypt_p <= MAX_SCRYPT_P:
                raise FormatError("scrypt p out of range")
            if 128 * n * self.scrypt_r > MAX_SCRYPT_MEM:
                raise FormatError("scrypt memory cost too high")
        elif (self.scrypt_log2n, self.scrypt_r, self.scrypt_p) != (0, 0, 0) \
                or self.salt != bytes(SALT_LEN):
            raise FormatError("unexpected KDF fields in raw-key file")

    def pack(self) -> bytes:
        """Validate, then serialize. Bad parameters are the caller's bug."""
        try:
            self.validate()
        except FormatError as exc:
            raise ParameterError(str(exc)) from None
        return _STRUCT.pack(
            MAGIC, VERSION, self.algorithm, self.key_mode, self.key_length,
            self.chunk_size, self.nonce_prefix, self.salt,
            self.scrypt_log2n, self.scrypt_r, self.scrypt_p,
        )

    @classmethod
    def parse(cls, data: bytes) -> "Header":
        """Strictly parse and validate raw header bytes (used in Phase 4)."""
        if len(data) != HEADER_SIZE:
            raise FormatError("truncated header")
        (magic, version, alg, mode, klen, csize, prefix, salt,
         log2n, r, p) = _STRUCT.unpack(data)
        if magic != MAGIC:
            raise FormatError("not a FENC file")
        if version != VERSION:
            raise FormatError("unsupported format version")
        try:
            algorithm, key_mode = Algorithm(alg), KeyMode(mode)
        except ValueError:
            raise FormatError("unsupported algorithm or key mode") from None
        header = cls(algorithm, key_mode, klen, csize, prefix, salt, log2n, r, p)
        header.validate()
        return header
