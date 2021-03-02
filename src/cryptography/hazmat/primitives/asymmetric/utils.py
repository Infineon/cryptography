# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import typing

from cryptography.hazmat._der import (
    DERReader,
    INTEGER,
    SEQUENCE,
    encode_der,
    encode_der_integer,
)
from cryptography.hazmat.primitives import hashes


def decode_dss_signature(signature: bytes) -> typing.Tuple[int, int]:
    with DERReader(signature).read_single_element(SEQUENCE) as seq:
        r = seq.read_element(INTEGER).as_integer()
        s = seq.read_element(INTEGER).as_integer()
        return r, s


def encode_dss_signature(r: int, s: int) -> bytes:
    return encode_der(
        SEQUENCE,
        encode_der(INTEGER, encode_der_integer(r)),
        encode_der(INTEGER, encode_der_integer(s)),
    )


def sm2_z_hash(hash_algorithm, user_id, public_key, backend):
    digest = hashes.Hash(hash_algorithm, backend)
    digest.update(utils.int_to_bytes(len(user_id) * 8, 2))
    digest.update(user_id)

    p, a, b, xg, yg = backend.elliptic_curve_parameters(public_key.curve)
    p_len = (p.bit_length() + 7) // 8
    public_numbers = public_key.public_numbers()

    digest.update(utils.int_to_bytes(a, p_len))
    digest.update(utils.int_to_bytes(b, p_len))
    digest.update(utils.int_to_bytes(xg, p_len))
    digest.update(utils.int_to_bytes(yg, p_len))
    digest.update(utils.int_to_bytes(public_numbers.x, p_len))
    digest.update(utils.int_to_bytes(public_numbers.y, p_len))
    return digest.finalize()


class Prehashed(object):
    def __init__(self, algorithm: hashes.HashAlgorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError("Expected instance of HashAlgorithm.")

        self._algorithm = algorithm
        self._digest_size = algorithm.digest_size

    digest_size = property(lambda self: self._digest_size)
