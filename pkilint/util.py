from cryptography.hazmat.primitives import hashes


def calculate_hash(octets: bytes, hash_algo: hashes.HashAlgorithm) -> bytes:
    h = hashes.Hash(hash_algo)
    h.update(octets)

    return h.finalize()


def calculate_sha1_hash(octets: bytes) -> bytes:
    return calculate_hash(octets, hashes.SHA1())
