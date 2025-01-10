from pyasn1.type.univ import ObjectIdentifier


# top-level OID arcs

nistAlgorithms = ObjectIdentifier("2.16.840.1.101.3.4")

sigAlgs = nistAlgorithms + (3,)

kems = nistAlgorithms + (4,)

# ML-DSA

id_ml_dsa_44 = sigAlgs + (17,)

id_ml_dsa_65 = sigAlgs + (18,)

id_ml_dsa_87 = sigAlgs + (19,)

MLDSA_OIDS = {
    id_ml_dsa_44,
    id_ml_dsa_65,
    id_ml_dsa_87,
}

# HashML-DSA

id_hash_ml_dsa_44_with_sha512 = sigAlgs + (32,)

id_hash_ml_dsa_65_with_sha512 = sigAlgs + (33,)

id_hash_ml_dsa_87_with_sha512 = sigAlgs + (34,)

HASH_MLDSA_OIDS = {
    id_hash_ml_dsa_44_with_sha512,
    id_hash_ml_dsa_65_with_sha512,
    id_hash_ml_dsa_87_with_sha512,
}

# SLH-DSA

id_slh_dsa_sha2_128s = sigAlgs + (20,)

id_slh_dsa_sha2_128f = sigAlgs + (21,)

id_slh_dsa_sha2_192s = sigAlgs + (22,)

id_slh_dsa_sha2_192f = sigAlgs + (23,)

id_slh_dsa_sha2_256s = sigAlgs + (24,)

id_slh_dsa_sha2_256f = sigAlgs + (25,)

id_slh_dsa_shake_128s = sigAlgs + (26,)

id_slh_dsa_shake_128f = sigAlgs + (27,)

id_slh_dsa_shake_192s = sigAlgs + (28,)

id_slh_dsa_shake_192f = sigAlgs + (29,)

id_slh_dsa_shake_256s = sigAlgs + (30,)

id_slh_dsa_shake_256f = sigAlgs + (31,)

SLHDSA_OIDS = {
    id_slh_dsa_sha2_128s,
    id_slh_dsa_sha2_128f,
    id_slh_dsa_sha2_192s,
    id_slh_dsa_sha2_192f,
    id_slh_dsa_sha2_256s,
    id_slh_dsa_sha2_256f,
    id_slh_dsa_shake_128s,
    id_slh_dsa_shake_128f,
    id_slh_dsa_shake_192s,
    id_slh_dsa_shake_192f,
    id_slh_dsa_shake_256s,
    id_slh_dsa_shake_256f,
}

# HashSLH-DSA

id_hash_slh_dsa_sha2_128s_with_sha256 = sigAlgs + (35,)

id_hash_slh_dsa_sha2_128f_with_sha256 = sigAlgs + (36,)

id_hash_slh_dsa_sha2_192s_with_sha512 = sigAlgs + (37,)

id_hash_slh_dsa_sha2_192f_with_sha512 = sigAlgs + (38,)

id_hash_slh_dsa_sha2_256s_with_sha512 = sigAlgs + (39,)

id_hash_slh_dsa_sha2_256f_with_sha512 = sigAlgs + (40,)

id_hash_slh_dsa_shake_128s_with_shake128 = sigAlgs + (41,)

id_hash_slh_dsa_shake_128f_with_shake128 = sigAlgs + (42,)

id_hash_slh_dsa_shake_192s_with_shake256 = sigAlgs + (43,)

id_hash_slh_dsa_shake_192f_with_shake256 = sigAlgs + (44,)

id_hash_slh_dsa_shake_256s_with_shake256 = sigAlgs + (45,)

id_hash_slh_dsa_shake_256f_with_shake256 = sigAlgs + (46,)

HASH_SLHDSA_OIDS = {
    id_hash_slh_dsa_sha2_128s_with_sha256,
    id_hash_slh_dsa_sha2_128f_with_sha256,
    id_hash_slh_dsa_sha2_192s_with_sha512,
    id_hash_slh_dsa_sha2_192f_with_sha512,
    id_hash_slh_dsa_sha2_256s_with_sha512,
    id_hash_slh_dsa_sha2_256f_with_sha512,
    id_hash_slh_dsa_shake_128s_with_shake128,
    id_hash_slh_dsa_shake_128f_with_shake128,
    id_hash_slh_dsa_shake_192s_with_shake256,
    id_hash_slh_dsa_shake_192f_with_shake256,
    id_hash_slh_dsa_shake_256s_with_shake256,
    id_hash_slh_dsa_shake_256f_with_shake256,
}

# ML-KEM

id_alg_ml_kem_512 = kems + (1,)

id_alg_ml_kem_768 = kems + (2,)

id_alg_ml_kem_1024 = kems + (3,)

MLKEM_OIDS = {
    id_alg_ml_kem_512,
    id_alg_ml_kem_768,
    id_alg_ml_kem_1024,
}
