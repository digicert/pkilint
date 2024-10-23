import binascii

from pkilint import validation
from pkilint.pkix import algorithm
from pkilint.pkix.certificate import certificate_key

ALLOWED_SIGNATURE_ALGORITHM_ENCODINGS = set(
    map(
        binascii.a2b_hex,
        [
            # RSASSA‐PKCS1‐v1_5 with SHA‐256
            "300d06092a864886f70d01010b0500",
            # RSASSA‐PKCS1‐v1_5 with SHA‐384
            "300d06092a864886f70d01010c0500",
            # RSASSA‐PKCS1‐v1_5 with SHA‐512
            "300d06092a864886f70d01010d0500",
            # RSASSA‐PSS with SHA‐256, MGF‐1 with SHA‐256, and a salt length of 32 bytes
            "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
            # RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
            "304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130",
            # RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
            "304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140",
            # ECDSA with SHA‐256
            "300a06082a8648ce3d040302",
            # ECDSA with SHA‐384
            "300a06082a8648ce3d040303",
            # ECDSA with SHA‐512
            "300a06082a8648ce3d040304",
        ],
    )
)

ALLOWED_SPKI_ENCODINGS = set(
    map(
        binascii.a2b_hex,
        [
            # RSA
            "300d06092a864886f70d0101010500",
            # ECDSA P-256
            "301306072a8648ce3d020106082a8648ce3d030107",
            # ECDSA P-384
            "301006072a8648ce3d020106052b81040022",
            # ECDSA P-521
            "301006072a8648ce3d020106052b81040023",
        ],
    )
)


class ServerauthAllowedSignatureAlgorithmEncodingValidator(
    algorithm.AllowedSignatureAlgorithmEncodingValidator
):
    """Validates that the signature algorithm conforms with BR 7.1.3.2."""

    VALIDATION_DISALLOWED_SIGNATURE_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.prohibited_signature_algorithm_encoding",
    )

    def __init__(self, **kwargs):
        super().__init__(
            validation=self.VALIDATION_DISALLOWED_SIGNATURE_ENCODING,
            allowed_encodings=ALLOWED_SIGNATURE_ALGORITHM_ENCODINGS,
            **kwargs
        )


class ServerauthAllowedPublicKeyAlgorithmEncodingValidator(
    certificate_key.AllowedPublicKeyAlgorithmEncodingValidator
):
    """Validates that subject public key algorithm conforms with BR 7.1.3.1."""

    VALIDATION_DISALLOWED_PUBKEY_ALG_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.prohibited_subject_public_key_algorithm_encoding",
    )

    def __init__(self, **kwargs):
        super().__init__(
            validation=self.VALIDATION_DISALLOWED_PUBKEY_ALG_ENCODING,
            allowed_encodings=ALLOWED_SPKI_ENCODINGS,
            **kwargs
        )
