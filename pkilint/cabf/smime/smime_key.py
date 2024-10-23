import binascii

from pyasn1_alt_modules import rfc3279

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
            "304106092a864886f70d01010a3034a00f300d060960864801650"
            "30402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
            # RSASSA‐PSS with SHA‐384, MGF‐1 with SHA‐384, and a salt length of 48 bytes
            "304106092a864886f70d01010a3034a00f300d060960864801650"
            "30402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130",
            # RSASSA‐PSS with SHA‐512, MGF‐1 with SHA‐512, and a salt length of 64 bytes
            "304106092a864886f70d01010a3034a00f300d060960864801650"
            "30402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140",
            # ECDSA with SHA‐256
            "300a06082a8648ce3d040302",
            # ECDSA with SHA‐384
            "300a06082a8648ce3d040303",
            # Ed25519
            "300506032b6570",
            # Ed448
            "300506032b6571",
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
            # Ed25519
            "300506032b6570",
            # Ed448
            "300506032b6571",
        ],
    )
)


class SmimeAllowedSignatureAlgorithmEncodingValidator(
    algorithm.AllowedSignatureAlgorithmEncodingValidator
):
    VALIDATION_PROHIBITED_SIGNATURE_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.prohibited_signature_algorithm_encoding",
    )

    def __init__(self, **kwargs):
        super().__init__(
            validation=self.VALIDATION_PROHIBITED_SIGNATURE_ALGORITHM,
            allowed_encodings=ALLOWED_SIGNATURE_ALGORITHM_ENCODINGS,
            **kwargs,
        )


class SmimeAllowedPublicKeyAlgorithmEncodingValidator(
    certificate_key.AllowedPublicKeyAlgorithmEncodingValidator
):
    VALIDATION_PROHIBITED_KEY_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.prohibited_spki_algorithm_encoding",
    )

    def __init__(self, **kwargs):
        super().__init__(
            validation=self.VALIDATION_PROHIBITED_KEY_ALGORITHM,
            allowed_encodings=ALLOWED_SPKI_ENCODINGS,
            **kwargs,
        )


class GmailAllowedModulusLengthValidator(validation.Validator):
    VALIDATION_PROHIBITED_RSA_MODULUS_LENGTH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "googl.prohibited_rsa_modulus_length",
    )

    _ALLOWED_LENGTHS = {2048, 3072, 4096}

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_PROHIBITED_RSA_MODULUS_LENGTH],
            pdu_class=rfc3279.RSAPublicKey,
        )

    def validate(self, node):
        modulus_length = int(node.children["modulus"].pdu).bit_length()

        if modulus_length not in self._ALLOWED_LENGTHS:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_RSA_MODULUS_LENGTH,
                f"Prohibited RSA modulus length: {modulus_length}",
            )
