from cryptography.hazmat.primitives import hashes
from pyasn1_alt_modules import rfc6960

from pkilint import validation


class OCSPBasicResponseCertsNotPresentValidator(validation.Validator):
    VALIDATION_CERTS_IS_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "pkix.ocsp_certs_sequence_is_empty",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_CERTS_IS_EMPTY],
            pdu_class=rfc6960.BasicOCSPResponse,
        )

    def validate(self, node):
        certs_node = node.children.get("certs")

        if certs_node is not None and len(certs_node.children) == 0:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CERTS_IS_EMPTY
            )


class ResponderKeyHashIsSHA1HashValidator(validation.Validator):
    VALIDATION_KEY_HASH_IS_NOT_SHA1 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.ocsp_responderid_keyhash_is_not_sha1",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_KEY_HASH_IS_NOT_SHA1],
            pdu_class=rfc6960.ResponderID,
            predicate=lambda n: "byKey" in n.children,
        )

    def validate(self, node):
        _, by_key_node = node.child

        hash_octets = by_key_node.pdu.asOctets()
        hash_len = len(hash_octets)

        if hash_len != hashes.SHA1.digest_size:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_KEY_HASH_IS_NOT_SHA1,
                f"Key hash length of {hash_len} octets is not SHA-1",
            )
