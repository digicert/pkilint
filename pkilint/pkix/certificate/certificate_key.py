import binascii

from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from pkilint import validation, util, document
from pkilint.pkix.key import verify_signature


class SubjectPublicKeyDecoder(document.ValueDecoder):
    def __init__(self, *, type_mappings):
        super().__init__(
            type_path="algorithm.algorithm",
            value_path="subjectPublicKey",
            type_mappings=type_mappings,
        )

    def decode_value(self, node, type_node, value_node, pdu_type):
        if isinstance(pdu_type, univ.OctetString):
            # map the BIT STRING into an OCTET STRING
            try:
                pdu = pdu_type.clone(value=value_node.pdu.asOctets())
            except PyAsn1Error as e:
                # bubble up any constraint violations
                raise document.SubstrateDecodingFailedError(
                    value_node.document, pdu_type, value_node, str(e)
                )

            return document.create_and_append_node_from_pdu(
                value_node.document, pdu, value_node
            )
        else:
            return super().decode_value(node, type_node, value_node, pdu_type)


class SubjectPublicKeyDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(
            pdu_class=rfc5280.SubjectPublicKeyInfo, decode_func=decode_func, **kwargs
        )


class SubjectPublicKeyParametersDecoder(document.ValueDecoder):
    def __init__(self, *, type_mappings):
        super().__init__(
            type_path="algorithm.algorithm",
            value_path="algorithm.parameters",
            type_mappings=type_mappings,
        )


class SubjectPublicKeyParametersDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(
            pdu_class=rfc5280.SubjectPublicKeyInfo, decode_func=decode_func, **kwargs
        )


class SubjectKeyIdentifierValidator(validation.Validator):
    VALIDATION_UNKNOWN_METHOD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "pkix.unknown_subject_key_identifier_calculation_method",
    )

    # TODO: consider renaming the finding code after weighing risk of user breakage
    VALIDATION_METHOD_1 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        "pkix.subject_key_identifier_method_1_identified",
    )

    # TODO: consider renaming the finding code after weighing risk of user breakage
    VALIDATION_METHOD_2 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        "pkix.subject_key_identifier_method_2_identified",
    )

    VALIDATION_RFC7093_METHOD_1 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        "pkix.subject_key_identifier_rfc7093_method_1_identified",
    )

    VALIDATION_RFC7093_METHOD_2 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        "pkix.subject_key_identifier_rfc7093_method_2_identified",
    )

    VALIDATION_RFC7093_METHOD_3 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        "pkix.subject_key_identifier_rfc7093_method_3_identified",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_UNKNOWN_METHOD,
                self.VALIDATION_METHOD_1,
                self.VALIDATION_METHOD_2,
                self.VALIDATION_RFC7093_METHOD_1,
                self.VALIDATION_RFC7093_METHOD_2,
                self.VALIDATION_RFC7093_METHOD_3,
            ],
            pdu_class=rfc5280.SubjectKeyIdentifier,
        )

    @staticmethod
    def _calculate_rfc5280_method2_id(sha1_hash):
        last_8_octets = bytearray(sha1_hash[12:])
        last_8_octets[0] = 0x40 | (last_8_octets[0] & 0xF)

        return bytes(last_8_octets)

    _RFC7093_HASH_CLS_TO_FINDINGS = {
        hashes.SHA256: VALIDATION_RFC7093_METHOD_1,
        hashes.SHA384: VALIDATION_RFC7093_METHOD_2,
        hashes.SHA512: VALIDATION_RFC7093_METHOD_3,
    }

    # TODO: support RFC 7093 method 4
    @staticmethod
    def _calculate_rfc7093_method_hash(public_key_octets, hash_cls):
        h = util.calculate_hash(public_key_octets, hash_cls())

        # leftmost 160 bits (i.e., 20 octets)
        return h[:20]

    def validate(self, node):
        public_key_node = node.document.root.navigate(
            "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey"
        )

        public_key_octets = public_key_node.pdu.asOctets()

        identifier_octets = bytes(node.pdu)

        public_key_sha1 = util.calculate_sha1_hash(public_key_octets)

        if identifier_octets == public_key_sha1:
            finding = self.VALIDATION_METHOD_1
        elif (
            identifier_octets
            == SubjectKeyIdentifierValidator._calculate_rfc5280_method2_id(
                public_key_sha1
            )
        ):
            finding = self.VALIDATION_METHOD_2
        else:
            finding = next(
                (
                    f
                    for h, f in SubjectKeyIdentifierValidator._RFC7093_HASH_CLS_TO_FINDINGS.items()
                    if SubjectKeyIdentifierValidator._calculate_rfc7093_method_hash(
                        public_key_octets, h
                    )
                    == identifier_octets
                ),
                self.VALIDATION_UNKNOWN_METHOD,
            )

        raise validation.ValidationFindingEncountered(finding)


class SubjectSignatureVerificationValidator(validation.Validator):
    VALIDATION_SIGNATURE_MISMATCH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.signature_verification_failed"
    )

    VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "pkix.unsupported_public_key_algorithm",
    )

    def __init__(self, *, tbs_node_retriever, **kwargs):
        super().__init__(
            validations=[
                self.VALIDATION_SIGNATURE_MISMATCH,
                self.VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            ],
            **kwargs,
        )

        self._tbs_node_retriever = tbs_node_retriever

    def validate(self, node):
        issuer_cert_doc = document.get_document_by_name(node, "issuer")

        public_key = issuer_cert_doc.public_key_object
        if public_key is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM
            )

        subject_crypto_doc = node.document.cryptography_object

        tbs_octets = encode(self._tbs_node_retriever(node).pdu)

        if not verify_signature(
            public_key,
            tbs_octets,
            node.pdu.asOctets(),
            subject_crypto_doc.signature_hash_algorithm,
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SIGNATURE_MISMATCH
            )


class AllowedPublicKeyAlgorithmEncodingValidator(validation.Validator):
    def __init__(self, *, validation, allowed_encodings, **kwargs):
        super().__init__(validations=[validation], **kwargs)

        self._allowed_encodings = allowed_encodings

    def validate(self, node):
        encoded = encode(node.pdu)

        if encoded not in self._allowed_encodings:
            encoded_str = binascii.hexlify(encoded).decode("us-ascii")

            raise validation.ValidationFindingEncountered(
                self._validations[0], f"Prohibited encoding: {encoded_str}"
            )
