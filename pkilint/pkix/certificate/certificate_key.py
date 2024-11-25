import binascii

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc8410, rfc3279, rfc5480

from pkilint import validation, util, document
from pkilint.itu import bitstring
from pkilint.pkix.certificate.certificate_extension import KeyUsageBitName
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

    VALIDATION_UNSUPPORTED_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "pkix.unsupported_algorithm",
    )

    def __init__(self, *, tbs_node_retriever, **kwargs):
        super().__init__(
            validations=[
                self.VALIDATION_SIGNATURE_MISMATCH,
                self.VALIDATION_UNSUPPORTED_ALGORITHM,
            ],
            **kwargs,
        )

        self._tbs_node_retriever = tbs_node_retriever

    def validate(self, node):
        issuer_cert_doc = document.get_document_by_name(node, "issuer")

        public_key = issuer_cert_doc.public_key_object
        if public_key is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSUPPORTED_ALGORITHM
            )

        subject_crypto_doc = node.document.cryptography_object

        tbs_octets = encode(self._tbs_node_retriever(node).pdu)

        try:
            if not verify_signature(
                public_key,
                tbs_octets,
                node.pdu.asOctets(),
                subject_crypto_doc.signature_hash_algorithm,
            ):
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_SIGNATURE_MISMATCH
                )
        except exceptions.UnsupportedAlgorithm:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSUPPORTED_ALGORITHM
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


class SpkiKeyUsageConsistencyValidator(validation.Validator):
    # all bits are allowed except for keyAgreement, see RFC 4055 section 1.2
    _RSA_ALLOWED_KEY_USAGES = {
        KeyUsageBitName.DIGITAL_SIGNATURE,
        KeyUsageBitName.NON_REPUDIATION,
        KeyUsageBitName.KEY_CERT_SIGN,
        KeyUsageBitName.CRL_SIGN,
        KeyUsageBitName.KEY_ENCIPHERMENT,
        KeyUsageBitName.DATA_ENCIPHERMENT,
        KeyUsageBitName.DECIPHER_ONLY,
        KeyUsageBitName.ENCIPHER_ONLY,
    }
    VALIDATION_RSA_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_rsa",
    )

    # all bits are allowed except for keyEncipherment and dataEncipherment, see RFC 8813 section 3
    _EC_ALLOWED_KEY_USAGES = {
        KeyUsageBitName.DIGITAL_SIGNATURE,
        KeyUsageBitName.NON_REPUDIATION,
        KeyUsageBitName.KEY_CERT_SIGN,
        KeyUsageBitName.CRL_SIGN,
        KeyUsageBitName.KEY_AGREEMENT,
        KeyUsageBitName.DECIPHER_ONLY,
        KeyUsageBitName.ENCIPHER_ONLY,
    }
    VALIDATION_EC_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_ec",
    )

    # see RFC 9295, section 3
    _X448_AND_X25519_REQUIRED_KEY_USAGES = {
        KeyUsageBitName.KEY_AGREEMENT,
    }
    VALIDATION_EDWARDS_MISSING_REQUIRED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_required_but_missing_for_edwards_curve",
    )

    _X448_AND_X25519_ALLOWED_KEY_USAGES = {
        KeyUsageBitName.KEY_AGREEMENT,
        KeyUsageBitName.DECIPHER_ONLY,
        KeyUsageBitName.ENCIPHER_ONLY,
    }
    VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_edwards_curve",
    )

    _SIGNATURE_ALGORITHM_ALLOWED_KEY_USAGES = {
        KeyUsageBitName.DIGITAL_SIGNATURE,
        KeyUsageBitName.NON_REPUDIATION,
        KeyUsageBitName.KEY_CERT_SIGN,
        KeyUsageBitName.CRL_SIGN,
    }
    VALIDATION_SIGNATURE_ALGORITHM_PROHIBITED_KEY_USAGE_VALUE = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "pkix.key_usage_value_prohibited_for_signature_algorithm",
        )
    )

    # _KEM_ALLOWED_KEY_USAGES = {KeyUsageBitName.KEY_ENCIPHERMENT}
    # VALIDATION_KEM_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
    #    validation.ValidationFindingSeverity.ERROR,
    #    "pkix.prohibited_key_usage_value_kem",
    # )

    VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "pkix.public_key_algorithm_unsupported",
    )

    _KEY_USAGE_VALUE_ALLOWANCES = {
        rfc3279.rsaEncryption: (
            (_RSA_ALLOWED_KEY_USAGES, VALIDATION_RSA_PROHIBITED_KEY_USAGE_VALUE),
            None,
        ),
        rfc5480.id_ecPublicKey: (
            (_EC_ALLOWED_KEY_USAGES, VALIDATION_EC_PROHIBITED_KEY_USAGE_VALUE),
            None,
        ),
        rfc8410.id_X448: (
            (
                _X448_AND_X25519_ALLOWED_KEY_USAGES,
                VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE,
            ),
            (
                _X448_AND_X25519_REQUIRED_KEY_USAGES,
                VALIDATION_EDWARDS_MISSING_REQUIRED_KEY_USAGE_VALUE,
            ),
        ),
        rfc8410.id_X25519: (
            (
                _X448_AND_X25519_ALLOWED_KEY_USAGES,
                VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE,
            ),
            (
                _X448_AND_X25519_REQUIRED_KEY_USAGES,
                VALIDATION_EDWARDS_MISSING_REQUIRED_KEY_USAGE_VALUE,
            ),
        ),
        rfc8410.id_Ed448: (
            (
                _SIGNATURE_ALGORITHM_ALLOWED_KEY_USAGES,
                VALIDATION_SIGNATURE_ALGORITHM_PROHIBITED_KEY_USAGE_VALUE,
            ),
            None,
        ),
        rfc8410.id_Ed25519: (
            (
                _SIGNATURE_ALGORITHM_ALLOWED_KEY_USAGES,
                VALIDATION_SIGNATURE_ALGORITHM_PROHIBITED_KEY_USAGE_VALUE,
            ),
            None,
        ),
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                self.VALIDATION_EC_PROHIBITED_KEY_USAGE_VALUE,
                self.VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE,
                self.VALIDATION_EDWARDS_MISSING_REQUIRED_KEY_USAGE_VALUE,
                self.VALIDATION_RSA_PROHIBITED_KEY_USAGE_VALUE,
                self.VALIDATION_SIGNATURE_ALGORITHM_PROHIBITED_KEY_USAGE_VALUE,
            ],
            pdu_class=rfc5280.KeyUsage,
        )

    def validate(self, node):
        spki_alg_oid = node.navigate(
            ":certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm"
        ).pdu

        allowances = self._KEY_USAGE_VALUE_ALLOWANCES.get(spki_alg_oid)

        if allowances is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                f"Unsupported public key algorithm: {str(spki_alg_oid)}",
            )

        allowed_values_and_finding, required_values_and_finding = allowances
        allowed_values, prohibited_finding = allowed_values_and_finding

        bit_set = bitstring.get_asserted_bit_set(node)

        prohibited_bits = bit_set - allowed_values

        if any(prohibited_bits):
            prohibited_ku_names = ", ".join(sorted(prohibited_bits))

            raise validation.ValidationFindingEncountered(
                prohibited_finding,
                f"Prohibited key usage value(s) present: {prohibited_ku_names}",
            )

        if required_values_and_finding is not None:
            required_values, missing_finding = required_values_and_finding

            missing_kus = required_values - bit_set

            if any(missing_kus):
                missing_ku_names = ", ".join(sorted(missing_kus))

                raise validation.ValidationFindingEncountered(
                    missing_finding,
                    f"Required key usage value(s) missing: {missing_ku_names}",
                )
