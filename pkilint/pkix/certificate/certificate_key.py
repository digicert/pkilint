import binascii
from typing import NamedTuple, Set, Optional

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc8410, rfc3279, rfc5480

from pkilint import validation, util, document
from pkilint.itu import bitstring
from pkilint.nist.asn1 import csor
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
    class KeyUsageBitsAndValidationFindingPair(NamedTuple):
        key_usage_bits: Set[str]
        validation_finding: validation.ValidationFinding

    class AlgorithmKeyUsageRequirement(NamedTuple):
        allowed: "SpkiKeyUsageConsistencyValidator.KeyUsageBitsAndValidationFindingPair"
        required: Optional[
            "SpkiKeyUsageConsistencyValidator.KeyUsageBitsAndValidationFindingPair"
        ]

    VALIDATION_RSA_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_rsa",
    )

    VALIDATION_EC_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_ec",
    )

    VALIDATION_EDWARDS_MISSING_REQUIRED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_required_but_missing_for_edwards_curve",
    )

    VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_edwards_curve",
    )

    VALIDATION_MLDSA_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_mldsa",
    )

    VALIDATION_HASH_MLDSA_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_hash_mldsa",
    )

    VALIDATION_SLHDSA_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_slhdsa",
    )

    VALIDATION_HASH_SLHDSA_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_hash_slhdsa",
    )

    VALIDATION_MLKEM_PROHIBITED_KEY_USAGE_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.key_usage_value_prohibited_for_mlkem",
    )

    VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "pkix.public_key_algorithm_unsupported",
    )

    _RSA = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # all bits are allowed except for keyAgreement, see RFC 4055 section 1.2
            key_usage_bits=KeyUsageBitName.all_bits() - {KeyUsageBitName.KEY_AGREEMENT},
            validation_finding=VALIDATION_RSA_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _EC = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # all bits are allowed except for keyEncipherment and dataEncipherment, see RFC 8813 section 3
            key_usage_bits=KeyUsageBitName.all_bits()
            - {KeyUsageBitName.KEY_ENCIPHERMENT, KeyUsageBitName.DATA_ENCIPHERMENT},
            validation_finding=VALIDATION_EC_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _EDWARDS_KEY_AGREEMENT = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see RFC 9295, section 3
            key_usage_bits={
                KeyUsageBitName.KEY_AGREEMENT,
                KeyUsageBitName.DECIPHER_ONLY,
                KeyUsageBitName.ENCIPHER_ONLY,
            },
            validation_finding=VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=KeyUsageBitsAndValidationFindingPair(
            # see RFC 9295, section 3
            key_usage_bits={
                KeyUsageBitName.KEY_AGREEMENT,
            },
            validation_finding=VALIDATION_EDWARDS_MISSING_REQUIRED_KEY_USAGE_VALUE,
        ),
    )

    _DIGITAL_SIGNATURE_ALGORITHM_BITS = {
        KeyUsageBitName.DIGITAL_SIGNATURE,
        KeyUsageBitName.NON_REPUDIATION,
        KeyUsageBitName.KEY_CERT_SIGN,
        KeyUsageBitName.CRL_SIGN,
    }

    _EDWARDS_DIGITAL_SIGNATURE = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see RFC 9295, section 3
            key_usage_bits=_DIGITAL_SIGNATURE_ALGORITHM_BITS,
            validation_finding=VALIDATION_EDWARDS_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _MLDSA = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see
            # https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-05.html#name-key-usage-bits
            key_usage_bits=_DIGITAL_SIGNATURE_ALGORITHM_BITS,
            validation_finding=VALIDATION_MLDSA_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _HASH_MLDSA = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see
            # https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-05.html#name-key-usage-bits
            key_usage_bits={
                KeyUsageBitName.DIGITAL_SIGNATURE,
                KeyUsageBitName.NON_REPUDIATION,
            },
            validation_finding=VALIDATION_HASH_MLDSA_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _SLHDSA = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-03.html#name-key-usage-bits
            key_usage_bits=_DIGITAL_SIGNATURE_ALGORITHM_BITS,
            validation_finding=VALIDATION_SLHDSA_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _HASH_SLHDSA = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-03.html#name-key-usage-bits
            key_usage_bits={
                KeyUsageBitName.DIGITAL_SIGNATURE,
                KeyUsageBitName.NON_REPUDIATION,
            },
            validation_finding=VALIDATION_HASH_SLHDSA_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _MLKEM = AlgorithmKeyUsageRequirement(
        allowed=KeyUsageBitsAndValidationFindingPair(
            # see https://datatracker.ietf.org/doc/html/draft-ietf-lamps-kyber-certificates-07#section-3
            key_usage_bits={KeyUsageBitName.KEY_ENCIPHERMENT},
            validation_finding=VALIDATION_MLKEM_PROHIBITED_KEY_USAGE_VALUE,
        ),
        required=None,
    )

    _KEY_USAGE_VALUE_ALLOWANCES = {}

    def __init__(self):
        validations = {self.VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM}

        for alg_allowance in self._KEY_USAGE_VALUE_ALLOWANCES.values():
            validations.add(alg_allowance.allowed.validation_finding)

            if alg_allowance.required:
                validations.add(alg_allowance.required.validation_finding)

        self._KEY_USAGE_VALUE_ALLOWANCES.update(
            {
                rfc3279.rsaEncryption: self._RSA,
                rfc5480.id_ecPublicKey: self._EC,
                **{
                    k: self._EDWARDS_KEY_AGREEMENT
                    for k in (
                        rfc8410.id_X448,
                        rfc8410.id_X25519,
                    )
                },
                **{
                    k: self._EDWARDS_DIGITAL_SIGNATURE
                    for k in (
                        rfc8410.id_Ed448,
                        rfc8410.id_Ed25519,
                    )
                },
                **{k: self._MLDSA for k in csor.MLDSA_OIDS},
                **{k: self._HASH_MLDSA for k in csor.HASH_MLDSA_OIDS},
                **{k: self._SLHDSA for k in csor.SLHDSA_OIDS},
                **{k: self._HASH_SLHDSA for k in csor.HASH_SLHDSA_OIDS},
                **{k: self._MLKEM for k in csor.MLKEM_OIDS},
            }
        )

        super().__init__(
            validations=list(validations),
            pdu_class=rfc5280.KeyUsage,
        )

    def validate(self, node):
        spki_alg_oid = node.navigate(
            ":certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm"
        ).pdu

        alg_allowances = self._KEY_USAGE_VALUE_ALLOWANCES.get(spki_alg_oid)

        if alg_allowances is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                f"Unsupported public key algorithm: {str(spki_alg_oid)}",
            )

        allowed_values_and_finding, required_values_and_finding = alg_allowances
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


class CaPrehashPublicKeyValidator(validation.Validator):
    VALIDATION_HASH_MLDSA_PROHIBITED_IN_CA_CERTIFICATE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.hash_mldsa_ca_key_prohibited"
    )

    VALIDATION_HASH_SLHDSA_PROHIBITED_IN_CA_CERTIFICATE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.hash_slhdsa_ca_key_prohibited"
    )

    _PROHIBITED_ALG_OID_TO_FINDING_MAPPINGS = {}

    def __init__(self):
        self._PROHIBITED_ALG_OID_TO_FINDING_MAPPINGS.update(
            {
                **{
                    k: self.VALIDATION_HASH_MLDSA_PROHIBITED_IN_CA_CERTIFICATE
                    for k in csor.HASH_MLDSA_OIDS
                },
                **{
                    k: self.VALIDATION_HASH_SLHDSA_PROHIBITED_IN_CA_CERTIFICATE
                    for k in csor.HASH_SLHDSA_OIDS
                },
            }
        )

        super().__init__(
            validations=[
                self.VALIDATION_HASH_MLDSA_PROHIBITED_IN_CA_CERTIFICATE,
                self.VALIDATION_HASH_SLHDSA_PROHIBITED_IN_CA_CERTIFICATE,
            ],
            pdu_class=rfc5280.SubjectPublicKeyInfo,
            predicate=lambda n: n.document.is_ca,
        )

    def validate(self, node):
        spki_alg_oid = node.navigate("algorithm.algorithm").pdu

        finding = self._PROHIBITED_ALG_OID_TO_FINDING_MAPPINGS.get(spki_alg_oid)

        if finding:
            raise validation.ValidationFindingEncountered(
                finding,
                f"Prohibited public key algorithm in CA certificate: {str(spki_alg_oid)}",
            )


class ObsoletePublicKeyAlgorithmValidator(validation.Validator):
    VALIDATION_IPD_ALGORITHM_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.public_key_nist_ipd_algorithm_present",
    )

    VALIDATION_ROUND3_ALGORITHM_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.public_key_nist_round3_algorithm_present",
    )

    _IPD_ALG_OIDS = {
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.12.4.4"),  # ML-DSA-44-ipd
        univ.ObjectIdentifier("1.1.4.1.2.267.12.6.5"),  # ML-DSA-65-ipd
        univ.ObjectIdentifier("1.1.4.1.2.267.12.8.7"),  # ML-DSA-87-ipd
        univ.ObjectIdentifier("1.3.9999.6.4.16"),  # SLH-DSA-SHA2-128s-ipd
        univ.ObjectIdentifier("1.3.9999.6.7.16"),  # SLH-DSA-SHAKE-128s-ipd
        univ.ObjectIdentifier("1.3.9999.6.4.13"),  # SLH-DSA-SHA2-128f-ipd
        univ.ObjectIdentifier("1.3.9999.6.7.13"),  # SLH-DSA-SHAKE-128f-ipd
        univ.ObjectIdentifier("1.3.9999.6.5.12"),  # SLH-DSA-SHA2-192s-ipd
        univ.ObjectIdentifier("1.3.9999.6.8.12"),  # SLH-DSA-SHAKE-192s-ipd
        univ.ObjectIdentifier("1.3.9999.6.5.10"),  # SLH-DSA-SHA2-192f-ipd
        univ.ObjectIdentifier("1.3.9999.6.8.10"),  # SLH-DSA-SHAKE-192f-ipd
        univ.ObjectIdentifier("1.3.9999.6.6.12"),  # SLH-DSA-SHA2-256s-ipd
        univ.ObjectIdentifier("1.3.9999.6.9.12"),  # SLH-DSA-SHAKE-256s-ipd
        univ.ObjectIdentifier("1.3.9999.6.6.10"),  # SLH-DSA-SHA2-256f-ipd
        univ.ObjectIdentifier("1.3.9999.6.9.10"),  # SLH-DSA-SHAKE-256f-ipd
        univ.ObjectIdentifier("1.3.6.1.4.1.22554.5.6.1"),  # ML-KEM-512-ipd
        univ.ObjectIdentifier("1.3.6.1.4.1.22554.5.6.2"),  # ML-KEM-768-ipd
        univ.ObjectIdentifier("1.3.6.1.4.1.22554.5.6.3"),  # ML-KEM-1024-ipd
    }

    _ROUND3_ALG_OIDS = {
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.7.4.4"),  # Dilithium2
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.7.6.5"),  # Dilithium3
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.7.8.7"),  # Dilithium5
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4"),  # DilithiumAES2
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.11.6.5"),  # DilithiumAES3
        univ.ObjectIdentifier("1.3.6.1.4.1.2.267.11.8.7"),  # DilithiumAES5
        univ.ObjectIdentifier("1.3.9999.3.1"),  # Falcon-512
        univ.ObjectIdentifier("1.3.9999.3.4"),  # Falcon-1024
        univ.ObjectIdentifier("1.3.9999.6.4.1"),  # SPHINCS+-SHA256-128f-robust
        univ.ObjectIdentifier("1.3.9999.6.4.4"),  # SPHINCS+-SHA256-128f-simple
        univ.ObjectIdentifier("1.3.9999.6.4.7"),  # SPHINCS+-SHA256-128s-robust
        univ.ObjectIdentifier("1.3.9999.6.4.10"),  # SPHINCS+-SHA256-128s-simple
        univ.ObjectIdentifier("1.3.9999.6.5.1"),  # SPHINCS+-SHA256-192f-robust
        univ.ObjectIdentifier("1.3.9999.6.5.3"),  # SPHINCS+-SHA256-192f-simple
        univ.ObjectIdentifier("1.3.9999.6.5.5"),  # SPHINCS+-SHA256-192s-robust
        univ.ObjectIdentifier("1.3.9999.6.5.7"),  # SPHINCS+-SHA256-192s-simple
        univ.ObjectIdentifier("1.3.9999.6.6.1"),  # SPHINCS+-SHA256-256f-robust
        univ.ObjectIdentifier("1.3.9999.6.6.3"),  # SPHINCS+-SHA256-256f-simple
        univ.ObjectIdentifier("1.3.9999.6.6.5"),  # SPHINCS+-SHA256-256s-robust
        univ.ObjectIdentifier("1.3.9999.6.6.7"),  # SPHINCS+-SHA256-256s-simple
        univ.ObjectIdentifier("1.3.6.1.4.1.22554.5.6.4"),  # kyber512_aes
        univ.ObjectIdentifier("1.3.6.1.4.1.22554.5.6.5"),  # kyber768_aes
        univ.ObjectIdentifier("1.3.6.1.4.1.22554.5.6.6"),  # kyber1024_aes
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_IPD_ALGORITHM_PRESENT,
                self.VALIDATION_ROUND3_ALGORITHM_PRESENT,
            ],
            pdu_class=rfc5280.SubjectPublicKeyInfo,
        )

    def validate(self, node):
        spki_alg_oid = node.navigate("algorithm.algorithm").pdu

        if spki_alg_oid in self._IPD_ALG_OIDS:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_IPD_ALGORITHM_PRESENT,
                f"Obsolete NIST IPD public key algorithm: {str(spki_alg_oid)}",
            )

        if spki_alg_oid in self._ROUND3_ALG_OIDS:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ROUND3_ALGORITHM_PRESENT,
                f"Obsolete NIST Round 3 public key algorithm: {str(spki_alg_oid)}",
            )
