import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc3279, rfc5480, rfc8410

from pkilint import validation, util, document
from pkilint.document import PDUNode

SUBJECT_PUBLIC_KEY_ALGORITHM_IDENTIFIER_MAPPINGS = {
    rfc3279.rsaEncryption: rfc5480.RSAPublicKey(),
    rfc5480.id_ecPublicKey: rfc5480.ECPoint(),
    rfc5480.id_ecDH: rfc5480.ECPoint(),
    rfc5480.id_ecMQV: rfc5480.ECPoint(),
}

SUBJECT_KEY_PARAMETER_ALGORITHM_IDENTIFIER_MAPPINGS = {
    rfc3279.rsaEncryption: univ.Null(),
    rfc5480.id_ecPublicKey: rfc5480.ECParameters(),
    rfc5480.id_ecDH: rfc5480.ECParameters(),
    rfc5480.id_ecMQV: rfc5480.ECParameters(),
    **{o: document.ValueDecoder.VALUE_NODE_ABSENT for o in (
        rfc8410.id_Ed448,
        rfc8410.id_Ed25519,
        rfc8410.id_X448,
        rfc8410.id_X25519,
    )}
}

EC_CURVE_OID_TO_OBJECT_MAPPINGS = {
    rfc5480.secp256r1: ec.SECP256R1(),
    rfc5480.secp384r1: ec.SECP384R1(),
    rfc5480.secp521r1: ec.SECP521R1(),
}


def convert_spki_to_object(spki_node: PDUNode):
    key_type = spki_node.navigate('algorithm.algorithm').pdu

    if key_type == rfc3279.rsaEncryption:
        modulus = spki_node.navigate(
            'subjectPublicKey.rSAPublicKey.modulus'
        ).pdu
        exponent = spki_node.navigate(
            'subjectPublicKey.rSAPublicKey.exponent'
        ).pdu

        return rsa.RSAPublicNumbers(int(modulus), int(exponent)).public_key()
    elif key_type in {rfc5480.id_ecPublicKey, rfc5480.id_ecDH, rfc5480.id_ecMQV}:
        curve_oid = spki_node.navigate(
            'algorithm.parameters.eCParameters.namedCurve'
        ).pdu

        curve = EC_CURVE_OID_TO_OBJECT_MAPPINGS.get(curve_oid)
        if curve is not None:
            return ec.EllipticCurvePublicKey.from_encoded_point(
                curve, spki_node.navigate('subjectPublicKey').pdu.asOctets()
            )

    # TODO: DSA
    return None


class SubjectPublicKeyDecoder(document.ValueDecoder):
    def __init__(self, *, type_mappings):
        super().__init__(type_path='algorithm.algorithm',
                         value_path='subjectPublicKey', type_mappings=type_mappings
                         )

    def filter_value(self, node, type_node, value_node, pdu_type):
        if isinstance(pdu_type, rfc5480.ECPoint):
            # wrap the BIT STRING in an OCTET STRING
            octet_str = univ.OctetString(value_node.pdu.asOctets())

            return encode(octet_str)
        else:
            return super().filter_value(node, type_node, value_node, pdu_type)


class SubjectPublicKeyDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(pdu_class=rfc5280.SubjectPublicKeyInfo,
                         decode_func=decode_func,
                         **kwargs
                         )


class SubjectPublicKeyParametersDecoder(document.ValueDecoder):
    def __init__(self, *, type_mappings):
        super().__init__(type_path='algorithm.algorithm',
                         value_path='algorithm.parameters', type_mappings=type_mappings
                         )


class SubjectPublicKeyParametersDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(pdu_class=rfc5280.SubjectPublicKeyInfo,
                         decode_func=decode_func,
                         **kwargs
                         )


def _calculate_method2_hash(sha1_hash):
    last_8_octets = bytearray(sha1_hash[12:])
    last_8_octets[0] = 0x40 | (last_8_octets[0] & 0xF)

    return bytes(last_8_octets)


class SubjectKeyIdentifierValidator(validation.Validator):
    VALIDATION_UNKNOWN_METHOD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'pkix.unknown_subject_key_identifier_calculation_method'
    )

    VALIDATION_METHOD_1 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        'pkix.subject_key_identifier_method_1_identified'
    )

    VALIDATION_METHOD_2 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        'pkix.subject_key_identifier_method_2_identified'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_UNKNOWN_METHOD,
                self.VALIDATION_METHOD_1,
                self.VALIDATION_METHOD_2,
            ],
            pdu_class=rfc5280.SubjectKeyIdentifier
        )

    def validate(self, node):
        public_key_node = node.document.root.navigate(
            'tbsCertificate.subjectPublicKeyInfo.subjectPublicKey'
        )

        public_key_bytes = public_key_node.pdu.asOctets()
        public_key_sha1 = util.calculate_sha1_hash(public_key_bytes)

        method2_hash = _calculate_method2_hash(public_key_sha1)

        identifier_octets = bytes(node.pdu)

        if public_key_sha1 == identifier_octets:
            finding = self.VALIDATION_METHOD_1
        elif method2_hash == identifier_octets:
            finding = self.VALIDATION_METHOD_2
        else:
            finding = self.VALIDATION_UNKNOWN_METHOD

        raise validation.ValidationFindingEncountered(finding)


def _verify_signature(public_key, message, signature,
                      signature_algorithm):
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                signature_algorithm
            )
        else:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(signature_algorithm)
            )

        return True
    except InvalidSignature:
        return False


class SubjectSignatureVerificationValidator(validation.Validator):
    VALIDATION_SIGNATURE_MISMATCH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.signature_verification_failed'
    )

    def __init__(self, *, tbs_node_retriever, **kwargs):
        super().__init__(validations=[self.VALIDATION_SIGNATURE_MISMATCH],
                         **kwargs
                         )

        self._tbs_node_retriever = tbs_node_retriever

    def validate(self, node):
        issuer_cert_doc = document.get_document_by_name(node, 'issuer')

        issuer_crypto_cert = issuer_cert_doc.cryptography_object
        subject_crypto_doc = node.document.cryptography_object
        public_key = issuer_crypto_cert.public_key()

        tbs_octets = encode(self._tbs_node_retriever(node).pdu)

        if not _verify_signature(public_key, tbs_octets,
                                 node.pdu.asOctets(),
                                 subject_crypto_doc.signature_hash_algorithm):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SIGNATURE_MISMATCH
            )


class AllowedPublicKeyAlgorithmEncodingValidator(validation.Validator):
    def __init__(self, *, validation, allowed_encodings, **kwargs):
        super().__init__(
            validations=[validation],
            **kwargs
        )

        self._allowed_encodings = allowed_encodings

    def validate(self, node):
        encoded = encode(node.pdu)

        if encoded not in self._allowed_encodings:
            encoded_str = binascii.hexlify(encoded).decode('us-ascii')

            raise validation.ValidationFindingEncountered(
                self._validations[0],
                f'Prohibited encoding: {encoded_str}'
            )
