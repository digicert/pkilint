import enum
from typing import NamedTuple, List

from pyasn1_alt_modules import rfc6962

from pkilint import validation


class HashAlgorithm(enum.IntEnum):
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SignatureAlgorithm(enum.IntEnum):
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


class SignedCertificateTimestamp(NamedTuple):
    sct_version: int
    log_id: bytes
    timestamp_msec: int
    extensions: bytes
    hash_alg: HashAlgorithm
    sig_alg: SignatureAlgorithm
    signature: bytes
    raw: bytes


# Thank you JHA
# https://letsencrypt.org/2018/04/04/sct-encoding.html
def _decode_sct(octets: bytes, offset: int):
    initial_offset = offset

    length = int.from_bytes(octets[offset:offset + 2], 'big')
    offset += 2

    version = octets[offset]
    offset += 1

    log_id = octets[offset:offset + 32]
    offset += 32

    timestamp = int.from_bytes(octets[offset: offset + 8], 'big')
    offset += 8

    extensions_length = int.from_bytes(octets[offset: offset + 2], 'big')
    offset += 2

    extensions = b'' if extensions_length == 0 else octets[offset:offset + extensions_length]
    offset += extensions_length

    raw = octets[initial_offset:offset]

    hash_alg = HashAlgorithm(octets[offset])
    offset += 1

    sig_alg = SignatureAlgorithm(octets[offset])
    offset += 1

    signature_length = int.from_bytes(octets[offset:offset + 2], 'big')
    offset += 2

    signature_octets = octets[offset:offset + signature_length]
    offset += signature_length

    return offset, SignedCertificateTimestamp(
        version, log_id, timestamp, extensions, hash_alg, sig_alg, signature_octets, raw)


def _decode(instance) -> List[SignedCertificateTimestamp]:
    if hasattr(instance, 'decoded'):
        return instance.decoded

    octets = instance.asOctets()

    expected_length = int.from_bytes(octets[0:2], 'big')
    offset = 2

    actual_length = len(octets) - 2

    if actual_length != expected_length:
        raise ValueError('Invalid SCT list encoding: '
                         f'expected length: {expected_length}, actual length: {actual_length}')

    scts = []
    while offset < actual_length:
        offset, sct = _decode_sct(octets, offset)

        scts.append(sct)

    setattr(instance, 'decoded', scts)


class SctListExtensionDecodingValidator(validation.Validator):
    VALIDATION_SCT_EXTENSION_INVALID_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.FATAL,
        'pkix.sct_list_extension_invalid_encoding'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_SCT_EXTENSION_INVALID_ENCODING,
                         pdu_class=rfc6962.SignedCertificateTimestampList)

    def validate(self, node):
        try:
            _ = _decode(node.pdu)
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SCT_EXTENSION_INVALID_ENCODING,
                str(e)
            )
