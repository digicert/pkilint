import datetime
import enum
from typing import Optional

from pyasn1.type.constraint import ValueRangeConstraint
from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.document import ValueDecoder
from pkilint.pkix import extension, algorithm, name

MAXIMUM_TIME_DATETIME = datetime.datetime(
    9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc
)


def create_attribute_decoder(type_mappings, decode_unknown_as_directorystring=True):
    default = rfc5280.DirectoryString() if decode_unknown_as_directorystring else None

    decoder = ValueDecoder(
        type_path="type",
        value_path="value",
        type_mappings=type_mappings,
        default=default,
    )

    return name.NameDecodingValidator(decode_func=decoder)


def create_extension_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path="extnID", value_path="extnValue", type_mappings=type_mappings
    )

    return extension.ExtensionsDecodingValidator(decode_func=decoder)


def create_signature_algorithm_identifier_decoder(type_mappings, **kwargs):
    decoder = ValueDecoder(
        type_path="algorithm", value_path="parameters", type_mappings=type_mappings
    )

    return algorithm.AlgorithmIdentifierDecodingValidator(decode_func=decoder, **kwargs)


def create_name_validator_container(additional_validators=None, **kwargs):
    if additional_validators is None:
        additional_validators = []
    return validation.ValidatorContainer(
        validators=[
            name.RDNContainsUniqueTypesValidator(),
        ]
        + additional_validators,
        **kwargs
    )


class CertificateSerialNumberValidator(validation.ASN1ConstraintValidator):
    VALIDATION_FINDING_CERTIFICATE_SERIAL_NUMBER_OOR = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.certificate_serial_number_out_of_range",
    )

    MAX_VALUE = (1 << 159) - 1

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.CertificateSerialNumber,
            validations=[self.VALIDATION_FINDING_CERTIFICATE_SERIAL_NUMBER_OOR],
            constraint=ValueRangeConstraint(1, self.MAX_VALUE),
        )


class Rfc2119Word(enum.IntEnum):
    SHALL = 1
    MUST = SHALL
    SHOULD = 2
    MAY = 3
    MUST_NOT = 4
    SHALL_NOT = MUST_NOT
    SHOULD_NOT = 5

    def __str__(self):
        return self.name

    @property
    def to_severity(self) -> Optional[validation.ValidationFindingSeverity]:
        if self.value in {Rfc2119Word.SHALL, Rfc2119Word.SHALL_NOT}:
            return validation.ValidationFindingSeverity.ERROR
        elif self.value in {Rfc2119Word.SHOULD, Rfc2119Word.SHOULD_NOT}:
            return validation.ValidationFindingSeverity.WARNING

        return None
