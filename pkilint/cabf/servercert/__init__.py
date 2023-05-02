import enum
import operator
from datetime import timedelta

from pyasn1_alt_modules import rfc5280

import pkilint.cabf.cabf_name
from pkilint import validation
from pkilint.cabf import cabf_key, cabf_name
from pkilint.cabf.servercert import (
    servercert_name, servercert_extension, servercert_constants,
    servercert_key
)
from pkilint.cabf.servercert.asn1 import ev_guidelines as ev_guidelines_asn1
from pkilint.itu import x520_name
from pkilint.pkix import name, certificate, time
from pkilint.pkix.certificate import certificate_extension


def _is_end_entity_certificate_type(certificate_type):
    return (certificate_type & 0x7) != 0


@enum.unique
class CertificateType(enum.IntEnum):
    DV = 1,
    IV = 2,
    OV = 3,
    EV = 4,
    INTERNAL_INTERMEDIATE = 8,
    EXTERNAL_INTERMEDIATE = 9,
    ROOT = 16

    def __str__(self):
        return self.name


ALLOWED_DUPLICATE_SUBJECT_ATTRIBUTES = {x520_name.id_at_streetAddress, rfc5280.id_domainComponent}

CABF_SUBJECT_VALIDATORS = [
    servercert_name.ValidBusinessCategoryValidator(),
    cabf_name.ValidCountryValidator(),
    servercert_name.ValidJurisdictionCountryValidator(),
    cabf_name.OrganizationIdentifierAttributeValidator(),
    servercert_name.OrganizationIdentifierConsistentSubjectAndExtensionValidator(),
    name.DuplicateAttributeTypeValidator(
        allowed_duplicate_oid_set=ALLOWED_DUPLICATE_SUBJECT_ATTRIBUTES,
        validation=validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            'cabf.prohibited_duplicate_attribute_type'
        )
    ),
]


def create_subject_validator(certificate_type):
    if _is_end_entity_certificate_type(certificate_type):
        return certificate.create_subject_validator_container(
            CABF_SUBJECT_VALIDATORS
        )
    else:
        required_attributes = [
            rfc5280.id_at_countryName,
            rfc5280.id_at_organizationName,
            rfc5280.id_at_commonName,
        ]

        allowed_attributes = [
            rfc5280.id_at_stateOrProvinceName,
            rfc5280.id_at_localityName,
            x520_name.id_at_streetAddress,
            x520_name.id_at_postalCode,
        ]

        return certificate.create_subject_validator_container(
            [
                name.EmptyNameValidator(),
            ] + CABF_SUBJECT_VALIDATORS
        )


def create_validity_validators(certificate_type):
    validators = []

    if _is_end_entity_certificate_type(certificate_type):
        thresholds = [
            (
                operator.le,
                timedelta(days=398),
                validation.ValidationFinding(
                    validation.ValidationFindingSeverity.ERROR,
                    'cabf.certificate_validity_period_exceeds_398_days'
                )
            ),
            (
                operator.le,
                timedelta(days=397),
                validation.ValidationFinding(
                    validation.ValidationFindingSeverity.WARNING,
                    'cabf.certificate_validity_period_exceeds_397_days'
                )
            )
        ]

        validators.append(
            time.ValidityPeriodRangeValidator(
                path='certificate.tbsCertificate.validity.notBefore',
                end_validity_node_retriever=lambda n: n.navigate('^.notAfter'),
                inclusive_second=True,
                validity_period_thresholds=thresholds
            )
        )

    return validators


def create_extension_validators(certificate_type):
    if _is_end_entity_certificate_type(certificate_type):
        return [
            servercert_extension.CABFOrganizationIdentifierExtensionValidator(),
            certificate_extension.CertificatePolicyOIDValidator(
                policy_sets=[certificate_extension.CertificatePolicySet(True, {
                    servercert_constants.ID_POLICY_DV,
                    servercert_constants.ID_POLICY_OV,
                    servercert_constants.ID_POLICY_IV,
                    servercert_constants.ID_POLICY_EV,
                })]
            )
        ]
    else:
        return []


def create_spki_validators():
    return validation.ValidatorContainer(
        validators=[
            servercert_key.CabfAllowedPublicKeyAlgorithmEncodingValidator(
                path='certificate.tbsCertificate.subjectPublicKeyInfo.algorithm'
            ),
            cabf_key.RsaKeyValidator()
        ],
        path='certificate.tbsCertificate.subjectPublicKeyInfo'
    )


def create_validators(certificate_type):
    return [
        certificate.create_issuer_validator_container(
            []
        ),
        certificate.create_validity_validator_container(
            create_validity_validators(certificate_type)
        ),
        create_subject_validator(certificate_type),
        create_spki_validators(),
        certificate.create_extensions_validator_container(
            create_extension_validators(certificate_type)
        ),
        servercert_key.CabfAllowedSignatureAlgorithmEncodingValidator(
            path='certificate.tbsCertificate.signature'
        )
    ]
