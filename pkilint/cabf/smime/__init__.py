import operator
from typing import Mapping, Tuple, Optional

from dateutil.relativedelta import relativedelta
from pyasn1.type import univ
from pyasn1_alt_modules import rfc8398, rfc5280, rfc4262

import pkilint.adobe.asn1 as adobe_asn1
import pkilint.cabf.cabf_extension
import pkilint.cabf.smime.smime_extension
import pkilint.common
import pkilint.etsi.asn1
import pkilint.pkix.certificate
from pkilint import validation, cabf, document
from pkilint.adobe import adobe_validator
from pkilint.cabf import cabf_extension, cabf_key, cabf_name
from pkilint.cabf.smime import (
    smime_constants,
    smime_name,
    smime_key,
    smime_extension,
    smime_validity,
)
from pkilint.cabf.smime.smime_constants import Generation
from pkilint.common import alternative_name
from pkilint.iso import lei
from pkilint.msft import asn1 as microsoft_asn1
from pkilint.msft import msft_name
from pkilint.pkix import certificate, time
from pkilint.pkix.certificate import certificate_validity
from pkilint.pkix.general_name import OTHER_NAME_MAPPINGS as PKIX_OTHERNAME_MAPPINGS

OTHER_NAME_MAPPINGS = {
    **PKIX_OTHERNAME_MAPPINGS,
    rfc8398.id_on_SmtpUTF8Mailbox: rfc8398.SmtpUTF8Mailbox(),
    microsoft_asn1.id_on_UserPrincipalName: microsoft_asn1.UserPrincipalName(),
}


def determine_validation_level_and_generation(
    cert: certificate.RFC5280Certificate,
    config: Mapping[
        univ.ObjectIdentifier,
        Tuple[smime_constants.ValidationLevel, smime_extension.Generation],
    ] = None,
):
    oids = cert.policy_oids

    for v in smime_constants.ValidationLevel:
        for g in smime_constants.Generation:
            oid = smime_constants.get_policy_oid(v, g)

            if oid in oids:
                return v, g

    if config is not None:
        for o in oids:
            v_g = config.get(o)

            if v_g is not None:
                return v_g

    return None


def _has_subject_attr(cert, attr):
    return any(cert.get_subject_attributes_by_type(attr))


def _get_first_subject_attr_dirstring_value(cert, attr, attr_asn1_cls):
    attrs = cert.get_subject_attributes_by_type(attr)

    if any(attrs):
        attr, _ = attrs[0]

        attr_value_pdu = attr.children["value"].pdu

        decoded_value = document.decode_substrate(cert, attr_value_pdu, attr_asn1_cls())

        # assume DirectoryString
        _, attr_value_choice_value = decoded_value.child

        return str(attr_value_choice_value.pdu)
    else:
        return None


def guess_validation_level_and_generation(
    cert: certificate.RFC5280Certificate,
    config: Mapping[
        univ.ObjectIdentifier,
        Tuple[smime_constants.ValidationLevel, smime_extension.Generation],
    ] = None,
):
    v_g = determine_validation_level_and_generation(cert, config)

    if v_g is not None:
        return v_g

    # assume Legacy generation
    g = smime_constants.Generation.LEGACY

    o = _get_first_subject_attr_dirstring_value(
        cert, rfc5280.id_at_organizationName, rfc5280.X520OrganizationName
    )
    has_o = o is not None
    cn = _get_first_subject_attr_dirstring_value(
        cert, rfc5280.id_at_commonName, rfc5280.X520CommonName
    )
    has_cn = cn is not None
    has_natural_name = _has_subject_attr(
        cert, rfc5280.id_at_surname
    ) or _has_subject_attr(cert, rfc5280.id_at_givenName)

    if has_o and (has_natural_name or (has_cn and o != cn and "@" not in cn)):
        v = smime_constants.ValidationLevel.SPONSORED
    elif has_o:
        v = smime_constants.ValidationLevel.ORGANIZATION
    elif has_natural_name:
        v = smime_constants.ValidationLevel.INDIVIDUAL
    else:
        v = smime_constants.ValidationLevel.MAILBOX

    return v, g


_SMIME_EXTENSION_MAPPINGS = {
    **cabf.EXTENSION_MAPPINGS,
    **lei.EXTENSION_MAPPINGS,
    **rfc4262.certificateExtensionsMap,
    **adobe_asn1.EXTENSION_MAPPINGS,
}


def create_decoding_validators():
    return pkilint.pkix.certificate.create_decoding_validators(
        cabf.NAME_ATTRIBUTE_MAPPINGS,
        _SMIME_EXTENSION_MAPPINGS,
        [
            certificate.create_other_name_decoder(OTHER_NAME_MAPPINGS),
            certificate.create_qc_statements_decoder(
                pkilint.etsi.asn1.ETSI_QC_STATEMENTS_MAPPINGS
            ),
        ],
    )


def create_spki_validation_container():
    return certificate.create_spki_validator_container(
        [
            smime_key.SmimeAllowedPublicKeyAlgorithmEncodingValidator(
                path="certificate.tbsCertificate.subjectPublicKeyInfo.algorithm"
            ),
            cabf_key.RsaKeyValidator(),
            cabf_key.EcdsaKeyValidator(),
            smime_key.GmailAllowedModulusLengthValidator(),
        ]
    )


def create_extensions_validator_container(validation_level, generation):
    return certificate.create_extensions_validator_container(
        [
            smime_extension.RequiredPolicyIdentifierValidator(
                validation_level, generation
            ),
            smime_extension.CertificatePoliciesPresenceValidator(),
            smime_extension.ExtendedKeyUsagePresenceValidator(),
            smime_extension.CabfSmimeKeyUsagePresenceValidator(),
            cabf_extension.AuthorityInformationAccessPresenceValidator(
                validation.ValidationFindingSeverity.WARNING
            ),
            smime_extension.CrlDistributionPointPresenceValidator(),
            smime_extension.SubjectAlternativeNamePresenceValidator(),
            smime_extension.AllowedExtendedKeyUsageValidator(generation),
            smime_extension.AllowedKeyUsageValidator(generation),
            smime_extension.EndEntityValidator(),
            cabf_extension.CpsUriHttpValidator(),
            cabf_extension.AuthorityInformationAccessContainsHttpUriValidator(),
            cabf_extension.CrlDpContainsHttpUriValidator(),
            smime_extension.SubjectAlternativeNameContainsEmailAddressValidator(),
            smime_extension.SubjectAlternativeNameProhibitedGeneralNameTypesValidator(
                generation
            ),
            smime_extension.CabfSmimeKeyUsageCriticalityValidator(),
            smime_extension.GmailAuthorityInfoAccessCaIssuersValidator(),
            msft_name.UserPrincipalNameSyntaxValidator(),
            smime_extension.AllowedCrldpFullNameValidator(generation),
            smime_extension.SmimeUserNoticeValidator(),
            smime_extension.AllowedAiaUriSchemeValidator(generation),
            smime_extension.LeiCriticalityValidator(),
            smime_extension.LeiRoleCriticalityValidator(),
            smime_extension.LeiPresenceValidator(validation_level),
            smime_extension.LeiRolePresenceValidator(validation_level),
            lei.LeiExtensionValueSyntaxValidator(),
            cabf_extension.CertificatePoliciesCriticalityValidator(),
            cabf_extension.CabfCrlDpCriticalityValidator(),
            cabf_extension.CabfAuthorityKeyIdentifierValidator(),
            smime_extension.SubjectDirectoryAttributesPresenceValidator(
                validation_level, generation
            ),
            smime_extension.QCStatementsCriticalityValidator(),
            alternative_name.create_internal_name_validator_container(
                cabf_name.VALIDATION_INTERNAL_DOMAIN_NAME,
                cabf_name.VALIDATION_INTERNAL_IP_ADDRESS,
                allow_onion_tld=False,
            ),
            alternative_name.create_cpsuri_internal_domain_name_validator(
                cabf_name.VALIDATION_INTERNAL_DOMAIN_NAME
            ),
            adobe_validator.AdobeTimestampValidator(),
            smime_extension.AdobeTimestampCriticalityValidator(),
            smime_extension.AdobeTimestampPresenceValidator(generation),
            smime_extension.AdobeArchiveRevInfoCriticalityValidator(),
            smime_extension.AdobeArchiveRevInfoPresenceValidator(generation),
        ]
    )


def create_validity_validators(
    generation, validity_period_start_retriever: document.ValidityPeriodStartRetriever
):
    days = 1185 if generation == Generation.LEGACY else 825

    threshold_error = (
        operator.le,
        relativedelta(days=days),
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            f"cabf.smime.certificate_validity_period_exceeds_{days}_days",
        ),
    )

    threshold_warning = (
        operator.le,
        relativedelta(days=days - 1, hours=23, minutes=59, seconds=59),
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.WARNING,
            "cabf.smime.certificate_validity_period_at_maximum",
        ),
    )

    validators = [
        time.ValidityPeriodThresholdsValidator(
            path="certificate.tbsCertificate.validity.notBefore",
            end_validity_node_retriever=lambda n: n.navigate("^.notAfter"),
            inclusive_second=True,
            validity_period_thresholds=[threshold_error, threshold_warning],
        )
    ]

    if generation == smime_constants.Generation.LEGACY:
        validators.append(
            smime_validity.LegacyGenerationSunsetValidator(
                validity_period_start_retriever
            )
        )

    return validators


def create_subscriber_validators(
    validation_level,
    generation,
    validity_period_start_retriever: Optional[
        document.ValidityPeriodStartRetriever
    ] = None,
):
    if validity_period_start_retriever is None:
        validity_period_start_retriever = (
            certificate_validity.CertificateValidityPeriodStartRetriever()
        )

    return [
        smime_name.create_subscriber_certificate_subject_validator_container(
            validation_level, generation
        ),
        create_spki_validation_container(),
        certificate.create_issuer_validator_container([]),
        certificate.create_validity_validator_container(
            create_validity_validators(generation, validity_period_start_retriever)
        ),
        create_extensions_validator_container(validation_level, generation),
        smime_key.SmimeAllowedSignatureAlgorithmEncodingValidator(
            path="certificate.tbsCertificate.signature"
        ),
        cabf_extension.CabfExtensionsPresenceValidator(),
    ]
