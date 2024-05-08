from typing import List

from pyasn1_alt_modules import rfc5280, rfc6962, rfc3739

from pkilint import validation, finding_filter, cabf
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.common import organization_id, alternative_name
from pkilint.etsi import (
    etsi_constants, ts_119_495, en_319_412_5, en_319_412_1, en_319_412_2, en_319_412_3,
    ts_119_312, en_319_412_4, etsi_shared
)
from pkilint.etsi.asn1 import (
    en_319_412_1 as en_319_412_asn1, en_319_412_5 as en_319_412_5_asn1, ts_119_495 as ts_119_495_asn1
)
from pkilint.etsi.etsi_constants import CertificateType
from pkilint.itu import x520_name_unbounded
from pkilint.pkix import certificate


def determine_certificate_type(cert: certificate.RFC5280Certificate) -> CertificateType:
    qualified_statement_ids = cert.qualified_statement_ids
    policy_oids = cert.policy_oids

    is_qualified = en_319_412_5_asn1.id_etsi_qcs_QcCompliance in qualified_statement_ids
    is_eidas_qualified = is_qualified and en_319_412_5_asn1.id_etsi_qcs_QcCClegislation not in qualified_statement_ids
    is_precert = cert.get_extension_by_oid(rfc6962.id_ce_criticalPoison) is not None

    if serverauth_constants.ID_POLICY_EV in policy_oids:
        is_psd2 = ts_119_495_asn1.id_etsi_psd2_qcStatement in qualified_statement_ids

        if is_psd2:
            return (
                CertificateType.QEVCP_W_PSD2_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QEVCP_W_PSD2_EIDAS_FINAL_CERTIFICATE
            )
        elif is_eidas_qualified:
            return (
                CertificateType.QEVCP_W_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QEVCP_W_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QEVCP_W_NON_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QEVCP_W_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
            return CertificateType.EVCP_PRE_CERTIFICATE if is_precert else CertificateType.EVCP_FINAL_CERTIFICATE
    elif serverauth_constants.ID_POLICY_OV in policy_oids:
        if is_eidas_qualified:
            return (
                CertificateType.QNCP_W_OV_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QNCP_W_OV_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QNCP_W_OV_NON_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QNCP_W_OV_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
            return CertificateType.OVCP_PRE_CERTIFICATE if is_precert else CertificateType.OVCP_FINAL_CERTIFICATE
    elif serverauth_constants.ID_POLICY_IV in policy_oids:
        if is_eidas_qualified:
            return (
                CertificateType.QNCP_W_IV_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QNCP_W_IV_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QNCP_W_IV_NON_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QNCP_W_IV_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
            return CertificateType.IVCP_PRE_CERTIFICATE if is_precert else CertificateType.IVCP_FINAL_CERTIFICATE
    elif serverauth_constants.ID_POLICY_DV in policy_oids:
        return CertificateType.DVCP_PRE_CERTIFICATE if is_precert else CertificateType.DVCP_FINAL_CERTIFICATE
    else:
        is_natural_person = any((
            cert.get_subject_attributes_by_type(rfc5280.id_at_givenName),
            cert.get_subject_attributes_by_type(rfc5280.id_at_surname),
            cert.get_subject_attributes_by_type(rfc5280.id_at_pseudonym),
        ))

        if is_natural_person:
            if is_eidas_qualified:
                return (
                    CertificateType.QNCP_W_GEN_NATURAL_PERSON_EIDAS_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_GEN_NATURAL_PERSON_EIDAS_FINAL_CERTIFICATE
                )
            elif is_qualified:
                return (
                    CertificateType.QNCP_W_GEN_NATURAL_PERSON_NON_EIDAS_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_GEN_NATURAL_PERSON_NON_EIDAS_FINAL_CERTIFICATE
                )
            else:
                return (CertificateType.NCP_NATURAL_PERSON_PRE_CERTIFICATE if is_precert
                        else CertificateType.NCP_NATURAL_PERSON_FINAL_CERTIFICATE)
        else:
            if is_eidas_qualified:
                return (
                    CertificateType.QNCP_W_GEN_LEGAL_PERSON_EIDAS_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_GEN_LEGAL_PERSON_EIDAS_FINAL_CERTIFICATE
                )
            elif is_qualified:
                return (
                    CertificateType.QNCP_W_GEN_LEGAL_PERSON_NON_EIDAS_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_GEN_LEGAL_PERSON_NON_EIDAS_FINAL_CERTIFICATE
                )
            else:
                return (CertificateType.NCP_LEGAL_PERSON_PRE_CERTIFICATE if is_precert
                        else CertificateType.NCP_LEGAL_PERSON_FINAL_CERTIFICATE)


def create_decoding_validators(certificate_type: CertificateType) -> List[validation.Validator]:
    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        return serverauth.create_decoding_validators()
    else:
        name_attribute_mappings = cabf.NAME_ATTRIBUTE_MAPPINGS.copy()

        """
        From EN 319 412-2:
        NAT-4.2.4-18 If present, the size of givenName, surname, pseudonym, commonName, organizationName and
        organizationalUnitName may be longer than the limit as stated in IETF RFC 5280 [1].
        
        From EN 319 412-3:
        LEG-4.2.1-9: If present, the size of organizationName, organizationalUnitName and commonName may
        be longer than the limit as stated in IETF RFC 5280 [3].
        """
        name_attribute_mappings.update(x520_name_unbounded.UNBOUNDED_ATTRIBUTE_TYPE_MAPPINGS)

        additional_validators = [
            certificate.create_qc_statements_decoder(asn1.ETSI_QC_STATEMENTS_MAPPINGS)
        ]

        return certificate.create_decoding_validators(
            name_attribute_mappings,
            cabf.EXTENSION_MAPPINGS,
            additional_validators
        )


def create_validators(certificate_type: CertificateType) -> List[validation.Validator]:
    subject_validators = [
        en_319_412_1.LegalPersonOrganizationIdentifierValidator(),
        en_319_412_1.NaturalPersonIdentifierValidator(),
        organization_id.OrganizationIdentifierLeiValidator(),
    ]

    qc_statement_validators = [
        ts_119_495.RolesOfPspValidator(),
        ts_119_495.NCANameLatinCharactersValidator(),
        ts_119_495.NCAIdValidator(),
        en_319_412_5.QcCClegislationCountryCodeValidator(),
        en_319_412_5.QcEuRetentionPeriodValidator(),
        en_319_412_5.QcTypeValidator(),
        en_319_412_5.QcEuPDSHttpsURLValidator(),
        en_319_412_5.QcEuLimitValueValidator(),
        en_319_412_5.QcEuPDSLanguageValidator(),
        en_319_412_1.LegalPersonIdentifierNameRegistrationAuthoritiesValidator(),
        en_319_412_1.NaturalPersonIdentifierNameRegistrationAuthoritiesValidator(),
    ]

    qc_statements_validator_container = validation.ValidatorContainer(
        validators=qc_statement_validators,
        pdu_class=rfc3739.QCStatements
    )

    extension_validators = [
        en_319_412_2.CertificatePoliciesCriticalityValidator(),
        en_319_412_2.SubjectAlternativeNameCriticalityValidator(),
        en_319_412_2.IssuerAlternativeNameCriticalityValidator(),
        en_319_412_2.ExtendedKeyUsageCriticalityValidator(),
        en_319_412_2.CRLDistributionPointsCriticalityValidator(),
        en_319_412_2.NaturalPersonExtensionIdentifierAllowanceValidator(certificate_type),
        en_319_412_2.CrlDistributionPointsExtensionPresenceValidator(),
        en_319_412_2.CrlDistributionPointsValidator(),
        en_319_412_2.AuthorityInformationAccessValidator(),
        en_319_412_2.CertificatePoliciesValidator(certificate_type),
        en_319_412_5.QcStatementsExtensionValidator(),
        qc_statements_validator_container
    ]

    spki_validators = [
        ts_119_312.RsaKeyValidator(),
        ts_119_312.AllowedPublicKeyTypeValidator(),
    ]

    top_level_validators = [
        en_319_412_2.ExtensionsPresenceValidator(),
    ]

    if certificate_type in etsi_constants.LEGAL_PERSON_CERTIFICATE_TYPES:
        # TODO: modify when eSig and eSeal support is added
        extension_validators.append(en_319_412_3.LegalPersonKeyUsageValidator(is_content_commitment_type=None))

        subject_validators.extend([
            en_319_412_3.LegalPersonSubjectAttributeAllowanceValidator(),
            en_319_412_3.LegalPersonDuplicateAttributeAllowanceValidator(),
            en_319_412_3.LegalPersonOrganizationAttributesEqualityValidator(),
        ])
    else:
        # TODO: modify when eSig and eSeal support is added
        extension_validators.append(en_319_412_2.NaturalPersonKeyUsageValidator(is_content_commitment_type=None))

        subject_validators.extend([en_319_412_2.NaturalPersonSubjectAttributeAllowanceValidator()])

    if certificate_type in etsi_constants.QEVCP_W_PSD2_EIDAS_CERTIFICATE_TYPES:
        qc_statement_validators.append(ts_119_495.PresenceofQCEUPDSStatementValidator())
        subject_validators.append(ts_119_495.PsdOrganizationIdentifierFormatValidator())

    if certificate_type in etsi_constants.QNCP_W_CERTIFICATE_TYPES:
        subject_validators.append(en_319_412_4.QncpWCommonNameValidator())
    elif certificate_type in etsi_constants.QNCP_W_GEN_CERTIFICATE_TYPES:
        subject_validators.append(en_319_412_4.QncpWGenCommonNameValidator())

    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        serverauth_cert_type = etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS[certificate_type]

        return serverauth.create_validators(
            serverauth_cert_type,
            additional_top_level_validators=top_level_validators,
            additional_name_validators=subject_validators,
            additional_extension_validators=extension_validators,
            additional_spki_validators=spki_validators
        )
    else:
        spki_validator_container = validation.ValidatorContainer(
            validators=spki_validators,
            path='certificate.tbsCertificate.subjectPublicKeyInfo'
        )

        top_level_container = validation.ValidatorContainer(
            validators=top_level_validators,
            pdu_class=rfc5280.Certificate
        )

        extension_validators.extend([
            alternative_name.create_internal_name_validator_container(
                etsi_shared.VALIDATION_INTERNAL_DOMAIN_NAME,
                etsi_shared.VALIDATION_INTERNAL_IP_ADDRESS,
                allow_onion_tld=False
            ),
            alternative_name.create_cpsuri_internal_domain_name_validator(
                etsi_shared.VALIDATION_INTERNAL_DOMAIN_NAME),
        ])

        return [
            certificate.create_issuer_validator_container(
                []
            ),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container(
                subject_validators
            ),
            certificate.create_extensions_validator_container(
                extension_validators
            ),
            spki_validator_container,
            top_level_container,
        ]


def create_etsi_finding_filters(certificate_type) -> List[finding_filter.FindingDescriptionFilter]:
    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        serverauth_cert_type = etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS[certificate_type]

        return serverauth.create_serverauth_finding_filters(serverauth_cert_type)
    else:
        return []
