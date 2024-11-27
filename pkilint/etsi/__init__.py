import typing
from typing import List

from pyasn1_alt_modules import rfc5280, rfc6962, rfc3739

from pkilint import validation, finding_filter, cabf, document
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import (
    serverauth_constants,
    serverauth_name,
    serverauth_finding_filter,
)
from pkilint.common import organization_id, alternative_name
from pkilint.etsi import (
    etsi_constants,
    ts_119_495,
    en_319_412_5,
    en_319_412_1,
    en_319_412_2,
    en_319_412_3,
    ts_119_312,
    en_319_412_4,
    etsi_shared,
    etsi_finding_filter,
    en_319_411_1,
)
from pkilint.etsi.asn1 import (
    en_319_412_1 as en_319_412_asn1,
    en_319_412_5 as en_319_412_5_asn1,
    ts_119_495 as ts_119_495_asn1,
)
from pkilint.etsi.etsi_constants import CertificateType
from pkilint.itu import x520_name_unbounded
from pkilint.pkix import certificate


def determine_certificate_type(cert: certificate.RFC5280Certificate) -> CertificateType:
    qualified_statement_ids = cert.qualified_statement_ids
    policy_oids = cert.policy_oids

    is_qualified = en_319_412_5_asn1.id_etsi_qcs_QcCompliance in qualified_statement_ids
    is_eidas_qualified = (
        is_qualified
        and en_319_412_5_asn1.id_etsi_qcs_QcCClegislation not in qualified_statement_ids
    )
    is_precert = cert.get_extension_by_oid(rfc6962.id_ce_criticalPoison) is not None
    is_webauth = rfc5280.id_kp_serverAuth in cert.extended_key_usages

    if serverauth_constants.ID_POLICY_EV in policy_oids:
        is_psd2 = ts_119_495_asn1.id_etsi_psd2_qcStatement in qualified_statement_ids

        if is_psd2:
            return (
                CertificateType.QEVCP_W_PSD2_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QEVCP_W_PSD2_EIDAS_FINAL_CERTIFICATE
            )
        elif is_eidas_qualified:
            return (
                CertificateType.QEVCP_W_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QEVCP_W_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QEVCP_W_NON_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QEVCP_W_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
            return (
                CertificateType.EVCP_PRE_CERTIFICATE
                if is_precert
                else CertificateType.EVCP_FINAL_CERTIFICATE
            )
    elif serverauth_constants.ID_POLICY_OV in policy_oids:
        if is_eidas_qualified:
            return (
                CertificateType.QNCP_W_OV_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QNCP_W_OV_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QNCP_W_OV_NON_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QNCP_W_OV_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
            return (
                CertificateType.OVCP_PRE_CERTIFICATE
                if is_precert
                else CertificateType.OVCP_FINAL_CERTIFICATE
            )
    elif serverauth_constants.ID_POLICY_IV in policy_oids:
        if is_eidas_qualified:
            return (
                CertificateType.QNCP_W_IV_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QNCP_W_IV_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QNCP_W_IV_NON_EIDAS_PRE_CERTIFICATE
                if is_precert
                else CertificateType.QNCP_W_IV_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
            return (
                CertificateType.IVCP_PRE_CERTIFICATE
                if is_precert
                else CertificateType.IVCP_FINAL_CERTIFICATE
            )
    elif serverauth_constants.ID_POLICY_DV in policy_oids:
        return (
            CertificateType.DVCP_PRE_CERTIFICATE
            if is_precert
            else CertificateType.DVCP_FINAL_CERTIFICATE
        )
    else:
        is_natural_person = any(
            (
                cert.get_subject_attributes_by_type(rfc5280.id_at_givenName),
                cert.get_subject_attributes_by_type(rfc5280.id_at_surname),
                cert.get_subject_attributes_by_type(rfc5280.id_at_pseudonym),
            )
        )

        if is_natural_person:
            if is_webauth:
                if is_eidas_qualified:
                    return (
                        CertificateType.QNCP_W_GEN_NATURAL_PERSON_EIDAS_PRE_CERTIFICATE
                        if is_precert
                        else CertificateType.QNCP_W_GEN_NATURAL_PERSON_EIDAS_FINAL_CERTIFICATE
                    )
                elif is_qualified:
                    return (
                        CertificateType.QNCP_W_GEN_NATURAL_PERSON_NON_EIDAS_PRE_CERTIFICATE
                        if is_precert
                        else CertificateType.QNCP_W_GEN_NATURAL_PERSON_NON_EIDAS_FINAL_CERTIFICATE
                    )
                else:
                    return (
                        CertificateType.NCP_W_NATURAL_PERSON_PRE_CERTIFICATE
                        if is_precert
                        else CertificateType.NCP_W_NATURAL_PERSON_FINAL_CERTIFICATE
                    )

            return CertificateType.NCP_NATURAL_PERSON_CERTIFICATE
        else:
            if is_webauth:
                if is_eidas_qualified:
                    return (
                        CertificateType.QNCP_W_GEN_LEGAL_PERSON_EIDAS_PRE_CERTIFICATE
                        if is_precert
                        else CertificateType.QNCP_W_GEN_LEGAL_PERSON_EIDAS_FINAL_CERTIFICATE
                    )
                elif is_qualified:
                    return (
                        CertificateType.QNCP_W_GEN_LEGAL_PERSON_NON_EIDAS_PRE_CERTIFICATE
                        if is_precert
                        else CertificateType.QNCP_W_GEN_LEGAL_PERSON_NON_EIDAS_FINAL_CERTIFICATE
                    )
                else:
                    return (
                        CertificateType.NCP_W_LEGAL_PERSON_PRE_CERTIFICATE
                        if is_precert
                        else CertificateType.NCP_W_LEGAL_PERSON_FINAL_CERTIFICATE
                    )

            return CertificateType.NCP_LEGAL_PERSON_CERTIFICATE


def create_decoding_validators(
    certificate_type: CertificateType,
) -> List[validation.Validator]:
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
        
        From EN 319 412-4:
        WEB-4.1.3-4: The following certificate profile requirements specified in the BRG [9] shall apply for subject
        certificate fields addressed by the following sub-sections of BRG:
        ...
        (c) 7.1.4.2.2 Subject Distinguished Name - commonName.
        """
        name_attribute_mappings.update(
            {
                k: v
                for k, v in x520_name_unbounded.UNBOUNDED_ATTRIBUTE_TYPE_MAPPINGS.items()
                if k
                in (
                    rfc5280.id_at_organizationName,
                    rfc5280.id_at_organizationalUnitName,
                    rfc5280.id_at_pseudonym,
                )
            }
        )

        if certificate_type not in etsi_constants.WEB_AUTHENTICATION_CERTIFICATE_TYPES:
            name_attribute_mappings[
                rfc5280.id_at_commonName
            ]: x520_name_unbounded.X520CommonNameUnbounded()

        additional_validators = [
            certificate.create_qc_statements_decoder(asn1.ETSI_QC_STATEMENTS_MAPPINGS)
        ]

        return certificate.create_decoding_validators(
            name_attribute_mappings, cabf.EXTENSION_MAPPINGS, additional_validators
        )


def create_validators(
    certificate_type: CertificateType,
    validity_period_start_retriever: typing.Optional[
        document.ValidityPeriodStartRetriever
    ] = None,
    additional_validity_validators=None,
    additional_spki_validators=None,
    additional_name_validators=None,
    additional_extension_validators=None,
    additional_top_level_validators=None,
) -> List[validation.Validator]:
    subject_validators = [
        en_319_412_1.LegalPersonOrganizationIdentifierValidator(),
        en_319_412_1.NaturalPersonIdentifierValidator(),
        en_319_412_1.EidasLegalPersonIdentifierValidator(),
        en_319_412_1.NaturalPersonEidasIdentifierValidator(),
        organization_id.OrganizationIdentifierLeiValidator(),
        en_319_412_3.LegalPersonOrganizationAttributesEqualityValidator(),
    ]

    if additional_name_validators:
        subject_validators.extend(additional_name_validators)

    issuer_validators = []

    qc_statement_validators = [
        ts_119_495.RolesOfPspValidator(),
        ts_119_495.NCANameLatinCharactersValidator(),
        ts_119_495.NCAIdValidator(),
        en_319_412_5.QcCCLegislationCountryCodeValidator(),
        en_319_412_5.QcEuRetentionPeriodValidator(),
        en_319_412_5.QcTypeValidator(certificate_type),
        en_319_412_5.QcEuPDSHttpsURLValidator(),
        en_319_412_5.QcEuLimitValueValidator(),
        en_319_412_5.QcEuPDSLanguageValidator(),
        en_319_412_1.LegalPersonIdentifierNameRegistrationAuthoritiesValidator(),
        en_319_412_1.NaturalPersonIdentifierNameRegistrationAuthoritiesValidator(),
        en_319_412_5.QcStatementIdentifierAllowanceValidator(certificate_type),
    ]

    qc_statements_validator_container = validation.ValidatorContainer(
        validators=qc_statement_validators, pdu_class=rfc3739.QCStatements
    )

    extension_validators = [
        en_319_412_2.QualifiedCertificatePoliciesValidator(certificate_type),
        en_319_412_5.QcStatementsExtensionCriticalityValidator(),
        ts_119_495.Psd2CertificatePolicyOidPresenceValidator(certificate_type),
        qc_statements_validator_container,
    ]

    if additional_extension_validators:
        extension_validators.extend(additional_extension_validators)

    spki_validators = [
        ts_119_312.RsaKeyValidator(),
        ts_119_312.AllowedPublicKeyTypeValidator(),
    ]

    if additional_spki_validators:
        spki_validators.extend(additional_spki_validators)

    top_level_validators = [
        en_319_412_2.ExtensionsPresenceValidator(),
        ts_119_312.AllowedSignatureAlgorithmValidator(
            path="certificate.tbsCertificate.signature"
        ),
    ]

    if additional_top_level_validators:
        top_level_validators.extend(additional_top_level_validators)

    if certificate_type in etsi_constants.EU:
        extension_validators.append(en_319_412_5.QcStatementPresenceValidator())

    if (
        certificate_type in etsi_constants.LEGAL_PERSON_CERTIFICATE_TYPES
        and certificate_type not in etsi_constants.CABF_CERTIFICATE_TYPES
    ):
        subject_validators.extend(
            [
                en_319_412_3.LegalPersonSubjectAttributeAllowanceValidator(),
                en_319_412_3.LegalPersonDuplicateAttributeAllowanceValidator(),
                en_319_412_3.LegalPersonCountryCodeValidator(),
            ]
        )

    elif (
        certificate_type in etsi_constants.NATURAL_PERSON_CERTIFICATE_TYPES
        and certificate_type not in etsi_constants.CABF_CERTIFICATE_TYPES
    ):
        subject_validators.append(
            en_319_412_2.NaturalPersonSubjectAttributeAllowanceValidator()
        )

        if certificate_type in etsi_constants.EU:
            issuer_validators.extend(
                [
                    en_319_412_2.LegalPersonIssuerCountryCodeValidator(),
                    en_319_412_2.LegalPersonIssuerOrganizationAttributesEqualityValidator(),
                    en_319_412_2.LegalPersonIssuerDuplicateAttributeAllowanceValidator(),
                    en_319_412_2.LegalPersonIssuerAttributeAllowanceValidator(),
                ]
            )

    if certificate_type not in etsi_constants.CABF_CERTIFICATE_TYPES:
        extension_validators.extend(
            [
                en_319_412_2.CertificatePoliciesCriticalityValidator(),
                en_319_412_2.SubjectAlternativeNameCriticalityValidator(),
                en_319_412_2.IssuerAlternativeNameCriticalityValidator(),
                en_319_412_2.ExtendedKeyUsageCriticalityValidator(),
                en_319_412_2.CRLDistributionPointsCriticalityValidator(),
                en_319_412_2.NaturalPersonExtensionIdentifierAllowanceValidator(
                    certificate_type
                ),
                en_319_412_2.CrlDistributionPointsExtensionPresenceValidator(),
                en_319_412_2.CrlDistributionPointsValidator(),
                en_319_412_2.AuthorityInformationAccessValidator(),
            ]
        )

        if certificate_type in etsi_constants.WEB_AUTHENTICATION_CERTIFICATE_TYPES:
            extension_validators.extend(
                [
                    en_319_412_4.NcpWExtendedKeyUsagePresenceValidator(),
                    serverauth.serverauth_subscriber.SubscriberEkuAllowanceValidator(),
                    en_319_412_4.NcpWCriticalityExtendedKeyUsageValidator(),
                    serverauth.serverauth_subscriber.SubscriberSanGeneralNameTypeValidator(),
                    serverauth_name.DnsNameLdhLabelSyntaxValidator(),
                    en_319_412_4.NcpWSubjectAltNamePresenceValidator(),
                ]
            )

        # TODO: fix commitment types when adding support for eSeal and eSignature
        if certificate_type in etsi_constants.LEGAL_PERSON_CERTIFICATE_TYPES:
            extension_validators.append(
                en_319_412_3.LegalPersonKeyUsageValidator(
                    is_content_commitment_type=None
                )
            )
        elif certificate_type in etsi_constants.NATURAL_PERSON_CERTIFICATE_TYPES:
            if certificate_type in etsi_constants.QCP_N_CERTIFICATE_TYPES:
                extension_validators.append(
                    en_319_412_2.NaturalPersonKeyUsageValidator(
                        is_content_commitment_type=True
                    )
                )
            else:
                extension_validators.append(
                    en_319_412_2.NaturalPersonKeyUsageValidator(
                        is_content_commitment_type=None
                    )
                )

    if certificate_type in etsi_constants.QEVCP_W_PSD2_EIDAS_CERTIFICATE_TYPES:
        qc_statement_validators.append(ts_119_495.PresenceofQCEUPDSStatementValidator())

        subject_validators.append(ts_119_495.PsdOrganizationIdentifierFormatValidator())

    if certificate_type in etsi_constants.QNCP_W_CERTIFICATE_TYPES:
        subject_validators.append(en_319_412_4.QncpWCommonNameValidator())
    elif certificate_type in etsi_constants.NCP_W_CERTIFICATE_TYPES:
        subject_validators.append(en_319_412_4.NcpWCommonNameValidator())

    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        extension_validators.append(
            en_319_411_1.CertificatePoliciesValidator(certificate_type)
        )

        serverauth_cert_type = (
            etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS[certificate_type]
        )

        return serverauth.create_validators(
            serverauth_cert_type,
            validity_period_start_retriever=validity_period_start_retriever,
            additional_top_level_validators=top_level_validators,
            additional_validity_validators=additional_validity_validators,
            additional_name_validators=subject_validators,
            additional_extension_validators=extension_validators,
            additional_spki_validators=spki_validators,
        )
    else:
        spki_validator_container = validation.ValidatorContainer(
            validators=spki_validators,
            path="certificate.tbsCertificate.subjectPublicKeyInfo",
        )

        top_level_container = validation.ValidatorContainer(
            validators=top_level_validators, pdu_class=rfc5280.Certificate
        )

        extension_validators.extend(
            [
                alternative_name.create_internal_name_validator_container(
                    etsi_shared.VALIDATION_INTERNAL_DOMAIN_NAME,
                    etsi_shared.VALIDATION_INTERNAL_IP_ADDRESS,
                    allow_onion_tld=False,
                ),
                alternative_name.create_cpsuri_internal_domain_name_validator(
                    etsi_shared.VALIDATION_INTERNAL_DOMAIN_NAME
                ),
            ]
        )

        return [
            certificate.create_issuer_validator_container(issuer_validators),
            certificate.create_validity_validator_container(
                additional_validity_validators
            ),
            certificate.create_subject_validator_container(subject_validators),
            certificate.create_extensions_validator_container(extension_validators),
            spki_validator_container,
            top_level_container,
        ]


def create_etsi_finding_filters(
    certificate_type,
) -> List[finding_filter.FindingDescriptionFilter]:
    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        serverauth_cert_type = (
            etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS[certificate_type]
        )

        filters = serverauth.create_serverauth_finding_filters(serverauth_cert_type)
    else:
        filters = [
            serverauth_finding_filter.DnsNameGeneralNamePreferredNameSyntaxFilter(),
        ]

    if (
        certificate_type
        in etsi_constants.QEVCP_W_PSD2_EIDAS_NON_BROWSER_CERTIFICATE_TYPES
    ):
        filters.append(etsi_finding_filter.Psd2CabfServerauthValidityPeriodFilter())

    return filters
