from typing import List

from pyasn1_alt_modules import rfc5280, rfc6962, rfc3739

from pkilint import validation, finding_filter
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.common import organization_id
from pkilint.etsi import etsi_constants, ts_119_495, en_319_412_5, en_319_412_1
from pkilint.etsi.asn1 import (
    en_319_412_1 as en_319_412_asn1, en_319_412_5 as en_319_412_5_asn1, ts_119_495 as ts_119_495_asn1
)
from pkilint.etsi.etsi_constants import CertificateType
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
                CertificateType.QEVCP_W_PSD2_PRE_CERTIFICATE if is_precert
                else CertificateType.QEVCP_W_PSD2_FINAL_CERTIFICATE
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
        if is_eidas_qualified:
            return (
                CertificateType.QNCP_W_DV_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QNCP_W_DV_EIDAS_FINAL_CERTIFICATE
            )
        elif is_qualified:
            return (
                CertificateType.QNCP_W_DV_NON_EIDAS_PRE_CERTIFICATE if is_precert
                else CertificateType.QNCP_W_DV_NON_EIDAS_FINAL_CERTIFICATE
            )
        else:
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


def create_decoding_validators() -> List[validation.Validator]:
    return serverauth.create_decoding_validators()


def create_validators(certificate_type: CertificateType) -> List[validation.Validator]:

    subject_validators = [
        en_319_412_1.LegalPersonOrganizationIdentifierValidator(),
        organization_id.OrganizationIdentifierLeiValidator()
    ]

    qc_statements_validator_container = validation.ValidatorContainer(
        validators=[
            ts_119_495.RolesOfPspValidator(),
            ts_119_495.NCANameLatinCharactersValidator(),
            ts_119_495.NCAIdValidator(),
            en_319_412_5.QcCClegislationCountryCodeValidator(),
            en_319_412_5.QcEuRetentionPeriodValidator(),
            en_319_412_5.QcTypeValidator(),
            en_319_412_5.QcEuPDSHttpsURLValidator(),
            en_319_412_5.QcEuLimitValueValidator(),
            en_319_412_5.QcEuPDSLanguageValidator()
            ])
    if certificate_type in etsi_constants.QEVCP_W_PSD2_CERTIFICATE_TYPES:
        validators.append( ts_119_495.PresenceofQCEUPDSStatementValidator())

    qc_statements_validator_container = validation.ValidatorContainer(
        validators=validators,
        pdu_class=rfc3739.QCStatements
    )

    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        serverauth_cert_type = etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS[certificate_type]

        return serverauth.create_validators(
            serverauth_cert_type, additional_name_validators=subject_validators,
            additional_extension_validators=[qc_statements_validator_container],
        )
    else:
        return [
            certificate.create_issuer_validator_container(
                []
            ),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container(
                subject_validators
            ),
            certificate.create_extensions_validator_container(
                [qc_statements_validator_container]
            ),
        ]


def create_etsi_finding_filters(certificate_type) -> List[finding_filter.FindingDescriptionFilter]:
    if certificate_type in etsi_constants.CABF_CERTIFICATE_TYPES:
        serverauth_cert_type = etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS[certificate_type]

        return serverauth.create_serverauth_finding_filters(serverauth_cert_type)
    else:
        return []
