from typing import List

from pyasn1_alt_modules import rfc5280, rfc6962

from pkilint import validation, finding_filter
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.etsi import etsi_constants, ts_119_495, en_319_412_5
from pkilint.etsi.asn1 import (
    en_319_412_1 as en_319_412_asn1, en_319_412_5 as en_319_412_5_asn1, ts_119_495 as ts_119_495_asn1
)
from pkilint.etsi.etsi_constants import CertificateType
from pkilint.pkix import certificate


def determine_certificate_type(cert: certificate.RFC5280Certificate) -> CertificateType:
    qualified_statement_ids = cert.qualified_statement_ids
    policy_oids = cert.policy_oids

    is_qualified = en_319_412_5_asn1.id_etsi_qcs_QcCompliance in qualified_statement_ids
    is_precert = cert.get_extension_by_oid(rfc6962.id_ce_criticalPoison) is not None

    if serverauth_constants.ID_POLICY_EV in policy_oids:
        is_psd2 = ts_119_495_asn1.id_etsi_psd2_qcStatement in qualified_statement_ids

        if is_psd2:
            return (CertificateType.QEVCP_W_PSD2_PRE_CERTIFICATE if is_precert
                    else CertificateType.QEVCP_W_PSD2_FINAL_CERTIFICATE)
        elif is_qualified:
            return CertificateType.QEVCP_W_PRE_CERTIFICATE if is_precert else CertificateType.QEVCP_W_FINAL_CERTIFICATE
        else:
            return CertificateType.EVCP_PRE_CERTIFICATE if is_precert else CertificateType.EVCP_FINAL_CERTIFICATE
    elif serverauth_constants.ID_POLICY_OV in policy_oids:
        if is_qualified:
            return (CertificateType.QNCP_W_OV_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_OV_FINAL_CERTIFICATE)
        else:
            return CertificateType.OVCP_PRE_CERTIFICATE if is_precert else CertificateType.OVCP_FINAL_CERTIFICATE
    elif serverauth_constants.ID_POLICY_IV in policy_oids:
        if is_qualified:
            return (CertificateType.QNCP_W_IV_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_IV_FINAL_CERTIFICATE)
        else:
            return CertificateType.IVCP_PRE_CERTIFICATE if is_precert else CertificateType.IVCP_FINAL_CERTIFICATE
    elif serverauth_constants.ID_POLICY_DV in policy_oids:
        if is_qualified:
            return (CertificateType.QNCP_W_DV_PRE_CERTIFICATE if is_precert
                    else CertificateType.QNCP_W_DV_FINAL_CERTIFICATE)
        else:
            return CertificateType.DVCP_PRE_CERTIFICATE if is_precert else CertificateType.DVCP_FINAL_CERTIFICATE
    else:
        is_natural_person = any((
            cert.get_subject_attributes_by_type(rfc5280.id_at_givenName),
            cert.get_subject_attributes_by_type(rfc5280.id_at_surname),
            cert.get_subject_attributes_by_type(rfc5280.id_at_pseudonym),
        ))

        if is_natural_person:
            if is_qualified:
                return (CertificateType.QNCP_W_GEN_NATURAL_PERSON_PRE_CERTIFICATE if is_precert
                        else CertificateType.QNCP_W_GEN_NATURAL_PERSON_FINAL_CERTIFICATE)
            else:
                return (CertificateType.NCP_NATURAL_PERSON_PRE_CERTIFICATE if is_precert
                        else CertificateType.NCP_NATURAL_PERSON_FINAL_CERTIFICATE)
        else:
            if is_qualified:
                return (CertificateType.QNCP_W_GEN_LEGAL_PERSON_PRE_CERTIFICATE if is_precert
                        else CertificateType.QNCP_W_GEN_LEGAL_PERSON_FINAL_CERTIFICATE)
            else:
                return (CertificateType.NCP_LEGAL_PERSON_PRE_CERTIFICATE if is_precert
                        else CertificateType.NCP_LEGAL_PERSON_FINAL_CERTIFICATE)


def create_decoding_validators() -> List[validation.Validator]:
    return serverauth.create_decoding_validators()


def create_validators(certificate_type: CertificateType) -> List[validation.Validator]:
    return [
        ts_119_495.RolesOfPspContainsRolesValidator(),
        en_319_412_5.CountryCodeNeededValidator(),
        en_319_412_5.CountryCodeNotValidValidator()
    ]

    # if certificate_type == CertificateType.QNCP_W:
    #    pass


#    else:
#        raise ValueError(f'Unsupported certificate type: {certificate_type}')


def create_etsi_finding_filters(certificate_type) -> List[finding_filter.FindingDescriptionFilter]:
    return []
