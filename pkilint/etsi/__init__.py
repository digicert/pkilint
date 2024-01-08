from typing import List

from pkilint import validation, finding_filter
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.etsi import etsi_constants
from pkilint.etsi.asn1 import en_319_412_5
from pkilint.etsi.etsi_constants import CertificateType
from pkilint.pkix import certificate


def determine_certificate_type(cert: certificate.RFC5280Certificate) -> CertificateType:
    qualified_statement_ids = cert.qualified_statement_ids
    policy_oids = cert.policy_oids

    is_qualified = en_319_412_5.id_etsi_qcs_QcCompliance in qualified_statement_ids

    if serverauth_constants.ID_POLICY_EV in policy_oids:
        return CertificateType.QEVCP_W if is_qualified else CertificateType.EVCP
    elif serverauth_constants.ID_POLICY_OV in policy_oids:
        return CertificateType.QNCP_W_OV if is_qualified else CertificateType.OVCP
    elif serverauth_constants.ID_POLICY_IV in policy_oids:
        return CertificateType.QNCP_W_IV if is_qualified else CertificateType.IVCP
    elif serverauth_constants.ID_POLICY_DV in policy_oids:
        return CertificateType.QNCP_W_DV if is_qualified else CertificateType.DVCP
    else:
        return CertificateType.QNCP_W_GEN if is_qualified else CertificateType.NCP


def create_decoding_validators() -> List[validation.Validator]:
    return []


def create_validators(certificate_type: CertificateType) -> List[validation.Validator]:
    return []

    # if certificate_type == CertificateType.QNCP_W:
    #    pass


#    else:
#        raise ValueError(f'Unsupported certificate type: {certificate_type}')


def create_etsi_finding_filters(certificate_type) -> List[finding_filter.FindingDescriptionFilter]:
    return []
