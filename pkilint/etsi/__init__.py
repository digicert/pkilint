from typing import List

from pyasn1_alt_modules import rfc5280

from pkilint import validation, finding_filter
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.etsi import etsi_constants, ts_119_495
from pkilint.etsi.asn1 import (
    en_319_412_1 as en_319_412_asn1, en_319_412_5 as en_319_412_5_asn1, ts_119_495 as ts_119_495_asn1
)
from pkilint.etsi.etsi_constants import CertificateType
from pkilint.pkix import certificate


def determine_certificate_type(cert: certificate.RFC5280Certificate) -> CertificateType:
    qualified_statement_ids = cert.qualified_statement_ids
    policy_oids = cert.policy_oids

    is_qualified = en_319_412_5_asn1.id_etsi_qcs_QcCompliance in qualified_statement_ids

    if serverauth_constants.ID_POLICY_EV in policy_oids:
        is_psd2 = ts_119_495_asn1.id_etsi_psd2_qcStatement in qualified_statement_ids

        if is_psd2:
            return CertificateType.QEVCP_W_PSD2
        elif is_qualified:
            return CertificateType.QEVCP_W
        else:
            return CertificateType.EVCP
    elif serverauth_constants.ID_POLICY_OV in policy_oids:
        return CertificateType.QNCP_W_OV if is_qualified else CertificateType.OVCP
    elif serverauth_constants.ID_POLICY_IV in policy_oids:
        return CertificateType.QNCP_W_IV if is_qualified else CertificateType.IVCP
    elif serverauth_constants.ID_POLICY_DV in policy_oids:
        return CertificateType.QNCP_W_DV if is_qualified else CertificateType.DVCP
    else:
        is_natural_person = any((
            cert.get_subject_attributes_by_type(rfc5280.id_at_givenName),
            cert.get_subject_attributes_by_type(rfc5280.id_at_surname),
            cert.get_subject_attributes_by_type(rfc5280.id_at_pseudonym),
        ))

        if is_natural_person:
            return CertificateType.QNCP_W_GEN_NP if is_qualified else CertificateType.NCP_NP
        else:
            return CertificateType.QNCP_W_GEN_LP if is_qualified else CertificateType.NCP_LP


def create_decoding_validators() -> List[validation.Validator]:
    return serverauth.create_decoding_validators()


def create_validators(certificate_type: CertificateType) -> List[validation.Validator]:
    return [
        ts_119_495.RolesOfPspContainsRolesValidator(),
    ]

    # if certificate_type == CertificateType.QNCP_W:
    #    pass


#    else:
#        raise ValueError(f'Unsupported certificate type: {certificate_type}')


def create_etsi_finding_filters(certificate_type) -> List[finding_filter.FindingDescriptionFilter]:
    return []
