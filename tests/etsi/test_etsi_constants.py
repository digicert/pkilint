from pkilint.etsi import etsi_constants
from pkilint.etsi.etsi_constants import CertificateType

_QNCP_W_GEN_LP_PSD2_TYPES = {
    CertificateType.QNCP_W_GEN_LEGAL_PERSON_PSD2_EIDAS_PRE_CERTIFICATE,
    CertificateType.QNCP_W_GEN_LEGAL_PERSON_PSD2_EIDAS_FINAL_CERTIFICATE,
}


def test_qncp_w_gen_lp_psd2_types_are_psd2_types():
    """The QNCP-w-gen PSD2 types must be PSD2 types, otherwise Psd2CertificatePolicyOidPresenceValidator
    rejects the QCP-w-psd2 policy identifier that TS 119 495 OVR-6.1-3 explicitly permits.
    """
    assert _QNCP_W_GEN_LP_PSD2_TYPES <= etsi_constants.PSD2_EIDAS_CERTIFICATE_TYPES


def test_qncp_w_gen_lp_psd2_types_are_eu_qwacs():
    """EU_QWAC_TYPES is a literal enumeration rather than a composed set, so new EU QWAC types must be added
    to it explicitly. Membership drives the QcStatement allowance rules in EN 319 412-5.
    """
    assert _QNCP_W_GEN_LP_PSD2_TYPES <= etsi_constants.EU_QWAC_TYPES
    assert _QNCP_W_GEN_LP_PSD2_TYPES <= etsi_constants.EU_TYPES


def test_qncp_w_gen_lp_psd2_types_are_qncp_w_gen_legal_person():
    assert (
        _QNCP_W_GEN_LP_PSD2_TYPES
        <= etsi_constants.QNCP_W_GEN_LP_EIDAS_CERTIFICATE_TYPES
    )
    assert _QNCP_W_GEN_LP_PSD2_TYPES <= etsi_constants.LEGAL_PERSON_CERTIFICATE_TYPES


def test_qncp_w_gen_lp_psd2_types_are_not_cabf():
    """TS 119 495 OVR-6.1-3A states that QNCP-w-gen applies to TLS authentication outside the context of a web
    browser, so the CA/Browser Forum serverauth profile must not be applied to these types. Membership in
    CABF_CERTIFICATE_TYPES would additionally require an entry in
    ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS, which is deliberately absent."""
    assert not (_QNCP_W_GEN_LP_PSD2_TYPES & etsi_constants.CABF_CERTIFICATE_TYPES)

    for certificate_type in _QNCP_W_GEN_LP_PSD2_TYPES:
        assert (
            certificate_type
            not in etsi_constants.ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS
        )


def test_qevcp_w_psd2_types_remain_psd2_types():
    """Widening PSD2_EIDAS_CERTIFICATE_TYPES must not drop the pre-existing QEVCP-w PSD2 types."""
    assert (
        etsi_constants.QEVCP_W_PSD2_EIDAS_CERTIFICATE_TYPES
        <= etsi_constants.PSD2_EIDAS_CERTIFICATE_TYPES
    )
