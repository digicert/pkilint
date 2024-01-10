import enum
from enum import auto

from pkilint.cabf.serverauth import serverauth_constants


EN_319_412_VERSION = '2023-09'


@enum.unique
class CertificateType(enum.IntEnum):
    DVCP_PRE_CERTIFICATE = auto()
    IVCP_PRE_CERTIFICATE = auto()
    OVCP_PRE_CERTIFICATE = auto()
    EVCP_PRE_CERTIFICATE = auto()
    NCP_NP_PRE_CERTIFICATE = auto()
    NCP_LP_PRE_CERTIFICATE = auto()
    QEVCP_W_PRE_CERTIFICATE = auto()
    QNCP_W_DV_PRE_CERTIFICATE = auto()
    QNCP_W_IV_PRE_CERTIFICATE = auto()
    QNCP_W_OV_PRE_CERTIFICATE = auto()
    QNCP_W_GEN_NP_PRE_CERTIFICATE = auto()
    QNCP_W_GEN_LP_PRE_CERTIFICATE = auto()
    QEVCP_W_PSD2_PRE_CERTIFICATE = auto()
    DVCP_FINAL_CERTIFICATE = auto()
    IVCP_FINAL_CERTIFICATE = auto()
    OVCP_FINAL_CERTIFICATE = auto()
    EVCP_FINAL_CERTIFICATE = auto()
    NCP_NP_FINAL_CERTIFICATE = auto()
    NCP_LP_FINAL_CERTIFICATE = auto()
    QEVCP_W_FINAL_CERTIFICATE = auto()
    QNCP_W_DV_FINAL_CERTIFICATE = auto()
    QNCP_W_IV_FINAL_CERTIFICATE = auto()
    QNCP_W_OV_FINAL_CERTIFICATE = auto()
    QNCP_W_GEN_NP_FINAL_CERTIFICATE = auto()
    QNCP_W_GEN_LP_FINAL_CERTIFICATE = auto()
    QEVCP_W_PSD2_FINAL_CERTIFICATE = auto()

    def __str__(self):
        return self.name

    @property
    def to_option_str(self):
        return self.name.replace('_', '-')

    @staticmethod
    def from_option_str(value):
        value = value.replace('-', '_').upper()

        return CertificateType[value]


DVCP_CERTIFICATE_TYPES = {CertificateType.DVCP_PRE_CERTIFICATE, CertificateType.DVCP_FINAL_CERTIFICATE}
IVCP_CERTIFICATE_TYPES = {CertificateType.IVCP_PRE_CERTIFICATE, CertificateType.IVCP_FINAL_CERTIFICATE}
OVCP_CERTIFICATE_TYPES = {CertificateType.OVCP_PRE_CERTIFICATE, CertificateType.OVCP_FINAL_CERTIFICATE}
EVCP_CERTIFICATE_TYPES = {CertificateType.EVCP_PRE_CERTIFICATE, CertificateType.EVCP_FINAL_CERTIFICATE}
NCP_NP_CERTIFICATE_TYPES = {CertificateType.NCP_NP_PRE_CERTIFICATE, CertificateType.NCP_NP_FINAL_CERTIFICATE}
NCP_LP_CERTIFICATE_TYPES = {CertificateType.NCP_LP_PRE_CERTIFICATE, CertificateType.NCP_LP_FINAL_CERTIFICATE}
QEVCP_W_CERTIFICATE_TYPES = {CertificateType.QEVCP_W_PRE_CERTIFICATE, CertificateType.QEVCP_W_FINAL_CERTIFICATE}
QNCP_W_DV_CERTIFICATE_TYPES = {CertificateType.QNCP_W_DV_PRE_CERTIFICATE, CertificateType.QNCP_W_DV_FINAL_CERTIFICATE}
QNCP_W_IV_CERTIFICATE_TYPES = {CertificateType.QNCP_W_IV_PRE_CERTIFICATE, CertificateType.QNCP_W_IV_FINAL_CERTIFICATE}
QNCP_W_OV_CERTIFICATE_TYPES = {CertificateType.QNCP_W_OV_PRE_CERTIFICATE, CertificateType.QNCP_W_OV_FINAL_CERTIFICATE}
QNCP_W_GEN_NP_CERTIFICATE_TYPES = {CertificateType.QNCP_W_GEN_NP_PRE_CERTIFICATE,
                                   CertificateType.QNCP_W_GEN_NP_FINAL_CERTIFICATE}
QNCP_W_GEN_LP_CERTIFICATE_TYPES = {CertificateType.QNCP_W_GEN_LP_PRE_CERTIFICATE,
                                   CertificateType.QNCP_W_GEN_LP_FINAL_CERTIFICATE}
QEVCP_W_PSD2_CERTIFICATE_TYPES = {CertificateType.QEVCP_W_PSD2_PRE_CERTIFICATE,
                                  CertificateType.QEVCP_W_PSD2_FINAL_CERTIFICATE}


CABF_DV_CERTIFICATE_TYPES = DVCP_CERTIFICATE_TYPES | QNCP_W_DV_CERTIFICATE_TYPES
CABF_IV_CERTIFICATE_TYPES = IVCP_CERTIFICATE_TYPES | QNCP_W_IV_CERTIFICATE_TYPES
CABF_OV_CERTIFICATE_TYPES = OVCP_CERTIFICATE_TYPES | QNCP_W_OV_CERTIFICATE_TYPES
CABF_EV_CERTIFICATE_TYPES = EVCP_CERTIFICATE_TYPES | QEVCP_W_CERTIFICATE_TYPES | QEVCP_W_PSD2_CERTIFICATE_TYPES

CABF_CERTIFICATE_TYPES = (
        CABF_DV_CERTIFICATE_TYPES |
        CABF_IV_CERTIFICATE_TYPES |
        CABF_OV_CERTIFICATE_TYPES |
        CABF_EV_CERTIFICATE_TYPES
)

NATURAL_PERSON_CERTIFICATE_TYPES = (CABF_IV_CERTIFICATE_TYPES | QNCP_W_GEN_NP_CERTIFICATE_TYPES |
                                    NCP_NP_CERTIFICATE_TYPES)

LEGAL_PERSON_CERTIFICATE_TYPES = (CABF_OV_CERTIFICATE_TYPES | CABF_EV_CERTIFICATE_TYPES |
                                  QNCP_W_GEN_LP_CERTIFICATE_TYPES | NCP_LP_CERTIFICATE_TYPES)

QWAC_TYPES = (QEVCP_W_CERTIFICATE_TYPES | QNCP_W_DV_CERTIFICATE_TYPES | QNCP_W_IV_CERTIFICATE_TYPES |
              QNCP_W_OV_CERTIFICATE_TYPES | QNCP_W_GEN_NP_CERTIFICATE_TYPES | QNCP_W_GEN_LP_CERTIFICATE_TYPES |
              QEVCP_W_PSD2_CERTIFICATE_TYPES)


ETSI_TYPE_TO_CABF_SERVERAUTH_TYPE_MAPPINGS = {
    CertificateType.DVCP_PRE_CERTIFICATE: serverauth_constants.CertificateType.DV_PRE_CERTIFICATE,
    CertificateType.IVCP_PRE_CERTIFICATE: serverauth_constants.CertificateType.IV_PRE_CERTIFICATE,
    CertificateType.OVCP_PRE_CERTIFICATE: serverauth_constants.CertificateType.OV_PRE_CERTIFICATE,
    CertificateType.EVCP_PRE_CERTIFICATE: serverauth_constants.CertificateType.EV_PRE_CERTIFICATE,
    CertificateType.QEVCP_W_PRE_CERTIFICATE: serverauth_constants.CertificateType.EV_PRE_CERTIFICATE,
    CertificateType.QNCP_W_DV_PRE_CERTIFICATE: serverauth_constants.CertificateType.DV_PRE_CERTIFICATE,
    CertificateType.QNCP_W_IV_PRE_CERTIFICATE: serverauth_constants.CertificateType.IV_PRE_CERTIFICATE,
    CertificateType.QNCP_W_OV_PRE_CERTIFICATE: serverauth_constants.CertificateType.OV_PRE_CERTIFICATE,
    CertificateType.QEVCP_W_PSD2_PRE_CERTIFICATE: serverauth_constants.CertificateType.EV_PRE_CERTIFICATE,

    CertificateType.DVCP_FINAL_CERTIFICATE: serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE,
    CertificateType.IVCP_FINAL_CERTIFICATE: serverauth_constants.CertificateType.IV_FINAL_CERTIFICATE,
    CertificateType.OVCP_FINAL_CERTIFICATE: serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE,
    CertificateType.EVCP_FINAL_CERTIFICATE: serverauth_constants.CertificateType.EV_FINAL_CERTIFICATE,
    CertificateType.QEVCP_W_FINAL_CERTIFICATE: serverauth_constants.CertificateType.EV_FINAL_CERTIFICATE,
    CertificateType.QNCP_W_DV_FINAL_CERTIFICATE: serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE,
    CertificateType.QNCP_W_IV_FINAL_CERTIFICATE: serverauth_constants.CertificateType.IV_FINAL_CERTIFICATE,
    CertificateType.QNCP_W_OV_FINAL_CERTIFICATE: serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE,
    CertificateType.QEVCP_W_PSD2_FINAL_CERTIFICATE: serverauth_constants.CertificateType.EV_FINAL_CERTIFICATE,
}
