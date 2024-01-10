import enum


EN_319_412_VERSION = '2023-09'


@enum.unique
class CertificateType(enum.IntEnum):
    DVCP = 1,
    IVCP = 2,
    OVCP = 3,
    EVCP = 4,
    NCP_NP = 5,
    NCP_LP = 6,
    QEVCP_W = 7,
    QNCP_W_DV = 8,
    QNCP_W_IV = 9,
    QNCP_W_OV = 10,
    QNCP_W_GEN_NP = 11,
    QNCP_W_GEN_LP = 12,
    QEVCP_W_PSD2 = 13,

    def __str__(self):
        return self.name

    @property
    def to_option_str(self):
        return self.name.replace('_', '-')

    @staticmethod
    def from_option_str(value):
        value = value.replace('-', '_').upper()

        return CertificateType[value]


CABF_DV_CERTIFICATE_TYPES = {CertificateType.DVCP, CertificateType.QNCP_W_DV}
CABF_IV_CERTIFICATE_TYPES = {CertificateType.IVCP, CertificateType.QNCP_W_IV}
CABF_OV_CERTIFICATE_TYPES = {CertificateType.OVCP, CertificateType.QNCP_W_OV}
CABF_EV_CERTIFICATE_TYPES = {CertificateType.EVCP, CertificateType.QEVCP_W, CertificateType.QEVCP_W_PSD2}

CABF_CERTIFICATE_TYPES = (
        CABF_DV_CERTIFICATE_TYPES |
        CABF_IV_CERTIFICATE_TYPES |
        CABF_OV_CERTIFICATE_TYPES |
        CABF_EV_CERTIFICATE_TYPES
)

NATURAL_PERSON_CERTIFICATE_TYPES = {CertificateType.IVCP, CertificateType.QNCP_W_IV, CertificateType.QNCP_W_GEN_NP}

LEGAL_PERSON_CERTIFICATE_TYPES = {CertificateType.OVCP, CertificateType.EVCP, CertificateType.QNCP_W_IV,
                                  CertificateType.QEVCP_W, CertificateType.QEVCP_W_PSD2, CertificateType.QNCP_W_GEN_LP}

QWAC_TYPES = {CertificateType.QEVCP_W, CertificateType.QNCP_W_DV, CertificateType.QNCP_W_OV, CertificateType.QNCP_W_IV,
              CertificateType.QNCP_W_GEN_NP, CertificateType.QNCP_W_GEN_LP, CertificateType.QEVCP_W_PSD2
              }
