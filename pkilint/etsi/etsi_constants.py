import enum


EN_319_412_VERSION = '2023-09'


@enum.unique
class CertificateType(enum.IntEnum):
    DVCP = 1,
    IVCP = 2,
    OVCP = 3,
    EVCP = 4,
    NCP = 5,
    QEVCP_W = 6,
    QNCP_W_DV = 7,
    QNCP_W_IV = 8,
    QNCP_W_OV = 9,
    QNCP_W_GEN = 10,

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
CABF_EV_CERTIFICATE_TYPES = {CertificateType.QEVCP_W}

CABF_CERTIFICATE_TYPES = (
        CABF_DV_CERTIFICATE_TYPES |
        CABF_IV_CERTIFICATE_TYPES |
        CABF_OV_CERTIFICATE_TYPES |
        CABF_EV_CERTIFICATE_TYPES
)
