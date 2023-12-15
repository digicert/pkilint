import enum


EN_319_412_VERSION = '2023-09'


@enum.unique
class CertificateType(enum.IntEnum):
    QEVCP_W = 1,
    QNCP_W = 2,
    QNCP_W_GEN = 3,

    def __str__(self):
        return self.name

    @property
    def to_option_str(self):
        return self.name.replace('_', '-')

    @staticmethod
    def from_option_str(value):
        value = value.replace('-', '_').upper()

        return CertificateType[value]

