import enum
from enum import auto

from pyasn1.type.univ import ObjectIdentifier

BR_VERSION = "2.1.5"


ID_POLICY_EV = ObjectIdentifier("2.23.140.1.1")
ID_POLICY_DV = ObjectIdentifier("2.23.140.1.2.1")
ID_POLICY_OV = ObjectIdentifier("2.23.140.1.2.2")
ID_POLICY_IV = ObjectIdentifier("2.23.140.1.2.3")

SERVERAUTH_RESERVED_POLICY_OIDS = {
    ID_POLICY_EV,
    ID_POLICY_DV,
    ID_POLICY_OV,
    ID_POLICY_IV,
}


@enum.unique
class CertificateType(enum.IntEnum):
    ROOT_CA = auto()
    INTERNAL_CROSS_CA = auto()
    EXTERNAL_CROSS_CA = auto()
    INTERNAL_SUBSCRIBER_ISSUING_CROSS_CA = auto()
    EXTERNAL_SUBSCRIBER_ISSUING_CROSS_CA = auto()
    NON_TLS_CA = auto()
    PRECERT_SIGNING_CA = auto()
    INTERNAL_UNCONSTRAINED_TLS_CA = auto()
    INTERNAL_CONSTRAINED_TLS_CA = auto()
    EXTERNAL_UNCONSTRAINED_TLS_CA = auto()
    EXTERNAL_UNCONSTRAINED_EV_TLS_CA = auto()
    EXTERNAL_CONSTRAINED_TLS_CA = auto()
    EXTERNAL_CONSTRAINED_EV_TLS_CA = auto()
    DV_FINAL_CERTIFICATE = auto()
    IV_FINAL_CERTIFICATE = auto()
    OV_FINAL_CERTIFICATE = auto()
    EV_FINAL_CERTIFICATE = auto()
    OCSP_RESPONDER = auto()
    DV_PRE_CERTIFICATE = auto()
    IV_PRE_CERTIFICATE = auto()
    OV_PRE_CERTIFICATE = auto()
    EV_PRE_CERTIFICATE = auto()

    def __str__(self):
        return self.name

    @property
    def to_option_str(self):
        return self.name.replace("_", "-")

    @staticmethod
    def from_option_str(value):
        value = value.replace("-", "_").upper()

        return CertificateType[value]


INTERNAL_CROSS_CA_TYPES = {
    CertificateType.INTERNAL_CROSS_CA,
    CertificateType.INTERNAL_SUBSCRIBER_ISSUING_CROSS_CA,
}


EXTERNAL_CROSS_CA_TYPES = {
    CertificateType.EXTERNAL_CROSS_CA,
    CertificateType.EXTERNAL_SUBSCRIBER_ISSUING_CROSS_CA,
}


CROSS_CA_TYPES = INTERNAL_CROSS_CA_TYPES | EXTERNAL_CROSS_CA_TYPES


ROOT_KEY_CROSS_CA_TYPES = {
    CertificateType.INTERNAL_CROSS_CA,
    CertificateType.EXTERNAL_CROSS_CA,
}


INTERNAL_CA_TYPES = {
    CertificateType.INTERNAL_CROSS_CA,
    CertificateType.INTERNAL_SUBSCRIBER_ISSUING_CROSS_CA,
    CertificateType.INTERNAL_UNCONSTRAINED_TLS_CA,
    CertificateType.INTERNAL_CONSTRAINED_TLS_CA,
    CertificateType.NON_TLS_CA,
}

EXTERNAL_CA_TYPES = {
    CertificateType.EXTERNAL_UNCONSTRAINED_TLS_CA,
    CertificateType.EXTERNAL_CONSTRAINED_EV_TLS_CA,
    CertificateType.EXTERNAL_UNCONSTRAINED_EV_TLS_CA,
    CertificateType.EXTERNAL_CONSTRAINED_TLS_CA,
    CertificateType.EXTERNAL_CROSS_CA,
    CertificateType.EXTERNAL_SUBSCRIBER_ISSUING_CROSS_CA,
}

INTERMEDIATE_CERTIFICATE_TYPES = (
    INTERNAL_CA_TYPES | EXTERNAL_CA_TYPES | {CertificateType.PRECERT_SIGNING_CA}
)

CONSTRAINED_TLS_CA_TYPES = {
    CertificateType.EXTERNAL_CONSTRAINED_EV_TLS_CA,
    CertificateType.EXTERNAL_CONSTRAINED_TLS_CA,
    CertificateType.INTERNAL_CONSTRAINED_TLS_CA,
}

TLS_CA_TYPES = (
    {
        CertificateType.INTERNAL_UNCONSTRAINED_TLS_CA,
        CertificateType.INTERNAL_CONSTRAINED_TLS_CA,
    }
    | EXTERNAL_CA_TYPES
    | INTERNAL_CROSS_CA_TYPES
)

SUBSCRIBER_FINAL_CERTIFICATE_TYPES = {
    CertificateType.DV_FINAL_CERTIFICATE,
    CertificateType.IV_FINAL_CERTIFICATE,
    CertificateType.OV_FINAL_CERTIFICATE,
    CertificateType.EV_FINAL_CERTIFICATE,
}

SUBSCRIBER_PRECERT_TYPES = {
    CertificateType.DV_PRE_CERTIFICATE,
    CertificateType.IV_PRE_CERTIFICATE,
    CertificateType.OV_PRE_CERTIFICATE,
    CertificateType.EV_PRE_CERTIFICATE,
}

SUBSCRIBER_CERTIFICATE_TYPES = (
    SUBSCRIBER_FINAL_CERTIFICATE_TYPES | SUBSCRIBER_PRECERT_TYPES
)

DV_CERTIFICATE_TYPES = {
    CertificateType.DV_PRE_CERTIFICATE,
    CertificateType.DV_FINAL_CERTIFICATE,
}
IV_CERTIFICATE_TYPES = {
    CertificateType.IV_PRE_CERTIFICATE,
    CertificateType.IV_FINAL_CERTIFICATE,
}
OV_CERTIFICATE_TYPES = {
    CertificateType.OV_PRE_CERTIFICATE,
    CertificateType.OV_FINAL_CERTIFICATE,
}
EV_CERTIFICATE_TYPES = {
    CertificateType.EV_PRE_CERTIFICATE,
    CertificateType.EV_FINAL_CERTIFICATE,
}

IDENTITY_CERTIFICATE_TYPES = (
    IV_CERTIFICATE_TYPES | OV_CERTIFICATE_TYPES | EV_CERTIFICATE_TYPES
)
