import enum
import math
import sys

from pyasn1.type.univ import ObjectIdentifier


BR_VERSION = "1.0.9"


CABF_SMIME_OID_ARC = ObjectIdentifier("2.23.140.1.5")


@enum.unique
class ValidationLevel(enum.IntEnum):
    MAILBOX = 1
    ORGANIZATION = 2
    SPONSORED = 4
    INDIVIDUAL = 8

    def __str__(self):
        return self.name


[
    setattr(
        sys.modules[__name__],
        f"CABF_SMIME_{v.name}_OID_ARC",
        CABF_SMIME_OID_ARC + (int(math.log2(v)) + 1,),
    )
    for v in ValidationLevel
]


@enum.unique
class Generation(enum.IntEnum):
    LEGACY = 1 << 8
    MULTIPURPOSE = 1 << 9
    STRICT = 1 << 10

    def __str__(self):
        return self.name


def _define_oids(validation_level):
    [
        setattr(
            sys.modules[__name__],
            f"CABF_SMIME_{validation_level.name}_{g.name}_OID",
            CABF_SMIME_OID_ARC
            + (
                int(math.log2(validation_level)) + 1,
                int(math.log2(g >> 8)) + 1,
            ),
        )
        for g in Generation
    ]


[_define_oids(v) for v in ValidationLevel]


def get_policy_oid(validation_level, generation):
    return CABF_SMIME_OID_ARC + (
        int(math.log2(validation_level)) + 1,
        int(math.log2(generation >> 8)) + 1,
    )
