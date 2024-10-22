import enum

from pyasn1_alt_modules import rfc5280

from pkilint import validation, pkix, document
from pkilint.document import Document
from pkilint.pkix import name, extension, time, general_name
from pkilint.pkix.crl import crl_validator, crl_extension, crl_validity


@enum.unique
class CertificateRevocationListType(enum.IntEnum):
    CRL = 0
    ARL = 1


class RFC5280CertificateList(Document):
    def __init__(self, substrate_source, substrate, name=None, parent=None):
        super().__init__(
            rfc5280.CertificateList(), substrate_source, substrate, name, parent
        )

    @property
    def this_update(self):
        try:
            return time.parse_time_node(self.root.navigate("tbsCertList.thisUpdate"))
        except ValueError:
            return pkix.MAXIMUM_TIME_DATETIME

    @property
    def next_update(self):
        try:
            return time.parse_time_node(self.root.navigate("tbsCertList.nextUpdate"))
        except document.PDUNavigationFailedError:
            return None
        except ValueError:
            return pkix.MAXIMUM_TIME_DATETIME

    def get_extension_by_oid(self, oid):
        tbs_crl = self.root.children["tbsCertList"]

        # ensure there's extensions
        if "crlExtensions" not in tbs_crl.children:
            return None

        extensions_node = tbs_crl.children["crlExtensions"]

        for ext_idx, extension_node in extensions_node.children.items():
            ext_oid = extension_node.children["extnID"].pdu

            if ext_oid == oid:
                return extension_node, int(ext_idx)

        return None


def create_issuer_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []
    additional_validators.append(name.EmptyNameValidator())

    return pkix.create_name_validator_container(
        additional_validators, path="certificateList.tbsCertList.issuer"
    )


def create_validity_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []
    return validation.ValidatorContainer(
        validators=[
            time.TimeCorrectEncodingValidator(),
        ]
        + additional_validators,
        pdu_class=rfc5280.Time,
    )


def create_extensions_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []
    return validation.ValidatorContainer(
        validators=[
            # extension.PermittedExtensionValidator(
            #    known_oids=known_oids
            # ),
            extension.UniqueExtensionValidator(),
            crl_extension.CrlNumberCriticalityValidator(),
            extension.AuthorityKeyIdentifierValidator(),
        ]
        + additional_validators,
        path="certificateList.tbsCertList.crlExtensions",
    )


def create_pkix_crl_validator_container(decoding_validators, validators):
    decoding_validator_container = [
        validation.ValidatorContainer(
            validators=decoding_validators, path="certificateList"
        )
    ]

    validators += [
        crl_validator.VersionPresenceValidator(),
        crl_validator.CorrectVersionValidator(),
        crl_extension.CrlNumberPresenceValidator(),
        crl_extension.AuthorityKeyIdentifierPresenceValidator(),
        crl_validator.SignatureAlgorithmMatchValidator(),
        crl_validator.RevokedCertificatesEmptyValidator(),
        crl_extension.CrlReasonCodeCriticalityValidator(),
        time.UtcTimeCorrectSyntaxValidator(),
        time.GeneralizedTimeCorrectSyntaxValidator(),
        crl_validity.CrlSaneValidityPeriodValidator(),
        pkix.CertificateSerialNumberValidator(),
        crl_extension.CrlNumberValueValidator(),
        general_name.GeneralNameValidatorContainer(),
    ]

    return validation.ValidatorContainer(
        validators=decoding_validator_container + validators
    )
