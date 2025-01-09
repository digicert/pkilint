import datetime
import functools
import logging
from typing import Set, Optional, List

from cryptography import x509, exceptions
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1.type.base import Asn1Type
from pyasn1_alt_modules import rfc5280, rfc3739

from pkilint import validation, pkix, document
from pkilint.document import Document, ValueDecoder
from pkilint.pkix import (
    extension,
    time,
    name,
    create_name_validator_container,
    general_name,
    algorithm,
    key,
)
from pkilint.pkix.certificate import (
    certificate_validity,
    certificate_extension,
    certificate_validator,
    certificate_key,
    certificate_name,
    certificate_transparency,
)

logger = logging.getLogger(__name__)


class RFC5280Certificate(Document):
    def __init__(self, substrate_source, substrate, name=None, parent=None):
        super().__init__(
            rfc5280.Certificate(), substrate_source, substrate, name, parent
        )

    @property
    def not_before(self):
        try:
            return time.parse_time_node(
                self.root.navigate("tbsCertificate.validity.notBefore")
            )
        except ValueError:
            return pkix.MAXIMUM_TIME_DATETIME

    @property
    def not_after(self):
        try:
            return time.parse_time_node(
                self.root.navigate("tbsCertificate.validity.notAfter")
            )
        except ValueError:
            return pkix.MAXIMUM_TIME_DATETIME

    @property
    def validity_period(self) -> datetime.timedelta:
        return (self.not_after - self.not_before) + datetime.timedelta(seconds=1)

    def _decode_and_append_extension(
        self, ext_oid: univ.ObjectIdentifier, ext_asn1_spec: Asn1Type
    ) -> Optional[document.PDUNode]:
        ext_and_idx = self.get_extension_by_oid(ext_oid)

        if ext_and_idx is None:
            return None

        ext, _ = ext_and_idx
        ext_value = ext.children["extnValue"]

        try:
            return document.decode_substrate(
                self, ext_value.pdu.asOctets(), ext_asn1_spec, ext_value
            )
        except ValueError:
            # suppress decoding errors, which will be reported by DecodingValidator instances
            return None

    @functools.cached_property
    def is_ca(self) -> bool:
        decoded = self._decode_and_append_extension(
            rfc5280.id_ce_basicConstraints, rfc5280.BasicConstraints()
        )

        return bool(decoded.navigate("cA").pdu) if decoded else False

    @functools.cached_property
    def extended_key_usages(self) -> Set[univ.ObjectIdentifier]:
        decoded = self._decode_and_append_extension(
            rfc5280.id_ce_extKeyUsage, rfc5280.ExtKeyUsageSyntax()
        )

        return (
            {eku_node.pdu for eku_node in decoded.children.values()}
            if decoded
            else set()
        )

    @functools.cached_property
    def qualified_statement_ids(self) -> Set[univ.ObjectIdentifier]:
        decoded = self._decode_and_append_extension(
            rfc3739.id_pe_qcStatements, rfc3739.QCStatements()
        )

        return (
            {qs.children["statementId"].pdu for qs in decoded.children.values()}
            if decoded
            else set()
        )

    @functools.cached_property
    def cryptography_object(self):
        return x509.load_der_x509_certificate(self.substrate)

    @functools.cached_property
    def is_self_issued(self):
        issuer_node = self.root.navigate("tbsCertificate.issuer")
        subject_node = self.root.navigate("tbsCertificate.subject")

        return encode(issuer_node.pdu) == encode(subject_node.pdu)

    @functools.cached_property
    def public_key_object(self):
        return key.convert_spki_to_object(
            self.root.navigate("tbsCertificate.subjectPublicKeyInfo")
        )

    def is_signed_with_key(self, public_key):
        tbs_octets = self.cryptography_object.tbs_certificate_bytes
        signature_hash_alg = self.cryptography_object.signature_hash_algorithm
        signature_octets = self.cryptography_object.signature

        return key.verify_signature(
            public_key, tbs_octets, signature_octets, signature_hash_alg
        )

    @functools.cached_property
    def is_self_signed(self):
        if not self.is_self_issued:
            return False

        public_key = self.public_key_object

        # return False if the certificate certifies an unsupported public key type
        if public_key is None:
            return False

        try:
            self.is_signed_with_key(public_key)

        # gracefully handle unsupported signature algorithms
        except exceptions.UnsupportedAlgorithm:
            return False

    def get_extension_by_oid(self, oid):
        tbs_cert = self.root.children["tbsCertificate"]

        # ensure there's extensions
        if "extensions" not in tbs_cert.children:
            return None

        extensions_node = tbs_cert.children["extensions"]

        for ext_idx, extension_node in extensions_node.children.items():
            ext_oid = extension_node.children["extnID"].pdu

            if ext_oid == oid:
                return extension_node, int(ext_idx)

        return None

    def get_name_attributes_by_type(self, oid, name_path):
        name_node = self.root.navigate(name_path)

        return name.get_name_attributes_by_type(name_node, oid)

    def get_issuer_attributes_by_type(self, oid):
        return self.get_name_attributes_by_type(oid, "tbsCertificate.issuer")

    def get_subject_attributes_by_type(self, oid):
        return self.get_name_attributes_by_type(oid, "tbsCertificate.subject")

    @functools.cached_property
    def policy_oids(self) -> Set[univ.ObjectIdentifier]:
        decoded = self._decode_and_append_extension(
            rfc5280.id_ce_certificatePolicies, rfc5280.CertificatePolicies()
        )

        return (
            {pi.children["policyIdentifier"].pdu for pi in decoded.children.values()}
            if decoded
            else set()
        )

    def get_san_general_names_by_type(
        self, general_name_type: general_name.GeneralNameTypeName
    ) -> List[document.PDUNode]:
        decoded = self._decode_and_append_extension(
            rfc5280.id_ce_subjectAltName, rfc5280.SubjectAltName()
        )

        return (
            []
            if decoded is None
            else [
                gn.children[general_name_type]
                for gn in decoded.children.values()
                if general_name_type in gn.children
            ]
        )


def create_spki_decoder(
    subject_public_key_type_mappings, subject_public_key_parameters_type_mappings
):
    subject_public_key_decoder = certificate_key.SubjectPublicKeyDecoder(
        type_mappings=subject_public_key_type_mappings
    )
    subject_public_key_parameters_decoder = (
        certificate_key.SubjectPublicKeyParametersDecoder(
            type_mappings=subject_public_key_parameters_type_mappings
        )
    )

    return validation.ValidatorContainer(
        validators=[
            certificate_key.SubjectPublicKeyDecodingValidator(
                decode_func=subject_public_key_decoder
            ),
            certificate_key.SubjectPublicKeyParametersDecodingValidator(
                decode_func=subject_public_key_parameters_decoder
            ),
        ],
        pdu_class=rfc5280.SubjectPublicKeyInfo,
    )


def create_policy_qualifier_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path="policyQualifierId",
        value_path="qualifier",
        type_mappings=type_mappings,
    )

    return validation.DecodingValidator(
        decode_func=decoder, pdu_class=rfc5280.PolicyQualifierInfo
    )


def create_other_name_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path="type-id", value_path="value", type_mappings=type_mappings
    )

    return validation.DecodingValidator(
        decode_func=decoder, pdu_class=rfc5280.AnotherName
    )


def create_qc_statements_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path="statementId", value_path="statementInfo", type_mappings=type_mappings
    )

    return validation.DecodingValidator(
        decode_func=decoder, pdu_class=rfc3739.QCStatement
    )


def create_issuer_validator_container(additional_validators=None, **kwargs):
    if additional_validators is None:
        additional_validators = []

    if len(kwargs) == 0:
        kwargs["path"] = "certificate.tbsCertificate.issuer"

    return create_name_validator_container(
        [
            name.EmptyNameValidator(),
            general_name.MailboxAddressSyntaxValidator(pdu_class=rfc5280.EmailAddress),
        ]
        + additional_validators,
        **kwargs
    )


def create_subject_validator_container(additional_validators=None, **kwargs):
    if additional_validators is None:
        additional_validators = []

    if len(kwargs) == 0:
        kwargs["path"] = "certificate.tbsCertificate.subject"

    return create_name_validator_container(
        [
            certificate_name.SubjectEmailAddressInSanValidator(),
            general_name.MailboxAddressSyntaxValidator(pdu_class=rfc5280.EmailAddress),
            name.DomainComponentValidDomainNameValidator(pdu_class=rfc5280.Name),
        ]
        + additional_validators,
        **kwargs
    )


def create_validity_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []
    return validation.ValidatorContainer(
        validators=[
            certificate_validity.CertificateSaneValidityPeriodValidator(),
            time.TimeCorrectEncodingValidator(),
        ]
        + additional_validators,
        path="certificate.tbsCertificate.validity",
    )


def create_spki_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []

    return validation.ValidatorContainer(
        validators=[
            certificate_key.CaPrehashPublicKeyValidator(),
            certificate_key.ObsoletePublicKeyAlgorithmValidator(),
        ]
        + additional_validators,
        path="certificate.tbsCertificate.subjectPublicKeyInfo",
    )


def create_extensions_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []
    return validation.ValidatorContainer(
        validators=[
            extension.UniqueExtensionValidator(),
            certificate_extension.BasicConstraintsValidator(),
            certificate_extension.CertificatePolicyQualifierValidator(),
            certificate_extension.CertificatePoliciesUserNoticeValidator(),
            certificate_key.SubjectKeyIdentifierValidator(),
            certificate_extension.SubjectKeyIdentifierCriticalityValidator(),
            certificate_extension.KeyUsageCriticalityValidator(),
            certificate_extension.KeyUsageValidator(),
            certificate_key.SpkiKeyUsageConsistencyValidator(),
            general_name.UriSyntaxValidator(pdu_class=rfc5280.CPSuri),
            general_name.GeneralNameValidatorContainer(),
            certificate_extension.DuplicatePolicyValidator(),
            certificate_extension.CrlDpCriticalityValidator(),
            certificate_extension.NameConstraintsCriticalityValidator(),
            extension.AuthorityKeyIdentifierValidator(),
            extension.AuthorityKeyIdentifierCriticalityValidator(),
            certificate_extension.NameConstraintsValidator(),
            certificate_extension.NameConstraintsGeneralSubtreeValidator(),
            certificate_extension.AuthorityInformationAccessCriticalityValidator(),
            certificate_extension.SubjectInformationAccessCriticalityValidator(),
            certificate_extension.SubjectAlternativeNameCriticalityValidator(),
            certificate_extension.SubjectDirectoryAttributesCriticalityValidator(),
            certificate_extension.SmimeCapabilitiesCriticalityValidator(),
            extension.DistributionPointValidator(),
            certificate_extension.CtPrecertPoisonCriticalityValidator(),
            certificate_extension.CtPrecertPoisonSctListMutuallyExclusiveExtensionsValidator(),
            certificate_transparency.SctListElementCountValidator(),
            certificate_extension.PolicyConstraintsPresenceValidator(),
            certificate_extension.PolicyMappingsPresenceValidator(),
            certificate_extension.InhibitAnyPolicyPresenceValidator(),
            certificate_extension.ProhibitedQualifiedStatementValidator(),
            certificate_extension.IssuerAlternativeNameCriticalityValidator(),
        ]
        + additional_validators,
        path="certificate.tbsCertificate.extensions",
    )


def create_pkix_certificate_validator_container(decoding_validators, validators):
    decoding_validator_container = [
        validation.ValidatorContainer(
            validators=decoding_validators, path="certificate"
        )
    ]

    validators += [
        certificate_validator.CorrectVersionValidator(),
        pkix.CertificateSerialNumberValidator(),
        certificate_validator.SignatureAlgorithmMatchValidator(),
        certificate_extension.SubjectKeyIdentifierPresenceValidator(),
        certificate_extension.AuthorityKeyIdentifierPresenceValidator(),
        certificate_extension.KeyUsagePresenceValidator(),
        time.UtcTimeCorrectSyntaxValidator(),
        time.GeneralizedTimeCorrectSyntaxValidator(),
        certificate_validator.IssuerUniqueIdAbsenceValidator(),
        certificate_validator.SubjectUniqueIdAbsenceValidator(),
    ]

    return validation.ValidatorContainer(
        validators=decoding_validator_container + validators
    )


def create_decoding_validators(
    name_mappings, extension_mappings, additional_decoding_validators=None
):
    if additional_decoding_validators is None:
        additional_decoding_validators = []
    return [
        pkix.create_attribute_decoder(name_mappings),
        pkix.create_extension_decoder(extension_mappings),
        pkix.create_signature_algorithm_identifier_decoder(
            algorithm.SIGNATURE_ALGORITHM_IDENTIFIER_MAPPINGS,
            path="certificate.tbsCertificate.signature",
        ),
        create_spki_decoder(
            key.SUBJECT_PUBLIC_KEY_ALGORITHM_IDENTIFIER_MAPPINGS,
            key.SUBJECT_KEY_PARAMETER_ALGORITHM_IDENTIFIER_MAPPINGS,
        ),
        create_policy_qualifier_decoder(
            certificate_extension.CERTIFICATE_POLICY_QUALIFIER_MAPPINGS
        ),
        create_other_name_decoder(general_name.OTHER_NAME_MAPPINGS),
        certificate_transparency.SctListExtensionDecodingValidator(),
    ] + additional_decoding_validators
