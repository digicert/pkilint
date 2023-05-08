import functools
import logging
from typing import Optional

from cryptography import x509, exceptions
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, dsa, ec, ed25519, ed448
)
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc3739

from pkilint import validation, pkix, document
from pkilint.document import Document, ValueDecoder
from pkilint.itu.bitstring import NamedBitStringMinimalEncodingValidator
from pkilint.itu.string import PrintableStringConstraintValidator
from pkilint.pkix import (extension, time, name,
                          create_name_validator_container, general_name, algorithm
                          )
from pkilint.pkix.certificate import (
    certificate_validity, certificate_extension, certificate_validator,
    certificate_key, certificate_name,
)

logger = logging.getLogger(__name__)


class RFC5280Certificate(Document):
    def __init__(self, substrate_source, substrate,
                 name=None, parent=None
                 ):
        super().__init__(
            rfc5280.Certificate(), substrate_source, substrate, name, parent
        )

    @property
    def not_before(self):
        return time.parse_time_node(
            self.root.navigate('tbsCertificate.validity.notBefore')
        )

    @property
    def not_after(self):
        return time.parse_time_node(
            self.root.navigate('tbsCertificate.validity.notAfter')
        )

    @property
    def is_ca(self) -> Optional[bool]:
        ext_and_idx = self.get_extension_by_oid(rfc5280.id_ce_basicConstraints)

        if ext_and_idx is None:
            return False

        ext, _ = ext_and_idx

        try:
            return bool(ext.navigate('extnValue.basicConstraints.cA').pdu)
        except document.PDUNavigationFailedError:
            return None

    @functools.cached_property
    def cryptography_object(self):
        return x509.load_der_x509_certificate(self.substrate)

    @functools.cached_property
    def is_self_issued(self):
        issuer_node = self.root.navigate('tbsCertificate.issuer')
        subject_node = self.root.navigate('tbsCertificate.subject')

        return encode(issuer_node.pdu) == encode(subject_node.pdu)

    @functools.cached_property
    def is_self_signed(self):
        if not self.is_self_issued:
            return False

        public_key = self.cryptography_object.public_key()
        tbs_octets = self.cryptography_object.tbs_certificate_bytes
        hash_alg = self.cryptography_object.signature_hash_algorithm
        signature_octets = self.cryptography_object.signature

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature_octets,
                    tbs_octets,
                    padding.PKCS1v15(),
                    hash_alg
                )
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(
                    signature_octets,
                    tbs_octets,
                    hash_alg
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature_octets,
                    tbs_octets,
                    ec.ECDSA(hash_alg)
                )
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(
                    signature_octets,
                    tbs_octets
                )
            elif isinstance(public_key, ed448.Ed448PublicKey):
                public_key.verify(
                    signature_octets,
                    tbs_octets
                )
        except exceptions.InvalidSignature:
            logger.exception('Signature validation failed')

            return False

        return True

    def get_extension_by_oid(self, oid):
        tbs_cert = self.root.children['tbsCertificate']

        # ensure there's extensions
        if 'extensions' not in tbs_cert.children:
            return None

        extensions_node = tbs_cert.children['extensions']

        for ext_idx, extension_node in extensions_node.children.items():
            ext_oid = extension_node.children['extnID'].pdu

            if ext_oid == oid:
                return extension_node, int(ext_idx)

        return None

    def get_name_attributes_by_type(self, oid, name_path):
        name_node = self.root.navigate(name_path)

        return name.get_name_attributes_by_type(name_node, oid)

    def get_issuer_attributes_by_type(self, oid):
        return self.get_name_attributes_by_type(oid, 'tbsCertificate.issuer')

    def get_subject_attributes_by_type(self, oid):
        return self.get_name_attributes_by_type(oid, 'tbsCertificate.subject')

    def has_policy_oid(self, oid, inhibit_anypolicy=False):
        ext = self.get_extension_by_oid(rfc5280.id_ce_certificatePolicies)

        if ext is None:
            return False

        ext_value, _ = ext

        oids = [
            pi.children['policyIdentifier'].pdu
            for pi in (
                ext_value.navigate(
                    'extnValue.certificatePolicies'
                ).children.values()
            )
        ]

        if not inhibit_anypolicy and rfc5280.anyPolicy in oids:
            return True

        return oid in oids


def create_spki_decoder(subject_public_key_type_mappings, subject_public_key_parameters_type_mappings):
    subject_public_key_decoder = certificate_key.SubjectPublicKeyDecoder(
        type_mappings=subject_public_key_type_mappings
    )
    subject_public_key_parameters_decoder = certificate_key.SubjectPublicKeyParametersDecoder(
        type_mappings=subject_public_key_parameters_type_mappings
    )

    return validation.ValidatorContainer(
        validators=[
            certificate_key.SubjectPublicKeyDecodingValidator(
                decode_func=subject_public_key_decoder
            ),
            certificate_key.SubjectPublicKeyParametersDecodingValidator(
                decode_func=subject_public_key_parameters_decoder
            )
        ],
        pdu_class=rfc5280.SubjectPublicKeyInfo
    )


def create_policy_qualifier_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path='policyQualifierId',
        value_path='qualifier',
        type_mappings=type_mappings
    )

    return validation.DecodingValidator(decode_func=decoder,
                                        pdu_class=rfc5280.PolicyQualifierInfo
                                        )


def create_other_name_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path='type-id',
        value_path='value',
        type_mappings=type_mappings
    )

    return validation.DecodingValidator(decode_func=decoder,
                                        pdu_class=rfc5280.AnotherName
                                        )


def create_qc_statements_decoder(type_mappings):
    decoder = ValueDecoder(
        type_path='statementId',
        value_path='statementInfo',
        type_mappings=type_mappings
    )

    return validation.DecodingValidator(decode_func=decoder, pdu_class=rfc3739.QCStatement)


def create_issuer_validator_container(additional_validators=None, **kwargs):
    if additional_validators is None:
        additional_validators = []

    if len(kwargs) == 0:
        kwargs['path'] = 'certificate.tbsCertificate.issuer'

    return create_name_validator_container([
                                                 name.EmptyNameValidator(),
                                                 general_name.MailboxAddressSyntaxValidator(
                                                     pdu_class=rfc5280.EmailAddress
                                                 )
                                             ] + additional_validators,
                                           **kwargs
    )


def create_subject_validator_container(additional_validators=None, **kwargs):
    if additional_validators is None:
        additional_validators = []

    if len(kwargs) == 0:
        kwargs['path'] = 'certificate.tbsCertificate.subject'

    return create_name_validator_container([
                                                  certificate_name.SubjectEmailAddressInSanValidator(),
                                                  general_name.MailboxAddressSyntaxValidator(
                                                      pdu_class=rfc5280.EmailAddress
                                                  ),
                                                  name.DomainComponentValidDomainNameValidator(
                                                      pdu_class=rfc5280.Name
                                                  ),
                                              ] + additional_validators,
                                           **kwargs
    )


def create_validity_validator_container(additional_validators=None):
    if additional_validators is None:
        additional_validators = []
    return validation.ValidatorContainer(
        validators=[
                       certificate_validity.CertificateSaneValidityPeriodValidator(),
                       time.TimeCorrectEncodingValidator(),
                   ] + additional_validators,
        path='certificate.tbsCertificate.validity'
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
                       general_name.UriSyntaxValidator(pdu_class=rfc5280.CPSuri),
                       general_name.GeneralNameUriSyntaxValidator(),
                       general_name.GeneralNameDnsNameSyntaxValidator(),
                       general_name.GeneralNameIpAddressSyntaxValidator(),
                       general_name.GeneralNameMailboxAddressSyntaxValidator(),
                       general_name.SmtpUTF8MailboxValidator(),
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
                   ] + additional_validators,
        path='certificate.tbsCertificate.extensions'
    )


def create_pkix_certificate_validator_container(
        decoding_validators, validators):
    decoding_validator_container = [
        validation.ValidatorContainer(
            validators=decoding_validators, path='certificate'
        )
    ]

    validators += [
        PrintableStringConstraintValidator(),
        certificate_validator.CorrectVersionValidator(),
        pkix.CertificateSerialNumberValidator(),
        certificate_validator.SignatureAlgorithmMatchValidator(),
        certificate_extension.SubjectKeyIdentifierPresenceValidator(),
        certificate_extension.AuthorityKeyIdentifierPresenceValidator(),
        certificate_extension.KeyUsagePresenceValidator(),
        time.UtcTimeCorrectSyntaxValidator(),
        time.GeneralizedTimeCorrectSyntaxValidator(),
        NamedBitStringMinimalEncodingValidator(),
        certificate_validator.IssuerUniqueIdAbsenceValidator(),
        certificate_validator.SubjectUniqueIdAbsenceValidator(),
    ]

    return validation.ValidatorContainer(
        validators=decoding_validator_container + validators
    )


def create_decoding_validators(name_mappings, extension_mappings, additional_decoding_validators=None):
    if additional_decoding_validators is None:
        additional_decoding_validators = []
    return [
               pkix.create_attribute_decoder(
                   name_mappings
               ),
               pkix.create_extension_decoder(
                   extension_mappings
               ),
               pkix.create_algorithm_identifier_decoder(
                   algorithm.ALGORITHM_IDENTIFIER_MAPPINGS
               ),
               create_spki_decoder(
                   certificate_key.SUBJECT_PUBLIC_KEY_ALGORITHM_IDENTIFIER_MAPPINGS,
                   certificate_key.SUBJECT_KEY_PARAMETER_ALGORITHM_IDENTIFIER_MAPPINGS
               ),
               create_policy_qualifier_decoder(
                   certificate_extension.CERTIFICATE_POLICY_QUALIFIER_MAPPINGS
               ),
           ] + additional_decoding_validators
