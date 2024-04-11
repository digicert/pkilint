import typing
from typing import List

from pyasn1_alt_modules import rfc5280, rfc4985, rfc6962

import pkilint.cabf.cabf_name
import pkilint.cabf.serverauth.serverauth_extension
import pkilint.cabf.serverauth.serverauth_name
import pkilint.cabf.serverauth.serverauth_subscriber
import pkilint.common
from pkilint import validation, cabf, etsi, document
from pkilint.cabf import cabf_key, cabf_name, cabf_extension, cabf_ca
from pkilint.cabf.serverauth import (
    serverauth_name, serverauth_extension, serverauth_constants,
    serverauth_key, serverauth_root, serverauth_ca, serverauth_ocsp, serverauth_cross_ca, serverauth_finding_filter
)
from pkilint.pkix import name, certificate
from pkilint.pkix.certificate import certificate_validity

OTHER_NAME_MAPPINGS = rfc4985.otherNamesMap.copy()


def _has_name_constraints(cert: certificate.RFC5280Certificate):
    return cert.get_extension_by_oid(rfc5280.id_ce_nameConstraints) is not None


def _determine_intermediate_ca_type(cert: certificate.RFC5280Certificate):
    ekus = cert.extended_key_usages

    if not ekus:
        # assume serverauth
        ekus = {rfc5280.id_kp_serverAuth}

    if rfc6962.id_kp_precertificateSigning in ekus:
        return serverauth_constants.CertificateType.PRECERT_SIGNING_CA
    elif rfc5280.id_kp_serverAuth in ekus or rfc5280.anyExtendedKeyUsage in ekus:
        if _has_name_constraints(cert):
            return serverauth_constants.CertificateType.INTERNAL_CONSTRAINED_TLS_CA
        else:
            return serverauth_constants.CertificateType.INTERNAL_UNCONSTRAINED_TLS_CA
    else:
        return serverauth_constants.CertificateType.NON_TLS_CA


def _is_ocsp_responder(cert: certificate.RFC5280Certificate):
    return rfc5280.id_kp_OCSPSigning in cert.extended_key_usages


def _is_precert(cert: certificate.RFC5280Certificate):
    return cert.get_extension_by_oid(rfc6962.id_ce_criticalPoison) is not None


def _determine_subscriber_certificate_type(cert: certificate.RFC5280Certificate):
    is_precert = _is_precert(cert)

    policy_oids = cert.policy_oids

    if serverauth_constants.ID_POLICY_EV in policy_oids:
        return (serverauth_constants.CertificateType.EV_PRE_CERTIFICATE if is_precert
                else serverauth_constants.CertificateType.EV_FINAL_CERTIFICATE)
    elif serverauth_constants.ID_POLICY_IV in policy_oids:
        return (serverauth_constants.CertificateType.IV_PRE_CERTIFICATE if is_precert
                else serverauth_constants.CertificateType.IV_FINAL_CERTIFICATE)
    elif serverauth_constants.ID_POLICY_OV in policy_oids:
        return (serverauth_constants.CertificateType.OV_PRE_CERTIFICATE if is_precert
                else serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE)
    else:
        # "unknown" certificate types are consider to be DV Subscriber certs
        return (serverauth_constants.CertificateType.DV_PRE_CERTIFICATE if is_precert
                else serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE)


def determine_certificate_type(cert: certificate.RFC5280Certificate) -> serverauth_constants.CertificateType:
    if cert.is_self_issued:
        return serverauth_constants.CertificateType.ROOT_CA

    if cert.is_ca:
        return _determine_intermediate_ca_type(cert)
    else:
        if _is_ocsp_responder(cert):
            return serverauth_constants.CertificateType.OCSP_RESPONDER
        else:
            return _determine_subscriber_certificate_type(cert)


def create_decoding_validators():
    return pkilint.pkix.certificate.create_decoding_validators(
        cabf.NAME_ATTRIBUTE_MAPPINGS,
        cabf.EXTENSION_MAPPINGS,
        [certificate.create_other_name_decoder(OTHER_NAME_MAPPINGS),
         certificate.create_qc_statements_decoder(etsi.ETSI_QC_STATEMENTS_MAPPINGS)]
    )


def create_top_level_certificate_validators(certificate_type: serverauth_constants.CertificateType):
    validators = [
        serverauth_key.ServerauthAllowedSignatureAlgorithmEncodingValidator(
            path='certificate.tbsCertificate.signature'
        ),
        serverauth_key.ServerauthAllowedSignatureAlgorithmEncodingValidator(
            path='certificate.signatureValue'
        ),
        cabf_extension.CabfExtensionsPresenceValidator(),
    ]

    if certificate_type == serverauth_constants.CertificateType.ROOT_CA:
        validators.append(serverauth_root.RootExtensionAllowanceValidator())
    elif certificate_type in serverauth_constants.CROSS_CA_TYPES:
        validators.append(serverauth_cross_ca.CrossCertificateExtensionAllowanceValidator(certificate_type))
    elif certificate_type in serverauth_constants.INTERMEDIATE_CERTIFICATE_TYPES:
        validators.append(serverauth_ca.CaCertificateExtensionAllowanceValidator(certificate_type))
    elif certificate_type in serverauth_constants.SUBSCRIBER_CERTIFICATE_TYPES:
        validators.append(serverauth_subscriber.SubscriberExtensionAllowanceValidator(certificate_type))
    elif certificate_type == serverauth_constants.CertificateType.OCSP_RESPONDER:
        validators.append(serverauth_ocsp.OcspExtensionAllowanceValidator())
    else:
        raise ValueError(f'Unsupported certificate type: {certificate_type}')

    return validators


def create_spki_validator_container():
    return validation.ValidatorContainer(validators=[
        serverauth_key.ServerauthAllowedPublicKeyAlgorithmEncodingValidator(
            path='certificate.tbsCertificate.subjectPublicKeyInfo.algorithm'
        ),
        cabf_key.RsaKeyValidator(),
        cabf_key.EcdsaKeyValidator(),
    ],
        path='certificate.tbsCertificate.subjectPublicKeyInfo')


def create_subject_name_validators() -> List[validation.Validator]:
    return [
        serverauth_name.AttributeOrderEncodingValidator(),
        serverauth_name.AttributeValueDirectoryStringValidator(),
        serverauth_name.X520NameAttributeValueLengthValidator(),
        serverauth_name.DomainComponentAttributeValueLengthValidator(),
        serverauth_name.ValidJurisdictionCountryValidator(),
        cabf_name.ValidCountryValidator(),
        serverauth_name.ValidBusinessCategoryValidator(),
        cabf_name.OrganizationIdentifierAttributeValidator(relax_stateprovince_syntax=False),
        serverauth_name.ServerauthRelativeDistinguishedNameContainsOneElementValidator(),
    ]


def create_ca_name_validator_container(certificate_type: serverauth_constants.CertificateType):
    validators = [
        serverauth_ca.CaRequiredSubjectAttributesValidator(certificate_type),
        serverauth_name.ServerauthDuplicateAttributeTypeValidator(certificate_type),
    ]
    validators.extend(create_subject_name_validators())

    if certificate_type == serverauth_constants.CertificateType.ROOT_CA:
        validators.append(serverauth_root.RootSubjectIssuerIdenticalEncodingValidator())

    return certificate.create_subject_validator_container(validators)


def create_subscriber_name_validator_container(certificate_type: serverauth_constants.CertificateType):
    validators = create_subject_name_validators()
    validators.extend([
        serverauth_subscriber.SubscriberCommonNameValidator(),
        serverauth_name.ServerauthDuplicateAttributeTypeValidator(certificate_type),
    ])

    if certificate_type in serverauth_constants.EV_CERTIFICATE_TYPES:
        validators.extend([
            serverauth_subscriber.EvSubscriberAttributeAllowanceValidator(),
            serverauth_subscriber.EvSubscriberJurisdictionPresenceValidator(),
            serverauth_name.OrganizationIdentifierConsistentSubjectAndExtensionValidator()
        ])
    elif certificate_type in serverauth_constants.IV_CERTIFICATE_TYPES:
        validators.append(serverauth_subscriber.IvSubscriberAttributeAllowanceValidator())
    elif certificate_type in serverauth_constants.OV_CERTIFICATE_TYPES:
        validators.append(serverauth_subscriber.OvSubscriberAttributeAllowanceValidator())
    elif certificate_type in serverauth_constants.DV_CERTIFICATE_TYPES:
        validators.append(serverauth_subscriber.DvSubcriberAttributeAllowanceValidator())
    else:
        raise ValueError(f'Unsupported certificate type: {certificate_type}')

    if certificate_type in serverauth_constants.IDENTITY_CERTIFICATE_TYPES:
        validators.append(serverauth_subscriber.IdentityCertificateStateProvinceAndLocalityPresenceValidator())

    return certificate.create_subject_validator_container(validators)


def create_extension_validators() -> List[validation.Validator]:
    return [
        serverauth_extension.CrlDpDistributionPointCountValidator(),
        serverauth_extension.CrlDpDistributionPointNameValidator(),
        serverauth_extension.CrlDpDistributionPointValidator(),
        serverauth_extension.AuthorityInformationAccessHttpUriLocationValidator(),
        serverauth_extension.AuthorityInformationAccessUniqueLocationValidator(),
        cabf_extension.CabfAuthorityKeyIdentifierValidator(),
        cabf_name.GeneralNameDnsNameInternalDomainNameValidator(allow_onion_tld=True),
        cabf_name.GeneralNameRfc822NameInternalDomainNameValidator(),
        cabf_name.GeneralNameUriInternalDomainNameValidator(),
        cabf_name.UriInternalDomainNameValidator(pdu_class=rfc5280.CPSuri),
        cabf_name.GeneralNameInternalIpAddressValidator(),
        serverauth_extension.CertificatePolicyQualifierValidator(),
        cabf_extension.CpsUriHttpValidator(),
        serverauth_name.DnsNameLdhLabelSyntaxValidator(),
        serverauth_name.TorVersion3DomainNameValidator(),
    ]


def create_ca_extension_validator_container(
        certificate_type: serverauth_constants.CertificateType,
        validity_period_start_retriever: document.ValidityPeriodStartRetriever
):
    validators = create_extension_validators()

    validators.extend([
        serverauth_ca.CaCertificateExtensionCriticalityValidator(),
        serverauth_ca.NameConstraintsBaseTypeValidator(),
        serverauth_ca.CaCertificatePoliciesValidator(certificate_type),
        serverauth_ca.CaCertificateAuthorityInformationAccessAccessMethodPresenceValidator(),
        cabf_ca.CaKeyUsageValidator(),
        cabf_ca.CaBasicConstraintsValidator(),
    ])

    if certificate_type == serverauth_constants.CertificateType.ROOT_CA:
        validators.extend([
            serverauth_root.RootAkiSkiEqualityValidator(),
            serverauth_root.RootBasicConstraintsValidator(),
        ])
    elif certificate_type in serverauth_constants.CROSS_CA_TYPES:
        validators.append(serverauth_cross_ca.CrossCertificateAllowedEkuValidator(certificate_type))
    elif certificate_type == serverauth_constants.CertificateType.NON_TLS_CA:
        validators.append(serverauth_ca.NonTlsCaCertificateAllowedEkuValidator())
    elif certificate_type == serverauth_constants.CertificateType.PRECERT_SIGNING_CA:
        validators.append(serverauth_ca.PrecertSigningCaCertificateAllowedEkuValidator())
    elif certificate_type in serverauth_constants.TLS_CA_TYPES:
        validators.append(serverauth_ca.TlsCaCertificateAllowedEkuValidator())

    if certificate_type in {serverauth_constants.CertificateType.EXTERNAL_UNCONSTRAINED_EV_TLS_CA,
                            serverauth_constants.CertificateType.EXTERNAL_CONSTRAINED_EV_TLS_CA}:
        validators.append(serverauth_extension.EvCpsUriPresenceValidator(validity_period_start_retriever))

    if certificate_type in serverauth_constants.CONSTRAINED_TLS_CA_TYPES:
        validators.append(serverauth_ca.TlsCaTechnicallyConstrainedValidator())

    return certificate.create_extensions_validator_container(validators)


def create_subscriber_extension_validator_container(
        certificate_type: serverauth_constants.CertificateType,
        validity_period_start_retriever: document.ValidityPeriodStartRetriever
):
    validators = create_extension_validators()

    validators.extend([
        serverauth_subscriber.SubscriberEkuAllowanceValidator(),
        serverauth_subscriber.CABFOrganizationIdentifierExtensionValidator(),
        serverauth_subscriber.SubscriberExtensionCriticalityValidator(),
        serverauth_subscriber.SubscriberAuthorityInformationAccessAccessMethodPresenceValidator(),
        serverauth_subscriber.SubscriberKeyUsageValidator(),
        serverauth_subscriber.SubscriberBasicConstraintsValidator(),
        serverauth_subscriber.SubscriberPoliciesValidator(certificate_type),
    ])

    if certificate_type in serverauth_constants.EV_CERTIFICATE_TYPES:
        validators.extend([
            serverauth_subscriber.EvSanGeneralNameTypeValidator(),
            serverauth_extension.EvCpsUriPresenceValidator(validity_period_start_retriever),
            serverauth_subscriber.EvWildcardAllowanceValidator(),
        ])
    else:
        validators.append(serverauth_subscriber.SubscriberSanGeneralNameTypeValidator())

    return certificate.create_extensions_validator_container(validators)


def create_ocsp_extension_validator_container():
    validators = create_extension_validators()

    validators.extend([
        serverauth_ocsp.OcspEkuAllowanceValidator(),
        serverauth_ocsp.OcspAuthorityInformationAccessAccessMethodPresenceValidator(),
        serverauth_ocsp.OcspResponderKeyUsageValidator(),
        serverauth_ocsp.OcspBasicConstraintsValidator(),
    ])

    return certificate.create_extensions_validator_container(validators)


def create_validity_validator_container(certificate_type):
    validators = []

    if certificate_type == serverauth_constants.CertificateType.ROOT_CA:
        validators.append(serverauth_root.RootValidityPeriodValidator())
    elif certificate_type in serverauth_constants.SUBSCRIBER_CERTIFICATE_TYPES:
        validators.append(serverauth_subscriber.SubscriberValidityPeriodValidator())

    return certificate.create_validity_validator_container(validators)


def create_root_ca_validators(validity_period_start_retriever: document.ValidityPeriodStartRetriever):
    return [
        create_validity_validator_container(serverauth_constants.CertificateType.ROOT_CA),
        create_spki_validator_container(),
        create_ca_name_validator_container(serverauth_constants.CertificateType.ROOT_CA),
        create_ca_extension_validator_container(
            serverauth_constants.CertificateType.ROOT_CA, validity_period_start_retriever
        ),
    ] + create_top_level_certificate_validators(serverauth_constants.CertificateType.ROOT_CA)


def create_intermediate_ca_validators(
        certificate_type: serverauth_constants.CertificateType,
        validity_period_start_retriever: document.ValidityPeriodStartRetriever
):
    return [
        create_validity_validator_container(certificate_type),
        create_spki_validator_container(),
        create_ca_name_validator_container(certificate_type),
        create_ca_extension_validator_container(certificate_type, validity_period_start_retriever),
    ] + create_top_level_certificate_validators(certificate_type)


def create_subscriber_validators(
        certificate_type: serverauth_constants.CertificateType,
        validity_period_start_retriever: document.ValidityPeriodStartRetriever
):
    return [
        create_validity_validator_container(certificate_type),
        create_spki_validator_container(),
        create_subscriber_name_validator_container(certificate_type),
        create_subscriber_extension_validator_container(certificate_type, validity_period_start_retriever),
    ] + create_top_level_certificate_validators(certificate_type)


def create_ocsp_responder_validators():
    return [
        create_validity_validator_container(serverauth_constants.CertificateType.OCSP_RESPONDER),
        create_spki_validator_container(),
        create_ca_name_validator_container(serverauth_constants.CertificateType.OCSP_RESPONDER),
        create_ocsp_extension_validator_container(),
    ] + create_top_level_certificate_validators(serverauth_constants.CertificateType.OCSP_RESPONDER)


def create_validators(
        certificate_type: serverauth_constants.CertificateType,
        validity_period_start_retriever: typing.Optional[document.ValidityPeriodStartRetriever] = None
):
    if validity_period_start_retriever is None:
        validity_period_start_retriever = certificate_validity.CertificateValidityPeriodStartRetriever()

    if certificate_type == serverauth_constants.CertificateType.ROOT_CA:
        return create_root_ca_validators(validity_period_start_retriever)
    elif certificate_type in serverauth_constants.INTERMEDIATE_CERTIFICATE_TYPES:
        return create_intermediate_ca_validators(certificate_type, validity_period_start_retriever)
    elif certificate_type in serverauth_constants.SUBSCRIBER_CERTIFICATE_TYPES:
        return create_subscriber_validators(certificate_type, validity_period_start_retriever)
    elif certificate_type == serverauth_constants.CertificateType.OCSP_RESPONDER:
        return create_ocsp_responder_validators()
    else:
        raise ValueError(f'Unsupported certificate type: {certificate_type}')


def create_serverauth_finding_filters(certificate_type: serverauth_constants.CertificateType):
    filters = [
        serverauth_finding_filter.NameConstraintsCriticalityFilter(),
        serverauth_finding_filter.PolicyQualifierPresentFilter(),
        serverauth_finding_filter.DnsNameGeneralNamePreferredNameSyntaxFilter(),
    ]

    if certificate_type in serverauth_constants.SUBSCRIBER_CERTIFICATE_TYPES:
        filters += [
            serverauth_finding_filter.EndEntitySubjectKeyIdentifierMissingFilter(),
        ]

    return filters
