from iso3166 import countries_by_alpha2
from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.cabf import cabf_constants
from pkilint.cabf.servercert.asn1 import ev_guidelines
from pkilint.cabf.cabf_constants import REGISTRATION_SCHEMES


class CABFOrganizationIdentifierExtensionValidator(validation.Validator):
    VALIDATION_ORGANIZATION_ID_INVALID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_ext_organization_identifier_registration_scheme'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_ext_organization_identifier_country'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_SP = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_ext_organization_identifier_state_province_for_scheme'
    )

    def __init__(self):
        super().__init__(
            pdu_class=ev_guidelines.CABFOrganizationIdentifier,
            validations=[
                self.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME,
                self.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
                self.VALIDATION_ORGANIZATION_ID_INVALID_SP,
            ]
        )

    def validate(self, node):
        scheme = str(node.children['registrationSchemeIdentifier'].pdu)
        country = str(node.children['registrationCountry'].pdu).upper()

        scheme_node = node.children.get('registrationStateOrProvince')
        sp = None if scheme_node is None else str(scheme_node.pdu)

        scheme_info = REGISTRATION_SCHEMES.get(scheme)

        if scheme_info is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME,
                f'Invalid registration scheme: {scheme}'
            )

        if scheme_info.country_identifier_type == cabf_constants.RegistrationSchemeCountryIdentifierType.NONE:
            valid_country_code = (country == '')
        elif scheme_info.country_identifier_type == cabf_constants.RegistrationSchemeCountryIdentifierType.XG:
            valid_country_code = (country == 'XG')
        elif scheme_info.country_identifier_type == cabf_constants.RegistrationSchemeCountryIdentifierType.ISO3166:
            valid_country_code = country in countries_by_alpha2
        else:
            raise ValueError(f'Unknown country identifier type for scheme "{scheme}": '
                             f'{scheme_info.country_identifier_type}')

        if not valid_country_code:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
                f'Invalid country code for scheme "{scheme}": {country}'
            )

        if sp is not None and not scheme_info.allow_state_province:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_SP,
                f'Scheme "{scheme}" does not allow state/province values'
            )


def _is_bit_asserted(pdu, value):
    return len(pdu) > value and pdu[value] != 0


class KeyUsageValidator(validation.Validator):
    VALIDATION_CA_CERT_INVALID_BITS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.ca_certificate_invalid_key_usage_bits'
    )

    VALIDATION_CA_CERT_NO_DIG_SIG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.ca_certificate_no_digital_signature_bit'
    )

    VALIDATION_EE_CERT_INVALID_BITS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.ee_certificate_invalid_key_usage_bits'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_CA_CERT_INVALID_BITS,
                self.VALIDATION_CA_CERT_NO_DIG_SIG,
                self.VALIDATION_EE_CERT_INVALID_BITS,
            ],
            pdu_class=rfc5280.KeyUsage
        )

    def validate(self, node):
        crlsign = rfc5280.KeyUsage.namedValues['cRLSign']
        digsig = rfc5280.KeyUsage.namedValues['digitalSignature']

        is_ca = node.document.is_ca

        results = []

        if is_ca:
            if not _is_bit_asserted(node.pdu, crlsign):
                results.append(validation.ValidationFindingDescription(
                    self.VALIDATION_CA_CERT_INVALID_BITS,
                    'cRLSign keyUsage bit not asserted'
                ))
            if not _is_bit_asserted(node.pdu, digsig):
                results.append(validation.ValidationFindingDescription(
                    self.VALIDATION_CA_CERT_NO_DIG_SIG,
                    'CA certificates with digitalSignature bit not asserted '
                    'cannot be used for OCSP response verification'
                ))
        else:
            if _is_bit_asserted(node.pdu, crlsign):
                results.append(validation.ValidationFindingDescription(
                    self.VALIDATION_EE_CERT_INVALID_BITS,
                    'cRLSign keyUsage bit is asserted'
                ))

        return validation.ValidationResult(self, node, results)
