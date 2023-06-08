import enum
import typing


@enum.unique
class RegistrationSchemeCountryIdentifierType(enum.IntEnum):
    NONE = 0
    XG = 1
    ISO3166 = 2


class RegistrationSchemeNamingConvention(typing.NamedTuple):
    country_identifier_type: RegistrationSchemeCountryIdentifierType
    allow_state_province: bool
    require_registration_reference: bool


REGISTRATION_SCHEMES = {
    'NTR': RegistrationSchemeNamingConvention(RegistrationSchemeCountryIdentifierType.ISO3166, True, True),
    'VAT': RegistrationSchemeNamingConvention(RegistrationSchemeCountryIdentifierType.ISO3166, False, True),
    'PSD': RegistrationSchemeNamingConvention(RegistrationSchemeCountryIdentifierType.ISO3166, False, True),
}
