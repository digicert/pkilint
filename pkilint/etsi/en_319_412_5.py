from pkilint import validation
from pkilint.etsi.asn1 import en_319_412_5
from iso3166 import countries_by_alpha2


class CountryCodeValidator(validation.Validator):
    """EN 319 412-5 4.2.4.: QCStatement stating the country or set of countries under the legislation of which the certificate
    is issued as a qualified certificate. Constrained by ISO 3166-1 alpha-2 codes only. This Validator will check to see if there is a country
    code at all or if it is a valid code.."""
    VALIDATION_ISO_COUNTRY_BAD_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_5.gen-4.2.4.iso_country_bad_empty'
    )
    VALIDATION_ISO_COUNTRY_BAD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_5.gen-4.2.4.iso_country_bad'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_ISO_COUNTRY_BAD_EMPTY, self.VALIDATION_ISO_COUNTRY_BAD], pdu_class=en_319_412_5.QcCClegislation)

    def validate(self, node):
        if not node.children:
            raise validation.ValidationFindingEncountered(self.VALIDATION_ISO_COUNTRY_BAD_EMPTY)
        for children in node.children.values():
            country = str(children.pdu)
            if country not in countries_by_alpha2:
                raise validation.ValidationFindingEncountered(self.VALIDATION_ISO_COUNTRY_BAD, f'invalid country code, value found {country}')
            else:
                return
