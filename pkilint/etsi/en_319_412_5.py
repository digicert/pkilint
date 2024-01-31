from pkilint import validation
from pkilint.etsi.asn1 import en_319_412_5
from iso3166 import countries_by_alpha2
from urllib.parse import urlparse
import iso639

class QcCClegislationCountryCodeValidator(validation.Validator):
    """EN 319 412-5 4.2.4.: QCStatement stating the country or set of countries under the legislation of which the certificate
    is issued as a qualified certificate. Constrained by ISO 3166-1 alpha-2 codes only. This Validator will check to see if there is a country
    code at all or if it is a valid code."""
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

class QcEuRetentionPeriodValidator(validation.Validator):
    """EN 319 412-5 4.3.3 QCStatement indicating the duration of the retention period 
    material information. This QCStatement declares a retention period for material information
    relevant to the use of and reliance of on a certificate, expressed as a number of years after the expiry
    date of the certificate. So in short anything greater will be 0 will be valid.
    """
    VALIDATION_QCRetention_POSITIVE = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.en_319_412_5.gen-4.3.3.years_not_positive')

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_QCRetention_POSITIVE], pdu_class=en_319_412_5.QcEuRetentionPeriod)

    def validate(self, node):
        valid_yrs = node.pdu
        if not valid_yrs > 0:
            raise validation.ValidationFindingEncountered(self.VALIDATION_QCRetention_POSITIVE)

class QcEuPDSLanguageValidator(validation.Validator):
    """Content of the QcEuPDS statement, in accordance with Clause 4.3.4 of EN 319-412-5.
    Valid ISO 639-1 language code"""
    VALIDATION_ISO_LANGUAGE_BAD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_5.gen-2.2.2.iso_language_bad'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_ISO_LANGUAGE_BAD], pdu_class=en_319_412_5.PdsLocation)

    def validate(self, node):
        language_code = str(node.children['language'].pdu).lower()

        try:
            iso639.Language.from_part1(language_code)
        except iso639.LanguageNotFoundError:
            raise validation.ValidationFindingEncountered(self.VALIDATION_ISO_LANGUAGE_BAD, f'invalid language code, value found {language_code}')

class QcEuPDSHttpsURLValidator(validation.Validator):
    """Content of the QcEuPDS statement, in accordance with Clause 4.3.4 of EN 319-412-5.
    Validator to check if the URL has the 'https' scheme."""
    VALIDATION_URL_SCHEME_NOT_HTTPS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_5.gen.url_scheme_not_https'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_URL_SCHEME_NOT_HTTPS], pdu_class=en_319_412_5.PdsLocation)

    def validate(self, node):
        url_string = str(node.children['url'].pdu)
        parsed_url = urlparse(url_string)

        if parsed_url.scheme.lower() != 'https':
            raise validation.ValidationFindingEncountered(self.VALIDATION_URL_SCHEME_NOT_HTTPS, f'URL scheme is not https, found {parsed_url.scheme}')

class QcTypeValidator(validation.Validator):
    """EN 319 412-5 4.2.3 Declares that a certificate is issued as one and only one of the purposes
    of electronic signature, electronic seal or web site authentication. According to Stephen
    a qwac should never have seal or sign but may have psd2."""
    VALIDATION_QCType_Web = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.en_319_412_5.gen-4.2.3.qctype_not_web')

    VALIDATION_QCType_not_one = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.en_319_412_5.gen-4.2.3.not_one')

    VALIDATION_QCType_empty = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.en_319_412_5.gen-4.2.3qctype_empty')

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_QCType_Web, self.VALIDATION_QCType_empty, self.VALIDATION_QCType_not_one], 
        pdu_class=en_319_412_5.QcType)
    
    def validate(self, node):
        if not node.children.values():
            raise validation.ValidationFindingEncountered(self.VALIDATION_QCType_empty)
        if len(node.children.values()) != 1:
            raise validation.ValidationFindingEncountered(self.VALIDATION_QCType_not_one)
        _, qctype_value = node.child
        if qctype_value.pdu != en_319_412_5.id_etsi_qct_web:
                raise validation.ValidationFindingEncountered(self.VALIDATION_QCType_Web)
