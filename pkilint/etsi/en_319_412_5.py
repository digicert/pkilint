from pkilint import validation, common
from pkilint.etsi import etsi_constants
from pkilint.etsi.asn1 import en_319_412_5
from iso3166 import countries_by_alpha2
from iso4217 import Currency
from urllib.parse import urlparse
from pyasn1_alt_modules import rfc3739
from pkilint.pkix import extension, Rfc2119Word
import iso639


class QcCCLegislationCountryCodeValidator(validation.Validator):
    """EN 319 412-5 4.2.4.: QCStatement stating the country or set of countries under the legislation of which the
    certificate is issued as a qualified certificate. Constrained by ISO 3166-1 alpha-2 codes only. This Validator
    will check to see if there is a country code at all or if it is a valid code."""

    VALIDATION_ISO_COUNTRY_CODE_LIST_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.2.4.iso_country_code_list_empty",
    )
    VALIDATION_ISO_COUNTRY_CODE_INVALID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.2.4.iso_country_code_invalid",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_ISO_COUNTRY_CODE_LIST_EMPTY,
                self.VALIDATION_ISO_COUNTRY_CODE_INVALID,
            ],
            pdu_class=en_319_412_5.QcCClegislation,
        )

    def validate(self, node):
        if not node.children:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ISO_COUNTRY_CODE_LIST_EMPTY
            )
        for children in node.children.values():
            country = str(children.pdu)
            if country not in countries_by_alpha2:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ISO_COUNTRY_CODE_INVALID,
                    f'Invalid country code found: "{country}"',
                )


class QcEuRetentionPeriodValidator(validation.Validator):
    """EN 319 412-5 4.3.3 QCStatement indicating the duration of the retention period
    material information. This QCStatement declares a retention period for material information
    relevant to the use of and reliance of on a certificate, expressed as a number of years after the expiry
    date of the certificate. So in short anything greater will be 0 will be valid.
    """

    VALIDATION_RETENTION_PERIOD_NOT_POSITIVE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.3.3.retention_period_years_not_positive",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_RETENTION_PERIOD_NOT_POSITIVE],
            pdu_class=en_319_412_5.QcEuRetentionPeriod,
        )

    def validate(self, node):
        # noinspection PyTypeChecker
        valid_yrs = int(node.pdu)
        if not valid_yrs > 0:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_RETENTION_PERIOD_NOT_POSITIVE
            )


class QcEuPDSLanguageValidator(validation.Validator):
    """Content of the QcEuPDS statement, in accordance with Clause 4.3.4 of EN 319-412-5.
    Valid ISO 639-1 language code"""

    VALIDATION_ISO_LANGUAGE_CODE_INVALID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.3.4.iso_language_code_invalid",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_ISO_LANGUAGE_CODE_INVALID],
            pdu_class=en_319_412_5.PdsLocation,
        )

    def validate(self, node):
        language_code = str(node.children["language"].pdu).lower()

        try:
            iso639.Language.from_part1(language_code)
        except iso639.LanguageNotFoundError:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ISO_LANGUAGE_CODE_INVALID,
                f'Invalid language code found: "{language_code}"',
            )


class QcEuPDSHttpsURLValidator(validation.Validator):
    """Content of the QcEuPDS statement, in accordance with Clause 4.3.4 of EN 319-412-5.
    Validator to check if the URL has the 'https' scheme."""

    VALIDATION_URL_SCHEME_NOT_HTTPS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.3.4.url_scheme_not_https",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_URL_SCHEME_NOT_HTTPS],
            pdu_class=en_319_412_5.PdsLocation,
        )

    def validate(self, node):
        url_string = str(node.children["url"].pdu)
        parsed_url = urlparse(url_string)

        if parsed_url.scheme.lower() != "https":
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_URL_SCHEME_NOT_HTTPS,
                f'Non-HTTPS URL scheme found: "{parsed_url.scheme}"',
            )


class QcTypeValidator(validation.Validator):
    """EN 319 412-5 4.2.3 Declares that a certificate is issued as one and only one of the purposes
    of electronic signature, electronic seal or web site authentication. According to Stephen
    a qwac should never have seal or sign but may have psd2."""

    VALIDATION_QC_TYPE_MISMATCH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.2.3.qc_type_mismatch",
    )

    VALIDATION_MULTIPLE_QC_TYPE_VALUES_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.2.3.multiple_qc_type_values_present",
    )

    VALIDATION_QC_TYPE_LIST_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.2.3.qc_type_list_empty",
    )

    def __init__(self, certificate_type):
        super().__init__(
            validations=[
                self.VALIDATION_QC_TYPE_MISMATCH,
                self.VALIDATION_QC_TYPE_LIST_EMPTY,
                self.VALIDATION_MULTIPLE_QC_TYPE_VALUES_PRESENT,
            ],
            pdu_class=en_319_412_5.QcType,
        )

        self._certificate_type = certificate_type

        if certificate_type in etsi_constants.WEB_AUTHENTICATION_CERTIFICATE_TYPES:
            self._expected_qc_type = en_319_412_5.id_etsi_qct_web
        elif certificate_type in etsi_constants.QCP_N_CERTIFICATE_TYPES:
            self._expected_qc_type = en_319_412_5.id_etsi_qct_esign
        else:
            self._expected_qc_type = None

    def validate(self, node):
        if not node.children.values():
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_QC_TYPE_LIST_EMPTY
            )

        if len(node.children.values()) != 1:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MULTIPLE_QC_TYPE_VALUES_PRESENT
            )

        if self._expected_qc_type:
            _, qctype_value = node.child

            if qctype_value.pdu != self._expected_qc_type:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_QC_TYPE_MISMATCH,
                    f'Certificate type is "{self._certificate_type.to_option_str}" but QcType qualified '
                    f'statement contains "{qctype_value.pdu}"',
                )


class QcEuLimitValueValidator(validation.Validator):
    """
    This QCStatement declares a limitation on the value of transaction for which a certificate
    can be used.
    MonetaryValue:: == SEQUENCE {
        currency Iso4217CurrencyCode,
        amount INTEGER,
        exponent INTEGR
    }
    -- value = amount * 10^exponent
    Iso4217CurrencyCode:: = CHOICE {
        alphabetic PrintableString (Size (3)), -- Recommended
        numeric INTEGER (1..999) }
        -- Alphabetic or numeric currency code as defined in ISO 4217
        -- It is recommended that the Alphabetic form is used
    }
    QCS-4.3.2-01: The currency codes shall be defined in ISO 4217.
    QCS-4.3.2-02: The alphabetic form of currency codes should be used.

    Things to validate - valid iso 4217 currency code
                       - warning if the numeric code is used
                       - Positive amount and exponent value
    """

    VALIDATION_CURRENCY_CODE_INVALID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.3.2.currency_code_invalid",
    )

    DISCOURAGED_VALIDATION_NUMERIC_CURRENCY_CODE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "etsi.en_319_412_5.gen-4.3.2.discouraged_numeric_currency_code_present",
    )

    VALIDATION_AMOUNT_NEGATIVE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.3.2.amount_negative",
    )

    VALIDATION_EXPONENT_NEGATIVE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.gen-4.3.2.exponent_negative",
    )

    def __init__(self):
        self._alpha_codes = set()
        self._numeric_codes = set()

        for currency in Currency:
            self._alpha_codes.add(currency.code)
            self._numeric_codes.add(currency.number)

        # Let's remove the testing and unknown currency codes from the set.
        alpha_bad_codes = {"XTS", "XXX"}
        numeric_bad_codes = {"999", "963"}

        self._alpha_codes -= alpha_bad_codes
        self._numeric_codes -= numeric_bad_codes

        super().__init__(
            validations=[
                self.VALIDATION_CURRENCY_CODE_INVALID,
                self.DISCOURAGED_VALIDATION_NUMERIC_CURRENCY_CODE_PRESENT,
                self.VALIDATION_AMOUNT_NEGATIVE,
                self.VALIDATION_EXPONENT_NEGATIVE,
            ],
            pdu_class=en_319_412_5.MonetaryValue,
        )

    def validate(self, node):
        findings = []
        currency_code_type, iso_code = node.children["currency"].child
        if currency_code_type != "alphabetic":
            findings.append(
                validation.ValidationFindingDescription(
                    self.DISCOURAGED_VALIDATION_NUMERIC_CURRENCY_CODE_PRESENT, None
                )
            )
            iso_code = int(iso_code.pdu)
        else:
            iso_code = str(iso_code.pdu)

        if iso_code not in self._alpha_codes and iso_code not in self._numeric_codes:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_CURRENCY_CODE_INVALID, None
                )
            )
        if node.children["amount"].pdu < 0:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_AMOUNT_NEGATIVE, None
                )
            )
        if node.children["exponent"].pdu < 0:
            findings.append(
                validation.ValidationFindingEncountered(
                    self.VALIDATION_EXPONENT_NEGATIVE, None
                )
            )

        return validation.ValidationResult(self, node, findings)


class QcStatementsExtensionCriticalityValidator(
    extension.ExtensionCriticalityValidator
):
    """EN 319 412-5 QCS-4.1-02 The qcStatements extension shall not be marked as critical"""

    VALIDATION_QCSTATEMENTS_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_5.qcs-4.1-02.qcstatements_extension_is_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc3739.id_pe_qcStatements,
            is_critical=False,
            validation=self.VALIDATION_QCSTATEMENTS_EXTENSION_CRITICAL,
        )


class QcStatementIdentifierAllowanceValidator(
    common.ElementIdentifierAllowanceValidator
):
    """
    EN 319 412-5:
    QCS-5-01: EU qualified certificates shall include QCStatements in accordance with table 2
    """

    _CODE_CLASSIFIER = "etsi.en_319_412_5.qcs-5.01"

    # qualified statements
    _OID_TO_CODE_NAME = {
        en_319_412_5.id_etsi_qcs_QcCompliance: "qc_compliance",
        en_319_412_5.id_etsi_qcs_QcType: "qc_type",
        en_319_412_5.id_etsi_qcs_QcCClegislation: "qc_cc_legislation",
        en_319_412_5.id_etsi_qcs_QcSSCD: "qc_sscd",
    }

    @classmethod
    def retrieve_qualified_statement_id(cls, node):
        return node.children["statementId"]

    def __init__(self, certificate_type: etsi_constants.CertificateType):
        allowances = {}

        if certificate_type in etsi_constants.EU:
            # Table 2: 4.2.1
            allowances[en_319_412_5.id_etsi_qcs_QcCompliance] = Rfc2119Word.MUST
            # Table 2: 4.2.4
            allowances[en_319_412_5.id_etsi_qcs_QcCClegislation] = Rfc2119Word.MUST_NOT
            # Table 2: 4.2.2
            if certificate_type in etsi_constants.EU_SSCD:
                allowances[en_319_412_5.id_etsi_qcs_QcSSCD] = Rfc2119Word.MUST

            if (certificate_type in etsi_constants.EU_QWAC_TYPES) or (
                certificate_type in etsi_constants.QCP_N_CERTIFICATE_TYPES
            ):
                # Table 2: 4.2.3 (QWAC is Annex IV, signatures is Annex I)
                allowances[en_319_412_5.id_etsi_qcs_QcType] = Rfc2119Word.MUST
            if certificate_type in etsi_constants.EU_QWAC_TYPES:
                # PR Question: Table 2, 4.2.2 only defines MUST, is the MUST_NOT also from 412-5 somewhere?
                allowances[en_319_412_5.id_etsi_qcs_QcSSCD] = Rfc2119Word.MUST_NOT

        elif certificate_type in etsi_constants.NON_EU_QWAC_TYPES:
            # PR Question: Is this from 415_5.qcs-4.2? Needs different classifier?
            allowances[en_319_412_5.id_etsi_qcs_QcCClegislation] = Rfc2119Word.MUST

        super().__init__(
            "qualified statement",
            self.retrieve_qualified_statement_id,
            allowances,
            f"{self._CODE_CLASSIFIER}.{{oid}}_qualified_statement_present",
            f"{self._CODE_CLASSIFIER}.{{oid}}_qualified_statement_absent",
            None,
            pdu_class=rfc3739.QCStatements,
        )
