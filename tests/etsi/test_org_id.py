from pkilint import document, validation
from pkilint.etsi.en_319_412_1 import LegalPersonOrganizationIdentifierValidator
from pkilint.itu import x520_name


def _create_node(value):
    pyasn1_node = x520_name.X520OrganizationIdentifier()
    pyasn1_node.setComponentByName('utf8String', value)

    return document.PDUNode(None, 'node', pyasn1_node, None)


def _expect_finding_for_value(value, finding):
    validator = LegalPersonOrganizationIdentifierValidator()

    node = _create_node(value)

    assert validator.match(node)

    try:
        result = validator.validate(node)

        assert len(result.finding_descriptions) == 1

        assert result.finding_descriptions[0].finding == finding
    except validation.ValidationFindingEncountered as e:
        assert e.finding == finding


def _expect_no_findings(value):
    validator = LegalPersonOrganizationIdentifierValidator()

    node = _create_node(value)

    assert validator.match(node)

    result = validator.validate(node)

    assert len(result.finding_descriptions) == 0


def test_invalid_format():
    values_under_test = [
        'TST',
        'TEST',
        'TESTXG-1',
        'TSTXG-',
        'NTRUS+VA-1',
    ]

    for value in values_under_test:
        _expect_finding_for_value(
            value,
            LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
        )


def test_invalid_scheme():
    values_under_test = [
        'FOOXG-1',
        'EI:XX-1',
        'EI:FR+PA-1',
    ]

    for value in values_under_test:
        _expect_finding_for_value(
            value,
            LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_SCHEME
        )


def test_valid_vat():
    values_under_test = [
        'VATFR-1',
        'VATXI-1',
        'VATEL-1',
    ]

    for value in values_under_test:
        _expect_no_findings(value)


def test_vat_invalid_country():
    _expect_finding_for_value('VATXG-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY
                              )


def test_vat_sp_present():
    _expect_finding_for_value('VATFR+PA-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_vat_no_reference():
    _expect_finding_for_value('VATFR',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_valid_ntr():
    values_under_test = [
        'NTRFR-1',
    ]

    for value in values_under_test:
        _expect_no_findings(value)


def test_ntr_invalid_country():
    _expect_finding_for_value('NTREL-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY
                              )


def test_ntr_sp_present():
    _expect_finding_for_value('NTRFR+PA-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_ntr_no_reference():
    _expect_finding_for_value('NTRFR',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_valid_psd():
    values_under_test = [
        'PSDFR-1',
    ]

    for value in values_under_test:
        _expect_no_findings(value)


def test_psd_invalid_country():
    _expect_finding_for_value('PSDEL-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY
                              )


def test_psd_sp_present():
    _expect_finding_for_value('PSDFR+PA-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_psd_no_reference():
    _expect_finding_for_value('PSDFR',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_valid_lei():
    values_under_test = [
        'LEIXG-1',  # length of reference and other checks are done by the LEI validator
    ]

    for value in values_under_test:
        _expect_no_findings(value)


def test_lei_invalid_country():
    _expect_finding_for_value('LEIFR-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY
                              )


def test_lei_sp_present():
    _expect_finding_for_value('LEIXG+PA-1',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_lei_no_reference():
    _expect_finding_for_value('LEIXG',
                              LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                              )


def test_national_scheme():
    values_under_test = [
        'EI:SE-5567971433'
    ]

    for value in values_under_test:
        _expect_finding_for_value(
            value,
            LegalPersonOrganizationIdentifierValidator.VALIDATION_ORGANIZATION_NATIONAL_SCHEME_DETECTED
        )
