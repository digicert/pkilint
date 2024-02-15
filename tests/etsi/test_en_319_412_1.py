from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280, rfc3739

from pkilint import document, validation
from pkilint.etsi.asn1 import en_319_412_1
from pkilint.etsi.en_319_412_1 import LegalPersonOrganizationIdentifierValidator, NaturalPersonIdentifierValidator
from pkilint.itu import x520_name


class Doc:
    def __init__(self, semantics_oid):
        self._semantics_oid = semantics_oid

    def get_extension_by_oid(self, _):
        if self._semantics_oid is None:
            return None

        ext = rfc5280.Extension()
        ext['extnID'] = rfc3739.id_pe_qcStatements

        semantic_info = rfc3739.SemanticsInformation()
        semantic_info['semanticsIdentifier'] = self._semantics_oid

        # noinspection PyTypeChecker
        semantics_info_node = document.PDUNode(self, 'semanticsInformation', semantic_info, None)

        statement = rfc3739.QCStatement()
        statement['statementId'] = rfc3739.id_qcs_pkixQCSyntax_v2
        statement['statementInfo'] = encode(semantic_info)

        qc_statements = rfc3739.QCStatements()
        qc_statements.append(statement)

        ext['extnValue'] = encode(qc_statements)

        # noinspection PyTypeChecker
        ext_node = document.PDUNode(self, 'ext', ext, None)

        # noinspection PyTypeChecker
        qc_statements_node = document.PDUNode(self, 'qCStatements', qc_statements, ext_node)
        qc_statements_node.navigate('0.statementInfo').children['semanticsInformation'] = semantics_info_node

        ext_node.children['extnValue'].children['qCStatements'] = qc_statements_node

        # noinspection PyTypeChecker
        return ext_node, 0


def _create_orgid_node(value, semantics_oid):
    pyasn1_node = x520_name.X520OrganizationIdentifier()
    pyasn1_node.setComponentByName('utf8String', value)

    # noinspection PyTypeChecker
    return document.PDUNode(Doc(semantics_oid), 'node', pyasn1_node, None)


def _create_serialnumber_node(value, semantics_oid):
    pyasn1_node = rfc5280.X520SerialNumber(value=value)

    # noinspection PyTypeChecker
    return document.PDUNode(Doc(semantics_oid), 'node', pyasn1_node, None)


def _expect_finding_for_orgid_value(value, finding):
    validator = LegalPersonOrganizationIdentifierValidator()

    node = _create_orgid_node(value, en_319_412_1.id_etsi_qcs_SemanticsId_Legal)

    assert validator.match(node)

    try:
        result = validator.validate(node)

        assert len(result.finding_descriptions) == 1

        assert result.finding_descriptions[0].finding == finding
    except validation.ValidationFindingEncountered as e:
        assert e.finding == finding


def _expect_no_findings_for_orgid(value):
    validator = LegalPersonOrganizationIdentifierValidator()

    node = _create_orgid_node(value, en_319_412_1.id_etsi_qcs_SemanticsId_Legal)

    assert validator.match(node)

    result = validator.validate(node)

    assert len(result.finding_descriptions) == 0


def test_no_match_no_qc_statement_orgid():
    validator = LegalPersonOrganizationIdentifierValidator()

    node = _create_orgid_node('FOO', None)

    assert not validator.match(node)


def test_no_match_different_semantics_id_orgid():
    validator = LegalPersonOrganizationIdentifierValidator()

    node = _create_orgid_node('FOO', en_319_412_1.id_etsi_qcs_semanticsId_Natural)

    assert not validator.match(node)


def test_invalid_orgid_format():
    values_under_test = [
        'TST',
        'TEST',
        'TESTXG-1',
        'TSTXG-',
        'NTRUS+VA-1',
    ]

    for value in values_under_test:
        _expect_finding_for_orgid_value(
            value,
            LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
        )


def test_invalid_orgid_scheme():
    values_under_test = [
        'FOOXG-1',
        'EI:XX-1',
        'EI:FR+PA-1',
    ]

    for value in values_under_test:
        _expect_finding_for_orgid_value(
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
        _expect_no_findings_for_orgid(value)


def test_vat_invalid_country():
    _expect_finding_for_orgid_value('VATXG-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY
                                    )


def test_vat_sp_present():
    _expect_finding_for_orgid_value('VATFR+PA-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_vat_no_reference():
    _expect_finding_for_orgid_value('VATFR',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_valid_ntr():
    values_under_test = [
        'NTRFR-1',
    ]

    for value in values_under_test:
        _expect_no_findings_for_orgid(value)


def test_ntr_invalid_country():
    _expect_finding_for_orgid_value('NTREL-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY
                                    )


def test_ntr_sp_present():
    _expect_finding_for_orgid_value('NTRFR+PA-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_ntr_no_reference():
    _expect_finding_for_orgid_value('NTRFR',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_valid_psd():
    values_under_test = [
        'PSDFR-1',
    ]

    for value in values_under_test:
        _expect_no_findings_for_orgid(value)


def test_psd_invalid_country():
    _expect_finding_for_orgid_value('PSDEL-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY
                                    )


def test_psd_sp_present():
    _expect_finding_for_orgid_value('PSDFR+PA-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_psd_no_reference():
    _expect_finding_for_orgid_value('PSDFR',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_valid_lei():
    values_under_test = [
        'LEIXG-1',  # length of reference and other checks are done by the LEI validator
    ]

    for value in values_under_test:
        _expect_no_findings_for_orgid(value)


def test_lei_invalid_country():
    _expect_finding_for_orgid_value('LEIFR-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY
                                    )


def test_lei_sp_present():
    _expect_finding_for_orgid_value('LEIXG+PA-1',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_lei_no_reference():
    _expect_finding_for_orgid_value('LEIXG',
                                    LegalPersonOrganizationIdentifierValidator.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT
                                    )


def test_orgid_national_scheme():
    values_under_test = [
        'EI:SE-5567971433'
    ]

    for value in values_under_test:
        _expect_finding_for_orgid_value(
            value,
            LegalPersonOrganizationIdentifierValidator.VALIDATION_ORGANIZATION_NATIONAL_SCHEME_DETECTED
        )


def _expect_finding_for_natural_person_id_value(value, finding):
    validator = NaturalPersonIdentifierValidator()

    node = _create_serialnumber_node(value, en_319_412_1.id_etsi_qcs_semanticsId_Natural)

    assert validator.match(node)

    try:
        result = validator.validate(node)

        assert len(result.finding_descriptions) == 1

        assert result.finding_descriptions[0].finding == finding
    except validation.ValidationFindingEncountered as e:
        assert e.finding == finding


def _expect_no_findings_for_natural_person_id(value):
    validator = NaturalPersonIdentifierValidator()

    node = _create_serialnumber_node(value, en_319_412_1.id_etsi_qcs_semanticsId_Natural)

    assert validator.match(node)

    result = validator.validate(node)

    assert len(result.finding_descriptions) == 0


def test_no_match_no_qc_statement_natural_person_id():
    validator = NaturalPersonIdentifierValidator()

    node = _create_serialnumber_node('FOO', None)

    assert not validator.match(node)


def test_no_match_different_semantics_id_natural_person_id():
    validator = NaturalPersonIdentifierValidator()

    node = _create_serialnumber_node('FOO', en_319_412_1.id_etsi_qcs_SemanticsId_Legal)

    assert not validator.match(node)


def test_invalid_natural_person_id_format():
    values_under_test = [
        'TST',
        'TEST',
        'TSTNO',
        'TESTXG-1',
        'TSTXG-',
        'NTRUS+VA-1',
    ]

    for value in values_under_test:
        _expect_finding_for_natural_person_id_value(
            value,
            NaturalPersonIdentifierValidator.VALIDATION_INVALID_NATURAL_PERSON_ID_FORMAT
        )


def test_invalid_natural_person_id_scheme():
    _expect_finding_for_natural_person_id_value(
        'FOOFR-1',
        NaturalPersonIdentifierValidator.VALIDATION_INVALID_NATURAL_PERSON_ID_SCHEME
    )


def test_valid_natural_person_values():
    values_under_test = [
        'PASFR-1',
        'IDCFR-1',
        'PNOFR-1',
        'TINFR-1',
    ]

    for value in values_under_test:
        _expect_no_findings_for_natural_person_id(value)


def test_deprecated_tax_value():
    _expect_finding_for_natural_person_id_value(
        'TAXFR-1',
        NaturalPersonIdentifierValidator.VALIDATION_DEPRECATED_NATURAL_PERSON_ID_SCHEME
    )


def test_invalid_natural_person_id_country():
    _expect_finding_for_natural_person_id_value(
        'PASXG-1',
        NaturalPersonIdentifierValidator.VALIDATION_INVALID_NATURAL_PERSON_ID_COUNTRY
    )


def test_natural_person_id_national_scheme():
    values_under_test = [
        'EI:SE-5567971433'
    ]

    for value in values_under_test:
        _expect_finding_for_natural_person_id_value(
            value,
            NaturalPersonIdentifierValidator.VALIDATION_NATURAL_PERSON_ID_NATIONAL_SCHEME_DETECTED
        )
