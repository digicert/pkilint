from pkilint import document, validation, report


class DummyValidator1(validation.Validator):
    pass


class DummyValidator2(validation.Validator):
    pass


_DUMMY_NODE_1 = document.PDUNode(None, "foo", None, None)
_DUMMY_NODE_2 = document.PDUNode(None, "bar", None, None)


_RESULTS = [
    validation.ValidationResult(DummyValidator1(), _DUMMY_NODE_1, []),
    validation.ValidationResult(
        DummyValidator2(),
        _DUMMY_NODE_2,
        [
            validation.ValidationFindingDescription(
                validation.ValidationFinding(
                    severity=validation.ValidationFindingSeverity.INFO,
                    code="info_finding",
                ),
                None,
            ),
            validation.ValidationFindingDescription(
                validation.ValidationFinding(
                    severity=validation.ValidationFindingSeverity.ERROR,
                    code="error_finding",
                ),
                "The error message",
            ),
        ],
    ),
]


def test_plaintext_all():
    gen = report.ReportGeneratorPlaintext(_RESULTS, None)

    assert (
        gen.generate()
        == "DummyValidator1 @ foo\nDummyValidator2 @ bar\n    info_finding (INFO)\n    error_finding (ERROR): The error message\n"
    )


def test_plaintext_info():
    gen = report.ReportGeneratorPlaintext(
        _RESULTS, validation.ValidationFindingSeverity.INFO
    )

    assert (
        gen.generate()
        == "DummyValidator2 @ bar\n    info_finding (INFO)\n    error_finding (ERROR): The error message\n"
    )


def test_plaintext_warning():
    gen = report.ReportGeneratorPlaintext(
        _RESULTS, validation.ValidationFindingSeverity.WARNING
    )

    assert (
        gen.generate()
        == "DummyValidator2 @ bar\n    error_finding (ERROR): The error message\n"
    )


def test_csv_all():
    gen = report.ReportGeneratorCsv(_RESULTS, None)

    assert (
        gen.generate()
        == "node_path,validator,severity,code,message\r\nbar,DummyValidator2,INFO,info_finding,\r\nbar,DummyValidator2,ERROR,error_finding,The error message\r\n"
    )


def test_csv_info():
    gen = report.ReportGeneratorCsv(_RESULTS, validation.ValidationFindingSeverity.INFO)

    assert (
        gen.generate()
        == "node_path,validator,severity,code,message\r\nbar,DummyValidator2,INFO,info_finding,\r\nbar,DummyValidator2,ERROR,error_finding,The error message\r\n"
    )


def test_csv_warning():
    gen = report.ReportGeneratorCsv(
        _RESULTS, validation.ValidationFindingSeverity.WARNING
    )

    assert (
        gen.generate()
        == "node_path,validator,severity,code,message\r\nbar,DummyValidator2,ERROR,error_finding,The error message\r\n"
    )


def test_json_all():
    gen = report.ReportGeneratorJson(_RESULTS, None)

    assert (
        gen.generate()
        == '{"results": [{"node_path": "foo", "validator": "DummyValidator1", "finding_descriptions": []}, {"node_path": "bar", "validator": "DummyValidator2", "finding_descriptions": [{"severity": "INFO", "code": "info_finding", "message": null}, {"severity": "ERROR", "code": "error_finding", "message": "The error message"}]}]}'
    )


def test_json_info():
    gen = report.ReportGeneratorJson(
        _RESULTS, validation.ValidationFindingSeverity.INFO
    )

    assert (
        gen.generate()
        == '{"results": [{"node_path": "bar", "validator": "DummyValidator2", "finding_descriptions": [{"severity": "INFO", "code": "info_finding", "message": null}, {"severity": "ERROR", "code": "error_finding", "message": "The error message"}]}]}'
    )


def test_json_warning():
    gen = report.ReportGeneratorJson(
        _RESULTS, validation.ValidationFindingSeverity.WARNING
    )

    assert (
        gen.generate()
        == '{"results": [{"node_path": "bar", "validator": "DummyValidator2", "finding_descriptions": [{"severity": "ERROR", "code": "error_finding", "message": "The error message"}]}]}'
    )
