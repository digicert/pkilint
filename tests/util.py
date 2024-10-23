import io
import operator
from typing import Iterable

from pkilint import document, loader, validation


def create_document(pdu):
    name = document.get_node_name_for_pdu(pdu)
    doc = document.Document(None, "test", pdu)

    doc.root = document.PDUNode(doc, name, pdu, None)

    return doc.root


class ExpectedResult(document.NodeVisitor):
    def __init__(self, expected_findings, expected_count=1, **kwargs):
        self._expected_findings = set(expected_findings)
        self.expected_count = expected_count

        super().__init__(**kwargs)

    def validate(self, actual_result: validation.ValidationResult):
        actual_findings = set(
            map(operator.attrgetter("finding"), actual_result.finding_descriptions)
        )

        assert (
            actual_findings == self._expected_findings
        ), "Actual findings are different from expected findings"

    def __repr__(self) -> str:
        findings_str = "\n".join([f"  - {f}" for f in self._expected_findings])
        return f"Expected findings: \n{findings_str}\nExpected count: {self.expected_count}"


def compare_results(
    actual_results: Iterable[validation.ValidationResult], expected_results=None
):
    if expected_results is None:
        expected_results = []
    for expected_result in expected_results:
        matched = [r for r in actual_results if expected_result.match(r.node)]

        assert len(matched) == expected_result.expected_count, (
            "Unexpected number of node matches. "
            f"Expected: {expected_result.expected_count}  "
            f"Actual: {len(matched)}"
        )

        for actual_result in matched:
            expected_result.validate(actual_result)

    for result_with_finding in (
        r for r in actual_results if any(r.finding_descriptions)
    ):
        expected = False
        for expected_result in expected_results:
            if expected_result.match(result_with_finding.node):
                expected = True
                break

        assert expected, f"Result has unexpected findings: {result_with_finding}"


def certificate_test_harness(
    substrate,
    validator: validation.Validator,
    expected_results=None,
    decoding_container: validation.ValidatorContainer = None,
):
    if expected_results is None:
        expected_results = []
    if isinstance(substrate, str):
        substrate = substrate.encode("us-ascii")

    doc = loader.load_certificate(io.BytesIO(substrate), "test")

    doc_validator_container = []
    if decoding_container is not None:
        doc_validator_container.append(decoding_container)

    doc_validator_container.append(validator)

    container = validation.ValidatorContainer(validators=doc_validator_container)

    results = container.validate(doc.root)

    compare_results(results, expected_results)
