import enum
import itertools
import logging
from typing import Callable, NamedTuple, List, Optional

from pyasn1.codec.der.encoder import encode
from pyasn1.type.constraint import PermittedAlphabetConstraint, ValueRangeConstraint
from pyasn1.type.error import ValueConstraintError
from pyasn1.type.univ import ObjectIdentifier

from pkilint.document import (
    PDUNode,
    NodeVisitor,
    SubstrateDecodingFailedError,
    PDUNavigationFailedError,
)

logger = logging.getLogger(__name__)


@enum.unique
class ValidationFindingSeverity(enum.IntEnum):
    """Represents the severity of a finding raised by a validator"""

    FATAL = 0
    """A violation so severe that the validator cannot proceed"""

    ERROR = 1
    """A clear violation of a standard or policy (e.g., violating a "MUST")"""

    WARNING = 2
    """A clear violation of best practice (e.g., violating a "SHOULD")"""

    NOTICE = 3
    """Not a clear violation of best practice or standard, but something to be noted"""

    INFO = 4
    """Informative findings that are not indicative of any problem"""

    DEBUG = 5
    """Information solely useful for debugging"""

    def __str__(self):
        return self.name


class ValidationFinding(NamedTuple):
    """Represents a finding that may be raised by a validator"""

    severity: ValidationFindingSeverity
    """The severity of the validation finding"""

    code: str
    """An identifier that specifies the part of standard or policy that is being validated"""

    def __repr__(self):
        return f"{self.code} ({self.severity.name})"


class ValidationFindingDescription(NamedTuple):
    """Represents a finding that is raised by a validator. Optionally may include a message"""

    finding: ValidationFinding
    """The finding raised by the validator"""

    message: Optional[str]
    """A optional message that provides additional human-readable context for the finding"""

    def __repr__(self):
        message = f": {self.message}" if self.message else ""

        return f"{self.finding}{message}"


class Validator(NodeVisitor):
    """Validates a document (or part thereof) for compliance with a policy or standard"""

    VALIDATION_FINDING_UNHANDLED_EXCEPTION = ValidationFinding(
        ValidationFindingSeverity.FATAL, "base.unhandled_exception"
    )
    """A finding that indicates an exception occurred during validation"""

    def __init__(self, *, validations=None, **kwargs):
        super().__init__(**kwargs)

        if validations is None:
            validations = []
        if not isinstance(validations, list):
            validations = [validations]

        self._validations = validations

    def validate_wrapper(self, node: PDUNode) -> "ValidationResult":
        try:
            # pylint: disable=assignment-from-no-return
            results = self.validate(node)
            if results is None:
                return ValidationResult(self, node, [])
            else:
                return results

        except ValidationFindingEncountered as e:
            finding = ValidationFindingDescription(e.finding, e.message)
        except Exception as e:
            logger.exception(
                "Unhandled exception occurred when executing "
                "validator %s on node %s",
                self.name,
                node.path,
            )
            finding = ValidationFindingDescription(
                self.VALIDATION_FINDING_UNHANDLED_EXCEPTION, str(e)
            )

        return ValidationResult(self, node, [finding])

    def validate(self, node: PDUNode) -> "ValidationResult":
        """Validates the specified node"""
        pass

    @property
    def tags(self) -> List[str]:
        return ["static"]

    @property
    def validations(self) -> List[ValidationFinding]:
        return self._validations + [self.VALIDATION_FINDING_UNHANDLED_EXCEPTION]

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def __repr__(self) -> str:
        return self.name


class ValidationResult(NamedTuple):
    """Represents the result of running a validator on a document node"""

    validator: Validator
    """The validator that was executed"""
    node: PDUNode
    """The node of the document that was validated"""
    finding_descriptions: List[ValidationFindingDescription]
    """The list of findings and their associated messages"""

    def __repr__(self):
        findings_str = ", ".join([str(f) for f in self.finding_descriptions])
        return f'{self.validator} result for "{self.node}": {findings_str}'


class ValidationFindingEncountered(Exception):
    """A convenient way to raise findings from a validator"""

    def __init__(self, finding: ValidationFinding, message: str = None):
        self.finding = finding
        """The finding that is being raised by the validator"""
        self.message = message
        """An optional message providing additional human-readable context for the finding"""


class ValidatorContainer(Validator):
    """A collection of validators that recursively executes all included
    validators on the matching document node and its children"""

    def __init__(self, *, validators: List[Validator], **kwargs):
        self.validators = validators
        validations_2d = (v.validations for v in self.validators)
        validations_1d = itertools.chain.from_iterable(validations_2d)

        all_validations = [
            v
            for v in validations_1d
            if v is not self.VALIDATION_FINDING_UNHANDLED_EXCEPTION
        ]

        super().__init__(validations=all_validations, **kwargs)

    def _validate_rec(self, node: PDUNode, results: List[ValidationResult]):
        for v in self.validators:
            if v.match(node):
                result = v.validate_wrapper(node)

                if isinstance(result, list):
                    results += result
                else:
                    results.append(result)

        for child_node in node.children.values():
            self._validate_rec(child_node, results)

    def validate(self, node: PDUNode) -> List[ValidationResult]:
        results = []

        self._validate_rec(node, results)

        return results


class ScalarFieldValueEqualityValidator(Validator):
    def __init__(self, *, value, **kwargs):
        super().__init__(**kwargs)

        self.value = value

    def validate(self, node: PDUNode):
        if node.pdu != self.value:
            validation = self.validations[0]

            raise ValidationFindingEncountered(
                validation, f'Expected="{self.value}", actual="{node.pdu}"'
            )


class ASN1ConstraintValidator(Validator):
    def __init__(self, constraint, **kwargs):
        super().__init__(**kwargs)

        self.constraint = constraint

    def _get_message(self, exc):
        if isinstance(self.constraint, PermittedAlphabetConstraint):
            return (
                'Invalid character outside permitted alphabet of "'
                f'{"".join(self.constraint._values)}"'
            )
        elif isinstance(self.constraint, ValueRangeConstraint):
            return (
                "Invalid value outside range "
                f"{self.constraint.start} - {self.constraint.stop}"
            )
        else:
            return "ASN.1 constraint violation"

    def validate(self, node):
        try:
            self.constraint(node.pdu)
        except ValueConstraintError as e:
            validation = self.validations[0]

            raise ValidationFindingEncountered(
                validation,
                f"ASN.1 constraint failed: {self._get_message(e)} "
                f'on content "{node.pdu}"',
            )


class DecodingValidator(Validator):
    VALIDATION_ASN1_DECODING_FAILURE = ValidationFinding(
        ValidationFindingSeverity.FATAL, "itu.invalid_asn1_syntax"
    )

    def __init__(self, *, decode_func=Callable[[PDUNode], None], **kwargs):
        self.decode_func = decode_func

        super().__init__(validations=[self.VALIDATION_ASN1_DECODING_FAILURE], **kwargs)

    def validate(self, node):
        try:
            self.decode_func(node)
        except SubstrateDecodingFailedError as e:
            raise ValidationFindingEncountered(
                self.VALIDATION_ASN1_DECODING_FAILURE, e.message
            )


class TypeMatchingValidator(Validator):
    def __init__(
        self, *, type_path: str, type_oid: ObjectIdentifier, value_path: str, **kwargs
    ):
        self.type_path = type_path
        self.type_oid = type_oid
        self.value_path = value_path

        super().__init__(**kwargs)

    def match(self, node):
        if not super().match(node):
            return False

        type_node = node.navigate(self.type_path)

        return type_node.pdu == self.type_oid

    def validate_with_value(self, node, value_node):
        pass

    def validate(self, node):
        value_node = node.navigate(self.value_path)

        return self.validate_with_value(node, value_node)


class DEREqualityValidator(Validator):
    def __init__(
        self,
        *,
        other_node_retriever=Callable[[PDUNode], PDUNode],
        validation: ValidationFinding,
        **kwargs,
    ):
        self._other_node_retriever = other_node_retriever

        super().__init__(**kwargs, validations=[validation])

    def validate(self, node):
        other_node = self._other_node_retriever(node)

        if encode(node.pdu) != encode(other_node.pdu):
            raise ValidationFindingEncountered(
                self.validations[0],
                f"DER encoding of {node.path} and {other_node.path} are " f"not equal",
            )


class NodePresenceValidator(Validator):
    def __init__(
        self,
        *,
        node_retriever: Callable[[PDUNode], PDUNode],
        absence_finding: ValidationFinding = None,
        presence_finding: ValidationFinding = None,
        **kwargs,
    ):
        self._node_retriever = node_retriever
        self._absence_finding = absence_finding
        self._presence_finding = presence_finding

        validations = []
        if absence_finding is not None:
            validations.append(absence_finding)
        if presence_finding is not None:
            validations.append(presence_finding)

        super().__init__(validations=validations, **kwargs)

    def validate(self, node):
        try:
            self._node_retriever(node)

            if self._presence_finding is not None:
                raise ValidationFindingEncountered(self._presence_finding)
        except PDUNavigationFailedError:
            if self._absence_finding is not None:
                raise ValidationFindingEncountered(self._absence_finding)
