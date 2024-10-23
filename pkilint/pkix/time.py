import operator
import re
from datetime import datetime, timedelta
from datetime import timezone

from dateutil.relativedelta import relativedelta
from pyasn1.type import useful
from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.document import PDUNavigationFailedError

_REGEX_UTC_TIME = re.compile(
    r"^(?P<year>\d{2})(?P<month>\d{2})(?P<day>\d{2})"
    r"(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z$"
)

_REGEX_GENERALIZED_TIME = re.compile(
    r"^(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})"
    r"(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z$"
)

VALIDATION_INVALID_TIME_SYNTAX = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "pkix.invalid_time_syntax"
)


def _match_to_datetime(m):
    # check if UTCTime
    has_2_digit_year = len(m["year"]) == 2

    date_components = {k: int(v) for k, v in m.groupdict().items()}

    if has_2_digit_year:
        if date_components["year"] >= 50:
            date_components["year"] += 1900
        else:
            date_components["year"] += 2000

    return datetime(
        date_components["year"],
        date_components["month"],
        date_components["day"],
        date_components["hour"],
        date_components["minute"],
        date_components["second"],
        0,  # msec
        timezone.utc,
    )


def parse_generalizedtime(value):
    strval = str(value)

    m = _REGEX_GENERALIZED_TIME.match(strval)
    if m is None:
        raise ValueError(
            f'"{strval}" does not match GeneralizedTime regular '
            f'expression "{_REGEX_GENERALIZED_TIME.pattern}"'
        )

    return _match_to_datetime(m)


def parse_utctime(value):
    strval = str(value)

    m = _REGEX_UTC_TIME.match(strval)
    if m is None:
        raise ValueError(
            f'"{strval}" does not match UTCTime regular '
            f'expression "{_REGEX_UTC_TIME.pattern}"'
        )

    return _match_to_datetime(m)


def parse_time_node(value):
    if "generalTime" in value.children:
        return parse_generalizedtime(value.children["generalTime"].pdu)
    else:
        return parse_utctime(value.children["utcTime"].pdu)


class TimeCorrectEncodingValidator(validation.Validator):
    VALIDATION_WRONG_TIME_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.wrong_time_useful_type"
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.Time,
            validations=[
                self.VALIDATION_WRONG_TIME_TYPE,
            ],
        )

    def validate(self, node):
        try:
            parsed_datetime = parse_time_node(node)
        except ValueError:
            # the time syntax validator will report any errors
            return

        if (
            ("generalTime" in node.children)
            and (parsed_datetime.year >= 1950)
            and (parsed_datetime.year < 2050)
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_WRONG_TIME_TYPE,
                "Time values that contain a year value of "
                f'"{parsed_datetime.year}" must be encoded using UTCTime',
            )


def _parse_date(node):
    try:
        if isinstance(node.pdu, rfc5280.Time):
            return parse_time_node(node)
        elif isinstance(node.pdu, useful.GeneralizedTime):
            return parse_generalizedtime(str(node.pdu))
        elif isinstance(node.pdu, useful.UTCTime):
            return parse_utctime(str(node.pdu))
        else:
            raise ValueError("Unsupported ASN.1 time type")
    except ValueError as e:
        raise validation.ValidationFindingEncountered(
            VALIDATION_INVALID_TIME_SYNTAX, f"{node.name}: {str(e)}"
        )


class ValidityPeriodDifferenceValidator(validation.Validator):
    VALIDATION_PERIOD_END_VALIDITY_NODE_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.validity_period_end_value_missing",
    )

    def __init__(self, *, end_validity_node_retriever, validations, **kwargs):
        self._end_validity_node_retriever = end_validity_node_retriever

        super().__init__(
            validations=[
                VALIDATION_INVALID_TIME_SYNTAX,
                self.VALIDATION_PERIOD_END_VALIDITY_NODE_MISSING,
            ]
            + validations,
            **kwargs,
        )

    def validate(self, node):
        try:
            end_node = self._end_validity_node_retriever(node)
        except PDUNavigationFailedError:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PERIOD_END_VALIDITY_NODE_MISSING
            )

        start_datetime = _parse_date(node)
        end_datetime = _parse_date(end_node)

        self.validate_date_range(start_datetime, end_datetime)

    def validate_date_range(self, start_datetime, end_datetime):
        pass


class SaneValidityPeriodValidator(ValidityPeriodDifferenceValidator):
    def __init__(self, *, end_validity_node_retriever, validation, **kwargs):
        self._invalid_validity_period_validation = validation

        super().__init__(
            end_validity_node_retriever=end_validity_node_retriever,
            validations=[validation],
            **kwargs,
        )

    def validate_date_range(self, start_datetime, end_datetime):
        if start_datetime > end_datetime:
            raise validation.ValidationFindingEncountered(
                self._invalid_validity_period_validation,
                f'Start of validity period "{start_datetime}" is greater than '
                f'end of validity period "{end_datetime}"',
            )


class ValidityPeriodThresholdsValidator(ValidityPeriodDifferenceValidator):
    def __init__(
        self,
        *,
        end_validity_node_retriever,
        inclusive_second=False,
        validity_period_thresholds,
        **kwargs,
    ):
        validity_period_thresholds.sort(key=lambda v: v[2].severity)

        validations = [v[2] for v in validity_period_thresholds]

        self._validity_period_thresholds = validity_period_thresholds
        self._inclusive_second = inclusive_second

        super().__init__(
            end_validity_node_retriever=end_validity_node_retriever,
            validations=validations,
            **kwargs,
        )

    def validate_date_range(self, start_datetime, end_datetime):
        if self._inclusive_second:
            end_datetime += timedelta(seconds=1)
        validity = end_datetime - start_datetime

        for op, threshold_value, finding in self._validity_period_thresholds:
            if isinstance(threshold_value, relativedelta):
                is_valid = op(end_datetime, start_datetime + threshold_value)
            else:
                is_valid = op(validity, threshold_value)

            if not is_valid:
                if op in [operator.ge, operator.gt]:
                    raise validation.ValidationFindingEncountered(
                        finding,
                        f"Validity period of {validity} is below minimum "
                        f"value of {threshold_value}",
                    )
                else:
                    raise validation.ValidationFindingEncountered(
                        finding,
                        f"Validity period of {validity} exceeds maximum "
                        f"value of {threshold_value}",
                    )


class UtcTimeCorrectSyntaxValidator(validation.Validator):
    VALIDATION_INCORRECT_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.utctime_incorrect_syntax"
    )

    def __init__(self):
        super().__init__(
            pdu_class=useful.UTCTime, validations=[self.VALIDATION_INCORRECT_SYNTAX]
        )

    def validate(self, node):
        try:
            parse_utctime(node.pdu)
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INCORRECT_SYNTAX, str(e)
            )


class GeneralizedTimeCorrectSyntaxValidator(validation.Validator):
    VALIDATION_INCORRECT_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.generalizedtime_incorrect_syntax",
    )

    def __init__(self):
        super().__init__(
            pdu_class=useful.GeneralizedTime,
            validations=[self.VALIDATION_INCORRECT_SYNTAX],
        )

    def validate(self, node):
        try:
            parse_generalizedtime(node.pdu)
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INCORRECT_SYNTAX, str(e)
            )
