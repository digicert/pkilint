import argparse
import datetime
import functools
from typing import Type

import dateutil.parser

from pkilint import validation, report, loader, document
from pkilint.pkix.certificate import certificate_validity
from pkilint.report import REPORT_FORMATS, report_wrapper


class SeverityThresholdAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values == "ALL":
            severity = None
        elif values not in [s.name for s in validation.ValidationFindingSeverity]:
            raise argparse.ArgumentError(self, f'Invalid severity value: "{values}"')
        else:
            severity = validation.ValidationFindingSeverity[values]

        setattr(namespace, self.dest, severity)


def add_severity_arg(parser):
    parser.add_argument(
        "-s",
        "--severity",
        type=str.upper,
        default=validation.ValidationFindingSeverity.INFO,
        help="The finding severity threshold; findings with a lesser severity will not be reported.",
        action=SeverityThresholdAction,
        choices=[s.name for s in validation.ValidationFindingSeverity] + ["ALL"],
    )


class ReportFormatAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        report_generator_cls = REPORT_FORMATS[values]

        setattr(
            namespace,
            self.dest,
            functools.partial(report_wrapper, report_generator_cls),
        )


def add_report_format_arg(parser):
    parser.add_argument(
        "-f",
        "--format",
        type=str.upper,
        default=functools.partial(report_wrapper, report.ReportGeneratorPlaintext),
        help="The format in which results will be output.",
        choices=list(REPORT_FORMATS.keys()),
        action=ReportFormatAction,
    )


class DocumentFormatAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values not in (f.name for f in loader.DocumentFormat):
            raise argparse.ArgumentError(self, f'Invalid document format: "{values}"')

        document_format = loader.DocumentFormat[values]

        setattr(namespace, self.dest, document_format)


def add_document_format_arg(parser):
    parser.add_argument(
        "--document-format",
        type=str.upper,
        default=loader.DocumentFormat.DETECT,
        help="The format of the specified input document(s).",
        choices=[f.name for f in loader.DocumentFormat],
        action=DocumentFormatAction,
    )


class ValidityPeriodStartAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_retriever_class(cls) -> Type[document.ValidityPeriodStartRetriever]:
        pass

    def __call__(self, parser, namespace, values, option_string=None):
        value_casefolded = values.casefold()

        if value_casefolded == "document".casefold():
            retriever_instance = self.get_retriever_class()()
        elif value_casefolded == "now".casefold():
            retriever_instance = document.StaticValidityPeriodStartRetriever(
                datetime.datetime.now(tz=datetime.timezone.utc)
            )
        else:
            try:
                dt = dateutil.parser.isoparse(values)

                retriever_instance = document.StaticValidityPeriodStartRetriever(dt)
            except ValueError:
                raise argparse.ArgumentError(
                    self, f'Invalid value for validity period start: "{values}"'
                )

        setattr(namespace, self.dest, retriever_instance)


class CertificateValidityPeriodStartAction(ValidityPeriodStartAction):
    @classmethod
    def get_retriever_class(cls):
        return certificate_validity.CertificateValidityPeriodStartRetriever


def add_validity_period_start_arg(action_cls: Type[ValidityPeriodStartAction], parser):
    parser.add_argument(
        "--validity-period-start",
        action=action_cls,
        default=action_cls.get_retriever_class()(),
        help="The start of the validity period that is compared to effective dates to determine applicability of "
        'validations. Acceptable values are "DOCUMENT" (use the validity period indicated in the document being '
        'validated, "NOW" (use the current time), or an ISO 8601-formatted date/time value.',
    )


add_certificate_validity_period_start_arg = functools.partial(
    add_validity_period_start_arg, CertificateValidityPeriodStartAction
)


def add_standard_args(parser):
    add_severity_arg(parser)
    add_report_format_arg(parser)
    add_document_format_arg(parser)


# This ensures that if a large (>255) number of findings are reported, we don't accidentally exit with an
# exit code of 0. This could happen if the number of findings is a multiple of 256.
def clamp_exit_code(exit_code):
    return min(exit_code, 255)
