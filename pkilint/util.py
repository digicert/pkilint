import argparse
import functools

from cryptography.hazmat.primitives import hashes

from pkilint import validation, report
from pkilint.report import report_wrapper, REPORT_FORMATS


def calculate_hash(octets: bytes, hash_algo: hashes.HashAlgorithm) -> bytes:
    h = hashes.Hash(hash_algo)
    h.update(octets)

    return h.finalize()


def calculate_sha1_hash(octets: bytes) -> bytes:
    return calculate_hash(octets, hashes.SHA1())


def argparse_enum_type_parser(enum_type):
    def _parse(value):
        value = value.upper()

        try:
            return enum_type[value]
        except KeyError:
            raise ValueError(value)

    return _parse


class SeverityThresholdAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values == 'ALL':
            severity = None
        elif values not in [s.name for s in validation.ValidationFindingSeverity]:
            raise argparse.ArgumentError(self, f'Invalid severity value: "{values}"')
        else:
            severity = validation.ValidationFindingSeverity[values]

        setattr(namespace, self.dest, severity)


def add_severity_arg(parser):
    parser.add_argument('-s', '--severity',
                        type=str.upper,
                        default=validation.ValidationFindingSeverity.INFO,
                        help='The finding severity threshold; findings with a lesser severity will not be reported.',
                        action=SeverityThresholdAction,
                        choices=[s.name for s in validation.ValidationFindingSeverity] + ['ALL']
                        )


class ReportFormatAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        report_generator_cls = REPORT_FORMATS[values]

        setattr(namespace, self.dest, functools.partial(report_wrapper, report_generator_cls))


def add_report_format_arg(parser):
    parser.add_argument('-f', '--format',
                        type=str.upper,
                        default=functools.partial(report_wrapper, report.ReportGeneratorPlaintext),
                        help='The format in which results will be output.',
                        choices=list(REPORT_FORMATS.keys()),
                        action=ReportFormatAction
                        )


def add_standard_args(parser):
    add_severity_arg(parser)
    add_report_format_arg(parser)


# This ensures that if a large (>255) number of findings are reported, we don't accidentally exit with an
# exit code of 0. This could happen if the number of findings is a multiple of 256.
def clamp_exit_code(exit_code):
    return min(exit_code, 255)
