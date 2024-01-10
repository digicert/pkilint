#!/usr/bin/env python

import argparse
import sys

from pkilint import etsi
from pkilint import loader, report, util, finding_filter
from pkilint.etsi import etsi_constants
from pkilint.pkix import certificate

_CERTIFICATE_TYPE_OPTIONS = [str(t).replace('_', '-') for t in etsi_constants.CertificateType]


class EtsiCertificateTypeAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        cert_type = etsi_constants.CertificateType.from_option_str(values)

        setattr(namespace, self.dest, cert_type)


def main(cli_args=None) -> int:
    parser = argparse.ArgumentParser(
        description=f'ETSI v{etsi_constants.EN_319_412_VERSION} Certificate Linter'
    )

    subparsers = parser.add_subparsers(dest='command', required=True)

    validations_parser = subparsers.add_parser('validations',
                                               help='Output the set of validations which this linter performs')
    validations_parser.add_argument('-t', '--type', required=True,
                                    type=str.upper,
                                    action=EtsiCertificateTypeAction,
                                    help='The type of certificate',
                                    choices=_CERTIFICATE_TYPE_OPTIONS)

    lint_parser = subparsers.add_parser('lint', help='Lint the specified certificate')

    detect_options_group = lint_parser.add_mutually_exclusive_group(required=True)
    detect_options_group.add_argument('-d', '--detect', action='store_true',
                                      help='Detect the type of certificate from reserved CA/B Forum policy '
                                           'OIDs and qualified certificate statements.')
    detect_options_group.add_argument('-t', '--type',
                                      type=str.upper,
                                      action=EtsiCertificateTypeAction,
                                      help='The type of certificate',
                                      choices=_CERTIFICATE_TYPE_OPTIONS)
    lint_parser.add_argument('-o', '--output', action='store_true',
                             help='Output the type of certificate to standard error. This option may be '
                                  'useful when using the --detect option.')
    lint_parser.add_argument('-r', '--report-all', action='store_true', help='Report all findings without filtering '
                             'any findings that are superseded by other requirements')

    util.add_standard_args(lint_parser)
    lint_parser.add_argument('file', type=argparse.FileType('rb'),
                             help='The certificate to lint'
                             )

    args = parser.parse_args(cli_args)

    if args.command == 'validations':
        doc_validator = certificate.create_pkix_certificate_validator_container(
            etsi.create_decoding_validators(),
            etsi.create_validators(args.type)
        )

        print(report.report_included_validations(doc_validator))

        return 0
    else:
        cert = loader.load_certificate(args.file, args.file.name)

        if args.type:
            certificate_type = args.type
        else:
            certificate_type = etsi.determine_certificate_type(cert)

        if args.output:
            print(certificate_type.to_option_str, file=sys.stderr)

        doc_validator = certificate.create_pkix_certificate_validator_container(
            etsi.create_decoding_validators(),
            etsi.create_validators(certificate_type)
        )

        results = doc_validator.validate(cert.root)

        if not args.report_all:
            results, _ = finding_filter.filter_results(
                etsi.create_etsi_finding_filters(certificate_type), results
            )

        print(args.format(results, args.severity))

        return report.get_findings_count(results, args.severity)


if __name__ == "__main__":
    sys.exit(main())
