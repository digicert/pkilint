#!/usr/bin/env python

import argparse
import sys

from pkilint import loader
from pkilint import report, util
from pkilint.pkix import certificate, name, extension


def main(cli_args=None) -> int:
    parser = argparse.ArgumentParser(description='RFC 5280 Certificate Linter')

    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('validations', help='Output the set of validations which this linter performs')

    lint_parser = subparsers.add_parser('lint', help='Lint the specified certificate')
    util.add_standard_args(lint_parser)

    lint_parser.add_argument('file', type=argparse.FileType('rb'),
                             help='The certificate to lint'
                             )

    args = parser.parse_args(cli_args)

    doc_validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
        [
            certificate.create_issuer_validator_container(
                []
            ),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container(
                []
            ),
            certificate.create_extensions_validator_container(
                []
            ),
        ]
    )

    if args.command == 'validations':
        print(report.report_included_validations(doc_validator))

        return 0
    else:
        cert = loader.load_certificate(args.file, args.file.name)

        results = doc_validator.validate(cert.root)

        print(args.format(results, args.severity))

        return report.get_findings_count(results, args.severity)


if __name__ == "__main__":
    sys.exit(main())
