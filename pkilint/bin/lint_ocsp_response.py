#!/usr/bin/env python

import argparse

from pkilint import pkix
from pkilint import util, loader, report
from pkilint.pkix import extension, name, ocsp


def main(cli_args=None):
    parser = argparse.ArgumentParser(description='RFC 6960 OCSP Response Linter')

    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('validations', help='Output the set of validations which this linter performs')

    lint_parser = subparsers.add_parser('lint', help='Lint the specified OCSP response')
    util.add_standard_args(lint_parser)

    lint_parser.add_argument('file', type=argparse.FileType('rb'),
                             help='The OCSP response to lint'
                             )

    args = parser.parse_args(cli_args)

    doc_validator = ocsp.create_pkix_ocsp_response_validator_container(
        [
            ocsp.create_response_decoder(),
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        []
    )

    if args.command == 'validations':
        print(report.report_included_validations(doc_validator))
    else:
        ocsp_response = loader.load_ocsp_response(args.file, args.file.name)

        results = doc_validator.validate(ocsp_response.root)

        print(args.format(results, args.severity))

        exit(report.get_findings_count(results, args.severity))


if __name__ == "__main__":
    main()
