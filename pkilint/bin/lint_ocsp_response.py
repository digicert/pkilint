#!/usr/bin/env python

import argparse
import sys

from pkilint import pkix
from pkilint import cli_util, loader, report
from pkilint.pkix import extension, name, ocsp


def main(cli_args=None) -> int:
    parser = argparse.ArgumentParser(description="RFC 6960 OCSP Response Linter")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "validations", help="Output the set of validations which this linter performs"
    )

    lint_parser = subparsers.add_parser("lint", help="Lint the specified OCSP response")
    cli_util.add_standard_args(lint_parser)

    lint_parser.add_argument(
        "file", type=argparse.FileType("rb"), help="The OCSP response to lint"
    )

    args = parser.parse_args(cli_args)

    doc_validator = ocsp.create_pkix_ocsp_response_validator_container(
        [
            ocsp.create_response_decoder(),
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        [],
    )

    if args.command == "validations":
        print(report.report_included_validations(doc_validator))

        return 0
    else:
        try:
            ocsp_response = (
                loader.RFC6960OCSPResponseDocumentLoader().get_file_loader_func(
                    args.document_format
                )(args.file, args.file.name)
            )
        except ValueError as e:
            print(f"Failed to load OCSP response: {e}", file=sys.stderr)
            return 1

        results = doc_validator.validate(ocsp_response.root)

        print(args.format(results, args.severity))

        return cli_util.clamp_exit_code(
            report.get_findings_count(results, args.severity)
        )


if __name__ == "__main__":
    sys.exit(main())
