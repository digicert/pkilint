#!/usr/bin/env python

import argparse
import sys

from pkilint import loader, pkix, report, cli_util
from pkilint.cabf import cabf_crl
from pkilint.pkix import crl, name, extension


def _add_args(parser):
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        type=str.upper,
        choices=["CRL", "ARL"],
        help="The type of CRL (whether the CRL in question is a CRL or an ARL)",
    )
    parser.add_argument(
        "-p",
        "--profile",
        required=True,
        type=str.upper,
        choices=["PKIX", "BR"],
        default="PKIX",
        help="The profile against which to lint",
    )


def main(cli_args=None) -> int:
    parser = argparse.ArgumentParser(description="RFC 5280 and CA/B Forum CRL Linter")

    subparsers = parser.add_subparsers(dest="command", required=True)
    validations_parser = subparsers.add_parser(
        "validations", help="Output the set of validations which this linter performs"
    )
    _add_args(validations_parser)

    lint_parser = subparsers.add_parser("lint", help="Lint the specified CRL")
    _add_args(lint_parser)
    cli_util.add_standard_args(lint_parser)

    lint_parser.add_argument(
        "file", type=argparse.FileType("rb"), help="The CRL file to lint"
    )

    args = parser.parse_args(cli_args)

    crl_type = crl.CertificateRevocationListType[args.type]

    validity_additional_validators = []
    doc_additional_validators = []

    if args.profile == "BR":
        doc_additional_validators.append(
            cabf_crl.CabfCrlReasonCodeAllowlistValidator(crl_type)
        )

        validity_additional_validators.append(
            cabf_crl.create_validity_period_validator(crl_type)
        )

    doc_validator = crl.create_pkix_crl_validator_container(
        [
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        [
            crl.create_issuer_validator_container([]),
            crl.create_validity_validator_container(validity_additional_validators),
            crl.create_extensions_validator_container([]),
        ]
        + doc_additional_validators,
    )

    if args.command == "validations":
        print(report.report_included_validations(doc_validator))

        return 0
    else:
        try:
            crl_doc = (
                loader.RFC5280CertificateListDocumentLoader().get_file_loader_func(
                    args.document_format
                )(args.file, args.file.name)
            )
        except ValueError as e:
            print(f"Failed to load CRL: {e}", file=sys.stderr)
            return 1

        results = doc_validator.validate(crl_doc.root)

        print(args.format(results, args.severity))

        return cli_util.clamp_exit_code(
            report.get_findings_count(results, args.severity)
        )


if __name__ == "__main__":
    sys.exit(main())
