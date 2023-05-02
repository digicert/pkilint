#!/usr/bin/env python

import argparse

import pkilint.pkix.certificate
from pkilint import cabf, loader, report, util, etsi
from pkilint.cabf import servercert
from pkilint.pkix import certificate


def main():
    parser = argparse.ArgumentParser(
        description='CA/B Forum TLS BR Certificate Linter'
    )

    subparsers = parser.add_subparsers(dest='command', required=True)

    validations_parser = subparsers.add_parser('validations',
                                               help='Output the set of validations which this linter performs')
    validations_parser.add_argument('-t', '--type', required=True,
                                    type=util.argparse_enum_type_parser(servercert.CertificateType),
                                    help='The type of TLS certificate',
                                    choices=list(servercert.CertificateType))

    lint_parser = subparsers.add_parser('lint', help='Lint the specified certificate')
    lint_parser.add_argument('-t', '--type', required=True,
                                    type=util.argparse_enum_type_parser(servercert.CertificateType),
                                    help='The type of TLS certificate',
                                    choices=list(servercert.CertificateType))
    util.add_standard_args(lint_parser)
    lint_parser.add_argument('file', type=argparse.FileType('rb'),
                        help='The certificate to lint'
                        )

    args = parser.parse_args()

    doc_validator = certificate.create_pkix_certificate_validator_container(
        pkilint.pkix.certificate.create_decoding_validators(cabf.NAME_ATTRIBUTE_MAPPINGS, cabf.EXTENSION_MAPPINGS, [
            pkilint.pkix.certificate.create_qc_statements_decoder(etsi.ETSI_QC_STATEMENTS_MAPPINGS),
        ]),
        servercert.create_validators(args.type)
    )

    if args.command == 'validations':
        print(report.report_included_validations(doc_validator))
    else:
        cert = loader.load_certificate(args.file, args.file.name)

        results = doc_validator.validate(cert.root)

        print(args.format(results, args.severity))

        exit(report.get_findings_count(results, args.severity))


if __name__ == "__main__":
    main()
