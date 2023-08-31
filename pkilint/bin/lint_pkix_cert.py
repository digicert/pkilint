#!/usr/bin/env python

import argparse

from pkilint import loader
from pkilint import pkix, report, util
from pkilint.pkix import certificate, general_name, name, extension, algorithm
from pkilint.pkix.certificate import certificate_extension, certificate_key


def main(cli_args=None):
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
        [
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
            pkix.create_signature_algorithm_identifier_decoder(
                algorithm.SIGNATURE_ALGORITHM_IDENTIFIER_MAPPINGS,
                path='certificate.tbsCertificate.signature'
            ),
            certificate.create_spki_decoder(
                certificate_key.SUBJECT_PUBLIC_KEY_ALGORITHM_IDENTIFIER_MAPPINGS,
                certificate_key.SUBJECT_KEY_PARAMETER_ALGORITHM_IDENTIFIER_MAPPINGS
            ),
            certificate.create_policy_qualifier_decoder(
                certificate_extension.CERTIFICATE_POLICY_QUALIFIER_MAPPINGS
            ),
            certificate.create_other_name_decoder(
                general_name.OTHER_NAME_MAPPINGS
            ),
        ],
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
    else:
        cert = loader.load_certificate(args.file, args.file.name)

        results = doc_validator.validate(cert.root)

        print(args.format(results, args.severity))

        exit(report.get_findings_count(results, args.severity))


if __name__ == "__main__":
    main()
