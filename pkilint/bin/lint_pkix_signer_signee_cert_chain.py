#!/usr/bin/env python

import argparse
import sys

from pyasn1_alt_modules import rfc5280

from pkilint import loader, document, cli_util, validation, pkix, report
from pkilint.pkix import certificate, name, extension, algorithm, key
from pkilint.pkix.certificate import certificate_extension, certificate_key


def create_decoder_validation_container():
    decoders = [
        pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
        pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        pkix.create_signature_algorithm_identifier_decoder(
            algorithm.SIGNATURE_ALGORITHM_IDENTIFIER_MAPPINGS,
            path="certificate.tbsCertificate.signature",
        ),
        certificate.create_spki_decoder(
            key.SUBJECT_PUBLIC_KEY_ALGORITHM_IDENTIFIER_MAPPINGS,
            key.SUBJECT_KEY_PARAMETER_ALGORITHM_IDENTIFIER_MAPPINGS,
        ),
    ]

    return validation.ValidatorContainer(validators=decoders, path="certificate")


def create_issuer_validation_container():
    validators = [
        name.IssuerSubjectNameBinaryEqualValidator(
            path="certificate.tbsCertificate.subject",
            subject_document_issuer_dn_path="subject:certificate.tbsCertificate.issuer",
        ),
        extension.IssuerSubjectKeyIdentifierBinaryEqualValidator(
            subject_auth_key_id_retriever=(
                lambda n: document.get_document_by_name(
                    n, "subject"
                ).get_extension_by_oid(rfc5280.id_ce_authorityKeyIdentifier)
            )
        ),
        certificate_extension.IssuerSubjectPolicyChainValidator(),
    ]

    return validation.ValidatorContainer(validators=validators)


def create_subject_validation_container():
    validators = [
        certificate_key.SubjectSignatureVerificationValidator(
            tbs_node_retriever=lambda n: n.navigate("^.tbsCertificate"),
            path="certificate.signature",
        )
    ]

    return validation.ValidatorContainer(validators=validators)


def main(cli_args=None) -> int:
    parser = argparse.ArgumentParser("RFC 5280 Issuer/Subject Certificate Chain Linter")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "validations", help="Output the set of validations which this linter performs"
    )

    lint_parser = subparsers.add_parser(
        "lint", help="Lint the specified issuer and subject certificates"
    )
    cli_util.add_standard_args(lint_parser)

    lint_parser.add_argument(
        dest="issuer",
        type=argparse.FileType("rb"),
        help="The issuer certificate to lint",
    )
    lint_parser.add_argument(
        dest="subject",
        type=argparse.FileType("rb"),
        help="The subject certificate to lint",
    )

    args = parser.parse_args(cli_args)

    decoding_validation_container = create_decoder_validation_container()
    issuer_validation_container = create_issuer_validation_container()
    subject_validation_container = create_subject_validation_container()

    if args.command == "validations":
        print(
            report.report_included_validations(
                decoding_validation_container,
                issuer_validation_container,
                subject_validation_container,
            )
        )

        return 0
    else:
        doc_collection = {}

        loader_func = loader.RFC5280CertificateDocumentLoader().get_file_loader_func(
            args.document_format
        )

        try:
            issuer = loader_func(
                args.issuer, args.issuer.name, "issuer", doc_collection
            )
        except ValueError as e:
            print(f"Failed to load issuer certificate: {e}", file=sys.stderr)
            return 1

        doc_collection["issuer"] = issuer

        try:
            subject = loader_func(
                args.subject, args.subject.name, "subject", doc_collection
            )
        except ValueError as e:
            print(f"Failed to load subject certificate: {e}", file=sys.stderr)
            return 1

        doc_collection["subject"] = subject

        results = decoding_validation_container.validate(issuer.root)
        results += decoding_validation_container.validate(subject.root)
        results += issuer_validation_container.validate(issuer.root)
        results += subject_validation_container.validate(subject.root)

        print(args.format(results, args.severity))

        return cli_util.clamp_exit_code(
            report.get_findings_count(results, args.severity)
        )


if __name__ == "__main__":
    sys.exit(main())
