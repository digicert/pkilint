#!/usr/bin/env python

import argparse
import re
import sys

from pyasn1.type.univ import ObjectIdentifier

from pkilint import cli_util, loader, report
from pkilint.cabf import smime
from pkilint.cabf.smime import smime_constants
from pkilint.pkix import certificate

_CERTIFICATE_TYPES = {}
for g in smime_constants.Generation:
    for v in smime_constants.ValidationLevel:
        _CERTIFICATE_TYPES[f"{v}-{g}"] = (
            v,
            g,
        )

_CONFIG_FILE_REGEX = re.compile(
    r"(?P<oid>\d+(\.\d+)*)\D.*(?P<type>(" + "|".join(_CERTIFICATE_TYPES.keys()) + "))"
)


class SmimeCertificateTypeAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        validation_level_str, generation_str = values.split("-", maxsplit=1)

        validation_level = smime_constants.ValidationLevel[validation_level_str]
        generation = smime_constants.Generation[generation_str]

        setattr(
            namespace,
            self.dest,
            (
                validation_level,
                generation,
            ),
        )


class MappingFileAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        mappings = {}

        for line_num, line in enumerate(values.readlines()):
            line = line.strip().upper()

            m = _CONFIG_FILE_REGEX.search(line)

            if m is None:
                raise argparse.ArgumentError(
                    self, f'Syntax error on mapping file line {line_num + 1}: "{line}"'
                )

            oid = ObjectIdentifier(m.group("oid"))
            validation_level, generation = _CERTIFICATE_TYPES[m.group("type")]

            mappings[oid] = (
                validation_level,
                generation,
            )

        setattr(namespace, self.dest, mappings)


def main(cli_args=None) -> int:
    parser = argparse.ArgumentParser(
        description=f"CA/Browser Forum S/MIME Baseline Requirements v{smime_constants.BR_VERSION} Certificate Linter"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validations_parser = subparsers.add_parser(
        "validations", help="Output the set of validations which this linter performs"
    )
    validations_parser.add_argument(
        "-t",
        "--type",
        required=True,
        type=str.upper,
        action=SmimeCertificateTypeAction,
        help="The type (validation level and generation) of S/MIME certificate",
        choices=list(_CERTIFICATE_TYPES.keys()),
    )

    lint_parser = subparsers.add_parser("lint", help="Lint the specified certificate")

    detect_options_group = lint_parser.add_mutually_exclusive_group(required=True)

    detect_options_group.add_argument(
        "-d",
        "--detect",
        action="store_true",
        help="Detect the type of S/MIME certificate from reserved CA/B Forum policy "
        "OID. If the type cannot be detected, then refuse to lint the certificate.",
    )
    detect_options_group.add_argument(
        "-g",
        "--guess",
        action="store_true",
        help="Detect the type of S/MIME certificate from reserved CA/B Forum policy "
        "OID. If the type cannot be detected, then use heuristics to determine "
        "the type of S/MIME certificate.",
    )
    detect_options_group.add_argument(
        "-t",
        "--type",
        type=str.upper,
        action=SmimeCertificateTypeAction,
        help="The type (validation level and generation) of S/MIME certificate",
        choices=list(_CERTIFICATE_TYPES.keys()),
    )

    lint_parser.add_argument(
        "-m",
        "--mapping",
        type=argparse.FileType("r"),
        action=MappingFileAction,
        help="Mapping file which contains OID to validation level and "
        "generation mappings. Each line of the mapping file starts with a policy OID "
        "followed by a non-numeric character and the certificate type to which the OID "
        "maps (see -t/--type option for possible values)",
        default=None,
    )
    lint_parser.add_argument(
        "-o",
        "--output",
        action="store_true",
        help="Output the type of S/MIME certificate to standard error. This option may be "
        "useful when using the --detect, --guess, or --mapping options.",
    )

    cli_util.add_certificate_validity_period_start_arg(lint_parser)

    cli_util.add_standard_args(lint_parser)

    lint_parser.add_argument(
        "file", type=argparse.FileType("rb"), help="The certificate to lint"
    )

    args = parser.parse_args(cli_args)

    if args.command == "validations":
        validation_level, generation = args.type

        doc_validator = certificate.create_pkix_certificate_validator_container(
            smime.create_decoding_validators(),
            smime.create_subscriber_validators(validation_level, generation),
        )

        print(report.report_included_validations(doc_validator))

        return 0
    else:
        try:
            cert = loader.RFC5280CertificateDocumentLoader().get_file_loader_func(
                args.document_format
            )(args.file, args.file.name)
        except ValueError as e:
            print(f"Failed to load certificate: {e}", file=sys.stderr)
            return 1

        if args.detect:
            v_g = smime.determine_validation_level_and_generation(cert, args.mapping)

            if v_g is None:
                print(
                    "Could not determine validation level and generation",
                    file=sys.stderr,
                )

                return 1
            else:
                validation_level, generation = v_g
        elif args.guess:
            validation_level, generation = smime.guess_validation_level_and_generation(
                cert, args.mapping
            )
        else:
            validation_level, generation = args.type

        if args.output:
            print(f"{validation_level}-{generation}", file=sys.stderr)

        doc_validator = certificate.create_pkix_certificate_validator_container(
            smime.create_decoding_validators(),
            smime.create_subscriber_validators(
                validation_level, generation, args.validity_period_start
            ),
        )

        results = doc_validator.validate(cert.root)

        print(args.format(results, args.severity))

        return cli_util.clamp_exit_code(
            report.get_findings_count(results, args.severity)
        )


if __name__ == "__main__":
    sys.exit(main())
