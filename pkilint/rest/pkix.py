from pkilint.pkix import certificate, name, extension
from pkilint.rest import model


class PkixCertificateLinterGroup(model.LinterGroup):
    def __init__(self, linters):
        super().__init__(name="pkix", linters=linters)

    def determine_linter(self, doc):
        return self.linters[0]


def create_linter_group_instance():
    return PkixCertificateLinterGroup(
        [
            model.Linter(
                validator=certificate.create_pkix_certificate_validator_container(
                    certificate.create_decoding_validators(
                        name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS
                    ),
                    [
                        certificate.create_issuer_validator_container([]),
                        certificate.create_validity_validator_container(),
                        certificate.create_subject_validator_container([]),
                        certificate.create_extensions_validator_container([]),
                        certificate.create_spki_validator_container([]),
                    ],
                ),
                name="certificate",
            )
        ]
    )
