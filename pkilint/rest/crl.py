from pkilint import pkix

from pkilint.pkix import crl, extension, name
from pkilint.rest import model


def create_crl_linter(
    validity_additional_validators=None, doc_additional_validators=None
):
    if doc_additional_validators is None:
        doc_additional_validators = []
    if validity_additional_validators is None:
        validity_additional_validators = []

    return model.Linter(
        validator=crl.create_pkix_crl_validator_container(
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
        ),
        name="crl_linter",
    )
