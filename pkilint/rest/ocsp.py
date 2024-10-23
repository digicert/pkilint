from pkilint.pkix import (
    ocsp,
    create_attribute_decoder,
    create_extension_decoder,
    extension,
    name,
)
from pkilint.rest import model


def create_ocsp_response_linter():
    return model.Linter(
        validator=ocsp.create_pkix_ocsp_response_validator_container(
            [
                ocsp.create_response_decoder(),
                create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
                create_extension_decoder(extension.EXTENSION_MAPPINGS),
            ],
            [],
        ),
        name="ocsp_linter",
    )
