from fastapi import HTTPException
from pyasn1.error import PyAsn1Error
from starlette import status

from pkilint.cabf import smime
from pkilint.cabf.smime import smime_constants
from pkilint.pkix import certificate
from pkilint.rest import model


class CabfSmimeLinterGroup(model.LinterGroup):
    def __init__(self, linters):
        super().__init__(name="cabf-smime", linters=linters)

    def determine_linter(self, doc):
        try:
            v_g = smime.determine_validation_level_and_generation(doc)
        except (ValueError, PyAsn1Error) as e:
            message = f"Parsing error occurred: {e}"

            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=model.create_unprocessable_entity_error_detail(message),
            )

        if v_g is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=model.create_unprocessable_entity_error_detail(
                    "Could not determine certificate type"
                ),
            )

        v, g = v_g

        name = f"{v}-{g}"

        return next((l for l in self.linters if l.name.casefold() == name.casefold()))


_V_G_PAIRS = []
for v in smime_constants.ValidationLevel:
    for g in smime_constants.Generation:
        _V_G_PAIRS.append((v, g))


def create_linter_group_instance():
    return CabfSmimeLinterGroup(
        [
            model.Linter(
                validator=certificate.create_pkix_certificate_validator_container(
                    smime.create_decoding_validators(),
                    smime.create_subscriber_validators(v, g),
                ),
                name=f"{v}-{g}",
            )
            for v, g in _V_G_PAIRS
        ]
    )
