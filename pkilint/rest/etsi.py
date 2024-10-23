from fastapi import HTTPException
from pyasn1.error import PyAsn1Error
from starlette import status

from pkilint import etsi
from pkilint.pkix import certificate
from pkilint.rest import model


class EtsiLinterGroup(model.LinterGroup):
    def __init__(self, linters):
        super().__init__(name="etsi", linters=linters)

    def determine_linter(self, doc):
        try:
            cert_type = etsi.determine_certificate_type(doc)
        except (ValueError, PyAsn1Error) as e:
            message = f"Parsing error occurred: {e}"

            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=model.create_unprocessable_entity_error_detail(message),
            )

        # this doesn't fail, so we don't need to guard against not being able to determine the certificate type
        return next(
            (
                l
                for l in self.linters
                if l.name.casefold() == cert_type.to_option_str.casefold()
            )
        )


def create_linter_group_instance():
    return EtsiLinterGroup(
        [
            model.Linter(
                validator=certificate.create_pkix_certificate_validator_container(
                    etsi.create_decoding_validators(cert_type),
                    etsi.create_validators(cert_type),
                ),
                finding_filters=etsi.create_etsi_finding_filters(cert_type),
                name=cert_type.to_option_str,
            )
            for cert_type in etsi.CertificateType
        ]
    )
