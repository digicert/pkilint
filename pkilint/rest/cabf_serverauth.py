from fastapi import HTTPException

from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.pkix import certificate
from pkilint.rest import model


class CabfServerauthLinterGroup(model.LinterGroup):
    def __init__(self, linters):
        super().__init__(name='cabf-serverauth', linters=linters)

    def determine_linter(self, doc):
        cert_type = serverauth.determine_certificate_type(doc)

        # this doesn't fail, so we don't need to guard against not being able to determine the certificate type
        return next((l for l in self.linters if l.name.casefold() == cert_type.to_option_str.casefold()))


def create_linter_group_instance():
    return CabfServerauthLinterGroup(
        [
            model.Linter(
                validator=certificate.create_pkix_certificate_validator_container(
                    serverauth.create_decoding_validators(),
                    serverauth.create_validators(cert_type)
                ),
                finding_filters=serverauth.create_serverauth_finding_filters(cert_type),
                name=cert_type.to_option_str
            )
            for cert_type in serverauth_constants.CertificateType
        ]
    )
