from pyasn1_alt_modules import rfc6960

from pkilint import document, validation
from pkilint.pkix import time
from pkilint.pkix.ocsp import ocsp_response, ocsp_basic_response, ocsp_validity


class RFC6960OCSPResponse(document.Document):
    def __init__(self, substrate_source, substrate, name=None, parent=None):
        super().__init__(
            rfc6960.OCSPResponse(), substrate_source, substrate, name, parent
        )


def create_response_decoder():
    decoder = ocsp_response.OCSPResponseDecoder(type_mappings=rfc6960.ocspResponseMap)

    return ocsp_response.OCSPResponseDecodingValidator(decode_func=decoder)


def create_pkix_ocsp_response_validator_container(decoding_validators, validators):
    decoding_validator_containers = [
        validation.ValidatorContainer(
            validators=decoding_validators, path="oCSPResponse"
        )
    ]

    validators += [
        ocsp_response.OCSPResponseStatusValidator(),
        ocsp_response.OCSPResponseIsBasicValidator(),
        ocsp_basic_response.OCSPBasicResponseCertsNotPresentValidator(),
        ocsp_basic_response.ResponderKeyHashIsSHA1HashValidator(),
        ocsp_validity.OCSPSaneValidityPeriodValidator(),
        time.UtcTimeCorrectSyntaxValidator(),
        time.GeneralizedTimeCorrectSyntaxValidator(),
    ]

    return validation.ValidatorContainer(
        validators=decoding_validator_containers + validators
    )
