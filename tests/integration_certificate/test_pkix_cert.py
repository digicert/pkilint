import functools
import glob
import sys
from os import path

from pkilint import pkix
from pkilint.pkix import certificate, name, extension, algorithm, general_name
from pkilint.pkix.certificate import certificate_key, certificate_extension
from tests import integration_certificate

cur_dir = path.dirname(__file__)
test_dir = path.join(cur_dir, 'pkix')
this_module = sys.modules[__name__]

files = glob.glob(path.join(test_dir, '*.crttest'))

for file in files:
    validator = certificate.create_pkix_certificate_validator_container(
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

    file_no_ext, _ = path.splitext(path.basename(file))

    func_name = f'test_{file_no_ext}'

    setattr(this_module, func_name, functools.partial(integration_certificate.run_test, file, validator))
