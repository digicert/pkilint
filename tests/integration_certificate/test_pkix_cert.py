import functools
import glob
import sys
from os import path

from pkilint.pkix import certificate, name, extension
from tests import integration_certificate

cur_dir = path.dirname(__file__)
test_dir = path.join(cur_dir, 'pkix')
this_module = sys.modules[__name__]

files = glob.glob(path.join(test_dir, '*.crttest'))

for file in files:
    validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
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
