import functools
import glob
import sys
from os import path

from pkilint.cabf import smime
from pkilint.cabf.smime import smime_constants
from pkilint.pkix import certificate
from tests import integration_certificate

this_module = sys.modules[__name__]


for validation_level in smime_constants.ValidationLevel:
    for generation in smime_constants.Generation:
        cur_dir = path.dirname(__file__)

        test_dir = path.join(cur_dir, 'smime_br', validation_level.name.lower(), generation.name.lower())

        files = glob.glob(path.join(test_dir, '*.tst'))

        for file in files:
            validator = certificate.create_pkix_certificate_validator_container(
                smime.create_decoding_validators(),
                smime.create_subscriber_validators(
                    validation_level, generation
                )
            )

            file_no_ext, _ = path.splitext(path.basename(file))

            func_name = f'test_{validation_level}-{generation}_{file_no_ext}'

            setattr(this_module, func_name, functools.partial(integration_certificate.run_test, file, validator))
