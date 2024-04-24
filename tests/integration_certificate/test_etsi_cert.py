import functools
import glob
import sys
from os import path

from pkilint import etsi
from pkilint.etsi import etsi_constants
from pkilint.pkix import certificate
from tests import integration_certificate

this_module = sys.modules[__name__]


for certificate_type in etsi_constants.CertificateType:
    cur_dir = path.dirname(__file__)

    test_dir = path.join(cur_dir, 'etsi', certificate_type.name.lower())

    files = glob.glob(path.join(test_dir, '*.crttest'))

    for file in files:
        validator = certificate.create_pkix_certificate_validator_container(
            etsi.create_decoding_validators(certificate_type),
            etsi.create_validators(certificate_type)
        )
        filters = etsi.create_etsi_finding_filters(certificate_type)

        file_no_ext, _ = path.splitext(path.basename(file))

        func_name = f'test_{certificate_type}_{file_no_ext}'

        setattr(this_module, func_name, functools.partial(integration_certificate.run_test, file, validator, filters))
