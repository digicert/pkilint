import glob
import sys
from os import path

from pkilint import pkix
from pkilint.cabf import cabf_crl
from pkilint.pkix import name, extension, crl
from tests.integration_crl import register_test

cur_dir = path.dirname(__file__)
test_dir = path.join(cur_dir, "cabf", "arl")
this_module = sys.modules[__name__]

files = glob.glob(path.join(test_dir, "*.crltest"))


for file in files:
    validator = crl.create_pkix_crl_validator_container(
        [
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        [
            crl.create_issuer_validator_container([]),
            crl.create_validity_validator_container(
                [
                    cabf_crl.create_validity_period_validator(
                        crl.CertificateRevocationListType.ARL
                    )
                ]
            ),
            crl.create_extensions_validator_container([]),
        ]
        + [
            cabf_crl.CabfCrlReasonCodeAllowlistValidator(
                crl.CertificateRevocationListType.ARL
            )
        ],
    )

    file_no_ext, _ = path.splitext(path.basename(file))

    test_name = f"test_{file_no_ext}"

    register_test(this_module, file, test_name, validator)
