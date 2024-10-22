import functools
from pathlib import Path

from pkilint import loader
from tests import integration_test_common

_FIXTURE_DIR = Path(__file__).parent.resolve()

_CERT_END_ASCII_ARMOR = "-----END CERTIFICATE-----"


def register_test(module, file, test_name, validator, filters=None):
    if hasattr(module, test_name):
        raise ValueError(f"Duplicate test name in {module}: {test_name}")

    setattr(
        module,
        test_name,
        functools.partial(
            integration_test_common.run_test,
            _CERT_END_ASCII_ARMOR,
            loader.load_pem_certificate,
            file,
            validator,
            filters,
        ),
    )
