import csv
import io
import subprocess

from pkilint.cabf.serverauth import serverauth_constants
from pkilint.cabf.smime import smime_constants


def _test_program(name, args=None):
    if args is None:
        args = []

    output = subprocess.check_output([name, 'validations'] + args).decode()

    s = io.StringIO(output)

    c = csv.DictReader(s)
    row_count = len([r for r in c])

    assert row_count > 0


def test_lint_cabf_serverauth_cert():
    for cert_type in serverauth_constants.CertificateType:
        _test_program('lint_cabf_serverauth_cert', ['-t', cert_type.name.replace('_', '-')])


def test_lint_cabf_smime_cert():
    for g in smime_constants.Generation:
        for v in smime_constants.ValidationLevel:
            _test_program('lint_cabf_smime_cert', ['-t', f'{v}-{g}'])


def test_lint_crl():
    for p in ['BR', 'PKIX']:
        for t in ['CRL', 'ARL']:
            _test_program('lint_crl', ['-p', p, '-t', t])


def test_lint_ocsp_response():
    _test_program('lint_ocsp_response')


def test_lint_pkix_cert():
    _test_program('lint_pkix_cert')


def test_lint_pkix_signer_signee_cert_chain():
    _test_program('lint_pkix_signer_signee_cert_chain')
