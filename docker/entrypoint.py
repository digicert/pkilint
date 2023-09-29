#!/usr/bin/env python3

import functools
import sys
import os

from pkilint.bin import (
    lint_cabf_serverauth_cert,
    lint_cabf_smime_cert,
    lint_crl,
    lint_ocsp_response,
    lint_pkix_cert,
    lint_pkix_signer_signee_cert_chain,
)

_ENTRYPOINTS = {
    'lint_cabf_serverauth_cert': lint_cabf_serverauth_cert.main,
    'lint_cabf_smime_cert': lint_cabf_smime_cert.main,
    'lint_crl': lint_crl.main,
    'lint_ocsp_response': lint_ocsp_response.main,
    'lint_pkix_cert': lint_pkix_cert.main,
    'lint_pkix_signer_signee_cert_chain': lint_pkix_signer_signee_cert_chain.main,
}


def _run(cmd, args):
    os.execvp(cmd, [cmd] + args)


def main():
    if len(sys.argv) < 2:
        print('Executable not specified', file=sys.stderr)

        return 1

    cmd = sys.argv[1]
    args = sys.argv[2:]

    entrypoint_func = _ENTRYPOINTS.get(cmd, functools.partial(_run, cmd))

    return entrypoint_func(args)


if __name__ == '__main__':
    sys.exit(main())
