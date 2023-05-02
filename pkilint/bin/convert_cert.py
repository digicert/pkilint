#!/usr/bin/env python

import argparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


def _convert_cert(f):
    content = f.read()

    if content.startswith(b'\x30'):
        cert = x509.load_der_x509_certificate(content)
    else:
        cert = x509.load_pem_x509_certificate(content)

    return cert.public_bytes(Encoding.PEM).decode('us-ascii')


parser = argparse.ArgumentParser()
parser.add_argument('file', type=argparse.FileType('rb'))

args = parser.parse_args()

pem = _convert_cert(args.file)

print(f'pem = """{pem}"""')
