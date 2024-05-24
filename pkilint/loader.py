import base64
import functools
import re
import sys

from pkilint.pkix.certificate import RFC5280Certificate
from pkilint.pkix.crl import RFC5280CertificateList
from pkilint.pkix.ocsp import RFC6960OCSPResponse


def _create_ascii_armor(document_kind: str):
    document_kind = document_kind.upper()

    return f'-----BEGIN {document_kind}-----', f'-----END {document_kind}-----'


def _create_pem_re(ascii_armor=('', '')) -> re.Pattern:
    return re.compile(f'^\\s*{ascii_armor[0]}(?P<pem>.+){ascii_armor[1]}\\s*$', re.DOTALL)


_CERTIFICATE_PEM_REGEX = _create_pem_re(_create_ascii_armor('CERTIFICATE'))
_CRL_PEM_REGEX = _create_pem_re(_create_ascii_armor('X509 CRL'))
_OCSPRESPONSE_PEM_REGEX = _create_pem_re(_create_ascii_armor('OCSP RESPONSE'))
_GENERIC_BASE64_REGEX = _create_pem_re()

_DOCUMENT_CLS_TO_PEM_REGEX = {
    RFC5280Certificate: _CERTIFICATE_PEM_REGEX,
    RFC5280CertificateList: _CRL_PEM_REGEX,
    RFC6960OCSPResponse: _OCSPRESPONSE_PEM_REGEX,
}


def _convert_pem_str_to_der(regex: re.Pattern, pem_text: str) -> bytes:
    m = regex.match(pem_text)

    if m is None:
        raise ValueError('Invalid PEM text')

    b64_text = m.group('pem')

    return base64.b64decode(b64_text)


def _convert_pem_bytes_to_der(regex: re.Pattern, pem_text: bytes) -> bytes:
    return _convert_pem_str_to_der(regex, pem_text.decode())


def _load_der_document(document_cls, substrate: bytes, document_name: str = None,
                       substrate_source: str = None, parent=None):
    if not substrate.startswith(b'\x30'):
        raise ValueError('Substrate is not DER-encoded')

    doc = document_cls(substrate_source, substrate, document_name, parent)
    doc.decode()

    return doc


def _load_pem_document(document_cls, substrate: str, document_name: str = None,
                       substrate_source: str = None, parent=None):
    regex = _DOCUMENT_CLS_TO_PEM_REGEX.get(document_cls, _GENERIC_BASE64_REGEX)

    der = _convert_pem_str_to_der(regex, substrate)

    return _load_der_document(document_cls, der, document_name, substrate_source, parent)


def _load_pem_file(document_cls, f, document_name: str = None, substrate_source: str = None, parent=None):
    data = f.read()

    regex = _DOCUMENT_CLS_TO_PEM_REGEX.get(document_cls, _GENERIC_BASE64_REGEX)

    if isinstance(data, bytes):
        der = _convert_pem_bytes_to_der(regex, data)
    else:
        der = _convert_pem_str_to_der(regex, data)

    return _load_der_document(document_cls, der, document_name, substrate_source, parent)


def _load_der_file(document_cls, f, document_name: str = None, substrate_source: str = None, parent=None):
    data = f.read()

    return _load_der_document(document_cls, data, document_name, substrate_source, parent)


_this_module = sys.modules[__name__]

for doc_name, doc_cls in [
    ('certificate', RFC5280Certificate),
    ('crl', RFC5280CertificateList),
    ('ocsp_response', RFC6960OCSPResponse),
]:
    for func in [
        _load_der_file,
        _load_pem_file,
        _load_der_document,
        _load_pem_document,
    ]:
        if func == _load_der_file:
            func_name = f'load_der_{doc_name}_file'
        elif func == _load_pem_file:
            func_name = f'load_pem_{doc_name}_file'
        elif func == _load_der_document:
            func_name = f'load_der_{doc_name}'
        elif func == _load_pem_document:
            func_name = f'load_pem_{doc_name}'
        else:
            raise ValueError(f'Unknown function: {func}')

        setattr(
            _this_module,
            func_name,
            functools.partial(func, doc_cls)
        )


def _load_document(der_loader, pem_loader, substrate, name=None, substrate_source=None, parent=None):
    if isinstance(substrate, str):
        return pem_loader(substrate, name, substrate_source, parent)
    elif isinstance(substrate, bytes):
        try:
            return der_loader(substrate, name, substrate_source, parent)
        except ValueError:
            pem_str = substrate.decode()

            return pem_loader(pem_str, name, substrate_source, parent)
    else:
        data = substrate.read()

        return _load_document(der_loader, pem_loader, data, name, substrate_source, parent)


def load_certificate(io, substrate_source, name=None, parent=None):
    return _load_document(getattr(_this_module, 'load_der_certificate'), getattr(_this_module, 'load_pem_certificate'),
                          io, name, substrate_source, parent)


def load_crl(io, substrate_source, name=None, parent=None):
    return _load_document(getattr(_this_module, 'load_der_crl'), getattr(_this_module, 'load_pem_crl'),
                          io, name, substrate_source, parent)


def load_ocsp_response(io, substrate_source, name=None, parent=None):
    return _load_document(getattr(_this_module, 'load_der_ocsp_response'),
                          getattr(_this_module, 'load_pem_ocsp_response'), io, name, substrate_source, parent)
