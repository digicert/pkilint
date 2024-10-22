import base64
import enum
import re

from pkilint.pkix.certificate import RFC5280Certificate
from pkilint.pkix.crl import RFC5280CertificateList
from pkilint.pkix.ocsp import RFC6960OCSPResponse


class DocumentFormat(enum.Enum):
    DETECT = enum.auto()
    BASE64 = enum.auto()
    DER = enum.auto()
    PEM = enum.auto()


class DocumentLoader:
    def __init__(self, document_cls, document_pem_label: str):
        self._document_cls = document_cls
        self._document_pem_label = document_pem_label.upper()

        self._pem_re = self._create_pem_re()

    def _create_pem_re(self) -> re.Pattern:
        ascii_armor_start = f"-----BEGIN {self._document_pem_label}-----"
        ascii_armor_end = f"-----END {self._document_pem_label}-----"

        return re.compile(
            f"^\\s*{ascii_armor_start}(?P<pem>.+){ascii_armor_end}\\s*$", re.DOTALL
        )

    def load_der_document(
        self,
        substrate: bytes,
        document_name: str = None,
        substrate_source: str = None,
        parent=None,
    ):
        if not substrate.startswith(b"\x30"):
            raise ValueError("Substrate is not DER-encoded")

        doc = self._document_cls(substrate_source, substrate, document_name, parent)
        doc.decode()

        return doc

    def load_der_file(
        self, f, document_name: str = None, substrate_source: str = None, parent=None
    ):
        return self.load_der_document(f.read(), document_name, substrate_source, parent)

    def load_b64_document(
        self,
        substrate: str,
        document_name: str = None,
        substrate_source: str = None,
        parent=None,
    ):
        der = base64.b64decode(substrate)

        return self.load_der_document(der, document_name, substrate_source, parent)

    def load_b64_file(
        self, f, document_name: str = None, substrate_source: str = None, parent=None
    ):
        data = f.read()

        if isinstance(data, bytes):
            data = data.decode("us-ascii")

        return self.load_b64_document(data, document_name, substrate_source, parent)

    def load_pem_document(
        self,
        substrate: str,
        document_name: str = None,
        substrate_source: str = None,
        parent=None,
    ):
        m = self._pem_re.match(substrate)

        if m is None:
            raise ValueError("Invalid PEM text")

        b64_text = m.group("pem")

        return self.load_b64_document(b64_text, document_name, substrate_source, parent)

    def load_pem_file(
        self, f, document_name: str = None, substrate_source: str = None, parent=None
    ):
        data = f.read()

        if isinstance(data, bytes):
            data = data.decode("us-ascii")

        return self.load_pem_document(data, document_name, substrate_source, parent)

    @classmethod
    def _is_ascii_armor_start_present(cls, substrate: str):
        first_significant_char = next((c for c in substrate if not c.isspace()), None)

        return first_significant_char == "-"

    def load_document(
        self,
        substrate,
        document_name: str = None,
        substrate_source: str = None,
        parent=None,
    ):
        if isinstance(substrate, bytes):
            try:
                return self.load_der_document(
                    substrate, document_name, substrate_source, parent
                )
            except ValueError:
                substrate = substrate.decode("us-ascii")

        if self._is_ascii_armor_start_present(substrate):
            return self.load_pem_document(
                substrate, document_name, substrate_source, parent
            )
        else:
            return self.load_b64_document(
                substrate, document_name, substrate_source, parent
            )

    def load_file(
        self, f, document_name: str = None, substrate_source: str = None, parent=None
    ):
        substrate = f.read()

        return self.load_document(substrate, document_name, substrate_source, parent)

    def load_document_or_file(
        self,
        substrate,
        document_name: str = None,
        substrate_source: str = None,
        parent=None,
    ):
        try:
            return self.load_file(substrate, document_name, substrate_source, parent)
        except AttributeError:
            return self.load_document(
                substrate, document_name, substrate_source, parent
            )

    def get_file_loader_func(self, document_format: DocumentFormat):
        if document_format == DocumentFormat.BASE64:
            return self.load_b64_file
        elif document_format == DocumentFormat.DER:
            return self.load_der_file
        elif document_format == DocumentFormat.PEM:
            return self.load_pem_file
        elif document_format == DocumentFormat.DETECT:
            return self.load_file
        else:
            raise ValueError(f"Unknown document format: {document_format}")


class RFC5280CertificateDocumentLoader(DocumentLoader):
    def __init__(self):
        super().__init__(RFC5280Certificate, "CERTIFICATE")


class RFC5280CertificateListDocumentLoader(DocumentLoader):
    def __init__(self):
        super().__init__(RFC5280CertificateList, "X509 CRL")


class RFC6960OCSPResponseDocumentLoader(DocumentLoader):
    def __init__(self):
        super().__init__(RFC6960OCSPResponse, "OCSP RESPONSE")


# RFC 5280 Certificate
_RFC5280_CERTIFICATE_LOADER_INSTANCE = RFC5280CertificateDocumentLoader()
load_der_certificate = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_der_document
load_pem_certificate = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_pem_document
load_b64_certificate = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_b64_document
load_certificate = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_document_or_file
load_der_certificate_file = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_der_file
load_pem_certificate_file = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_pem_file
load_b64_certificate_file = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_b64_file
load_certificate_file = _RFC5280_CERTIFICATE_LOADER_INSTANCE.load_file


# RFC 5280 CRL
_RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE = RFC5280CertificateListDocumentLoader()
load_der_crl = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_der_document
load_pem_crl = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_pem_document
load_b64_crl = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_b64_document
load_crl = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_document_or_file
load_der_crl_file = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_der_file
load_pem_crl_file = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_pem_file
load_b64_crl_file = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_b64_file
load_crl_file = _RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE.load_file


# RFC 6960 OCSP Response
_RFC6960_OCSP_RESPONSE_LOADER_INSTANCE = RFC6960OCSPResponseDocumentLoader()
load_der_ocsp_response = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_der_document
load_pem_ocsp_response = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_pem_document
load_b64_ocsp_response = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_b64_document
load_ocsp_response = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_document_or_file
load_der_ocsp_response_file = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_der_file
load_pem_ocsp_response_file = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_pem_file
load_b64_ocsp_response_file = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_b64_file
load_ocsp_response_file = _RFC6960_OCSP_RESPONSE_LOADER_INSTANCE.load_file
