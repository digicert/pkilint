from importlib.metadata import version
from typing import List

from fastapi import FastAPI, HTTPException

from pkilint.rest import cabf_serverauth, cabf_smime, pkix, etsi, ocsp, crl
from pkilint.rest import model

_PKILINT_VERSION = version("pkilint")
_API_VERSION = "v1.6"

app = FastAPI(
    title="pkilint API", version=_API_VERSION, description="HTTP interface for pkilint"
)

_CERTIFICATE_LINTER_GROUPS = [
    m.create_linter_group_instance()
    for m in (
        pkix,
        cabf_smime,
        cabf_serverauth,
        etsi,
    )
]

_OCSP_PKIX_LINTER = ocsp.create_ocsp_response_linter()
_CRL_PKIX_LINTER = crl.create_crl_linter()


@app.get("/version")
def version() -> model.Version:
    """Retrieves the version of pkilint that this server is using"""
    return model.Version(version=_PKILINT_VERSION)


@app.get("/certificate")
def certificate_linter_groups() -> List[model.LinterGroup]:
    """Retrieves the groups of linters that are available for linting certificates"""
    return _CERTIFICATE_LINTER_GROUPS


def _get_linter_group_by_name(linter_group_name: str):
    try:
        return next(
            (
                l
                for l in _CERTIFICATE_LINTER_GROUPS
                if l.name.casefold() == linter_group_name.casefold()
            )
        )
    except StopIteration:
        raise HTTPException(404, "Linter group with the specified name does not exist")


@app.get("/certificate/{linter_group_name}")
def certificate_linter_group(linter_group_name: str) -> model.LinterGroup:
    """Retrieves the list of linters that are available in the specified linter group"""
    return _get_linter_group_by_name(linter_group_name)


@app.post("/certificate/{linter_group_name}")
def certificate_determine_and_lint(
    linter_group_name: str, doc: model.CertificateModel
) -> model.LintResultListWithLinter:
    """Determines the linter that is most appropriate to lint the specified certificate and then returns the results
    reported by the linter for the certificate"""

    linter_group_instance = _get_linter_group_by_name(linter_group_name)

    parsed_doc = doc.parsed_document

    linter = linter_group_instance.determine_linter(parsed_doc)

    result_list = linter.lint(parsed_doc)

    return model.LintResultListWithLinter(results=result_list.results, linter=linter)


@app.post("/certificate/{linter_group_name}/determine-linter")
def certificate_determine_type(
    linter_group_name: str, doc: model.CertificateModel
) -> model.Linter:
    """Determines the linter that is most appropriate to lint the specified certificate"""
    linter_group_instance = _get_linter_group_by_name(linter_group_name)

    parsed_doc = doc.parsed_document

    return linter_group_instance.determine_linter(parsed_doc)


@app.get("/certificate/{linter_group_name}/{linter_name}")
def linter_validations(
    linter_group_name: str, linter_name: str
) -> List[model.Validation]:
    """Returns the set of validations performed by the specified linter"""
    linter_group_instance = _get_linter_group_by_name(linter_group_name)

    linter_instance = linter_group_instance.get_linter_by_name(linter_name)

    return linter_instance.validations


@app.post("/certificate/{linter_group_name}/{linter_name}")
def certificate_lint(
    linter_group_name: str, linter_name: str, doc: model.CertificateModel
) -> model.LintResultList:
    """Lints the specified certificate with the specified linter"""
    linter_group_instance = _get_linter_group_by_name(linter_group_name)

    linter_instance = linter_group_instance.get_linter_by_name(linter_name)

    parsed_doc = doc.parsed_document

    return linter_instance.lint(parsed_doc)


@app.get("/ocsp/pkix")
def ocsp_linter_validations() -> List[model.Validation]:
    """Returns the set of validations performed by the OCSP response linter"""

    return _OCSP_PKIX_LINTER.validations


@app.post("/ocsp/pkix")
def ocsp_response_lint(doc: model.OcspResponseModel) -> model.LintResultList:
    """Lints the specified OCSP response"""

    parsed_doc = doc.parsed_document

    return _OCSP_PKIX_LINTER.lint(parsed_doc)


@app.get("/crl/pkix/crl")
def crl_linter_validations() -> List[model.Validation]:
    """Returns the set of validations performed by the CRL linter"""

    return _CRL_PKIX_LINTER.validations


@app.post("/crl/pkix/crl")
def crl_lint(doc: model.CrlModel) -> model.LintResultList:
    """Lints the specified CRL"""

    parsed_doc = doc.parsed_document

    return _CRL_PKIX_LINTER.lint(parsed_doc)
