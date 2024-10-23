from typing import List, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, model_validator
from typing_extensions import Annotated

from pkilint import finding_filter, report, validation, loader, document


class Version(BaseModel):
    version: Annotated[
        str, Field(description="The version of pkilint that this server is using")
    ]


_SEVERITY_DESCRIPTION = f'The severity of the finding ({", ".join(map(str, validation.ValidationFindingSeverity))})'


class Validation(BaseModel):
    severity: Annotated[str, Field(description=_SEVERITY_DESCRIPTION)]
    code: Annotated[
        str, Field(description="The code that identifies the type of validation")
    ]


class FindingDescription(BaseModel):
    severity: Annotated[str, Field(description=_SEVERITY_DESCRIPTION)]
    code: Annotated[
        str, Field(description="The code that identifies the type of finding")
    ]
    message: Annotated[
        Optional[str],
        Field(
            description="An optional message that provides further context for the "
            "finding"
        ),
    ]


class Result(BaseModel):
    validator: Annotated[
        str,
        Field(description="The class name of the validator which returned this result"),
    ]
    node_path: Annotated[
        str,
        Field(
            description="The path in the document (or set of documents) that was validated"
        ),
    ]
    finding_descriptions: Annotated[
        List[FindingDescription],
        Field(description="The list of findings returned by the validator"),
    ]


class LintResultList(BaseModel):
    results: Annotated[
        List[Result], Field(description="The list of results returned by the linter")
    ]


class Linter(BaseModel):
    name: Annotated[str, Field(description="The name of the linter")]

    def __init__(self, validator, finding_filters=None, **kwargs):
        super().__init__(**kwargs)

        self._validator = validator
        self._finding_filters = finding_filters

    @property
    def validations(self) -> List[Validation]:
        return [
            Validation(severity=str(v.severity), code=v.code)
            for v in report.get_included_validations(self._validator)
        ]

    def lint(self, doc) -> LintResultList:
        results = self._validator.validate(doc.root)

        if self._finding_filters is not None:
            results, _ = finding_filter.filter_results(self._finding_filters, results)

        report_gen = report.ReportGeneratorJson(
            results, validation.ValidationFindingSeverity.INFO
        )
        json_str = report_gen.generate()

        return LintResultList.model_validate_json(json_str)


class LintResultListWithLinter(LintResultList):
    linter: Annotated[
        Linter,
        Field(
            description="The linter that was used for linting the specified document"
        ),
    ]


class LinterGroup(BaseModel):
    name: Annotated[str, Field(description="The name of the linter group")]
    linters: Annotated[
        List[Linter], Field(description="The set of linters in this group")
    ]

    def determine_linter(self, doc):
        pass

    def get_linter_by_name(self, name: str) -> Linter:
        try:
            return next(
                (l for l in self.linters if l.name.casefold() == name.casefold())
            )
        except StopIteration:
            raise HTTPException(404, "Linter with the specified name does not exist")


class DocumentModel(BaseModel):
    pem: Annotated[Optional[str], Field(description="A PEM-encoded ASN.1 document")] = (
        None
    )
    b64: Annotated[
        Optional[str],
        Field(description="A Base64-encoded DER representation of an ASN.1 document"),
    ] = None

    def _validate(self) -> "DocumentModel":
        if self.pem and self.b64:
            raise ValueError(
                'Cannot set both "pem" and "b64" fields; exactly one must be specified'
            )
        elif not self.pem and not self.b64:
            raise ValueError('Must set exactly one of "pem" or "b64" fields')
        else:
            return self

    def parse_document(self) -> document.Document:
        pass


class CertificateModel(DocumentModel):
    _parsed_document = None

    @model_validator(mode="after")
    def validate(self) -> "CertificateModel":
        super()._validate()

        if self.pem is not None:
            try:
                self._parsed_document = loader.load_pem_certificate(
                    self.pem, "request", "request"
                )
            except ValueError as e:
                raise ValueError("Invalid PEM text specified") from e
        else:
            try:
                self._parsed_document = loader.load_b64_certificate(
                    self.b64, "request", "request"
                )
            except ValueError as e:
                raise ValueError("Invalid Base-64 encoding specified") from e

        return self

    @property
    def parsed_document(self):
        return self._parsed_document


class OcspResponseModel(DocumentModel):
    _parsed_document = None

    @model_validator(mode="after")
    def validate(self) -> "OcspResponseModel":
        super()._validate()

        if self.pem is not None:
            try:
                self._parsed_document = loader.load_pem_ocsp_response(
                    self.pem, "request", "request"
                )
            except ValueError as e:
                raise ValueError("Invalid PEM text specified") from e
        else:
            try:
                self._parsed_document = loader.load_b64_ocsp_response(
                    self.b64, "request", "request"
                )
            except ValueError as e:
                raise ValueError("Invalid Base-64 encoding specified") from e
        return self

    @property
    def parsed_document(self):
        return self._parsed_document


class CrlModel(DocumentModel):
    _parsed_document = None

    @model_validator(mode="after")
    def validate(self) -> "CrlModel":
        super()._validate()

        if self.pem is not None:
            try:
                self._parsed_document = loader.load_pem_crl(
                    self.pem, "request", "request"
                )
            except ValueError as e:
                raise ValueError("Invalid PEM text specified") from e
        else:
            try:
                self._parsed_document = loader.load_b64_crl(
                    self.b64, "request", "request"
                )
            except ValueError as e:
                raise ValueError("Invalid Base-64 encoding specified") from e
        return self

    @property
    def parsed_document(self):
        return self._parsed_document


def create_unprocessable_entity_error_detail(
    message: str, error_type: str = "value_error"
):
    return [
        {
            "loc": ["body"],
            "type": error_type,
            "msg": message,
        }
    ]
