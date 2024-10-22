import datetime

from pyasn1_alt_modules import rfc5280

from pkilint import validation, document


class LegacyGenerationSunsetValidator(validation.Validator):
    """
    SMBR, section 7.1.6.1:
    Effective July 15, 2025 S/MIME Subscriber Certificates SHALL NOT be issued using the Legacy Generation profiles
    2.23.140.1.5.1.1, 2.23.140.1.5.2.1, 2.23.140.1.5.3.1, or 2.23.140.1.5.4.1.
    """

    VALIDATION_LEGACY_GENERATION_CERTIFICATE_ISSUED_AFTER_PROHIBITION = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "cabf.smime.legacy_generation_certificate_issued_after_prohibition",
        )
    )

    _LEGACY_GENERATION_SUNSET_DATE = datetime.datetime(
        2025, 7, 15, 0, 0, 0, tzinfo=datetime.timezone.utc
    )

    def __init__(
        self, validity_period_start_retriever: document.ValidityPeriodStartRetriever
    ):
        super().__init__(
            validations=[
                self.VALIDATION_LEGACY_GENERATION_CERTIFICATE_ISSUED_AFTER_PROHIBITION
            ],
            pdu_class=rfc5280.Validity,
        )

        self._validity_period_start_retriever = validity_period_start_retriever

    def validate(self, node):
        if (
            self._validity_period_start_retriever(node.document)
            >= self._LEGACY_GENERATION_SUNSET_DATE
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_LEGACY_GENERATION_CERTIFICATE_ISSUED_AFTER_PROHIBITION
            )
