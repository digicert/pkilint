import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pkilint import loader, validation
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_subscriber
from pkilint.pkix import certificate

_JURISDICTION_COUNTRY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3")
_JURISDICTION_STATE_OR_PROVINCE_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2")
_JURISDICTION_LOCALITY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1")

_VALIDATOR_CLASS = (
    serverauth_subscriber.EvSubscriberOrganizationIdentifierJurisdictionConsistencyValidator
)

_COUNTRY_MISMATCH = (
    _VALIDATOR_CLASS.VALIDATION_ORG_ID_JURISDICTION_COUNTRY_MISMATCH.code
)
_SUBDIVISION_ABSENT_STP_PRESENT = (
    _VALIDATOR_CLASS.VALIDATION_ORG_ID_SUBDIVISION_ABSENT_JURISDICTION_STP_PRESENT.code
)
_SUBDIVISION_ABSENT_LOCALITY_PRESENT = (
    _VALIDATOR_CLASS.VALIDATION_ORG_ID_SUBDIVISION_ABSENT_JURISDICTION_LOCALITY_PRESENT.code
)
_SUBDIVISION_PRESENT_STP_ABSENT = (
    _VALIDATOR_CLASS.VALIDATION_ORG_ID_SUBDIVISION_PRESENT_JURISDICTION_STP_ABSENT.code
)


def _create_certificate(
    organization_identifier,
    jurisdiction_country,
    jurisdiction_state_or_province=None,
    jurisdiction_locality=None,
):
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Guadeloupe"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Les Abymes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Le Banque"),
        x509.NameAttribute(NameOID.BUSINESS_CATEGORY, "Private Organization"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "1"),
        x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, organization_identifier),
        x509.NameAttribute(_JURISDICTION_COUNTRY_OID, jurisdiction_country),
    ]

    if jurisdiction_state_or_province is not None:
        attributes.append(
            x509.NameAttribute(
                _JURISDICTION_STATE_OR_PROVINCE_OID, jurisdiction_state_or_province
            )
        )

    if jurisdiction_locality is not None:
        attributes.append(
            x509.NameAttribute(_JURISDICTION_LOCALITY_OID, jurisdiction_locality)
        )

    key = ec.generate_private_key(ec.SECP256R1())

    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(attributes))
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certs R Us CA")])
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    return loader.RFC5280CertificateDocumentLoader().load_pem_document(
        cert.public_bytes(serialization.Encoding.PEM).decode()
    )


def _lint(**kwargs):
    cert = _create_certificate(**kwargs)

    validator = certificate.create_pkix_certificate_validator_container(
        serverauth.create_decoding_validators(),
        [
            validation.ValidatorContainer(
                validators=[_VALIDATOR_CLASS()], path="certificate"
            )
        ],
    )

    results = validator.validate(cert.root)

    return {
        fd.finding.code
        for r in results
        for fd in r.finding_descriptions
        if r.validator.name == _VALIDATOR_CLASS.__name__
    }


def test_country_level_ntr_registration_with_country_level_jurisdiction():
    """NTRFR-419964010 with jurisdictionCountryName=FR and no jurisdiction state/locality is consistent."""
    assert (
        _lint(organization_identifier="NTRFR-419 964 010", jurisdiction_country="FR")
        == set()
    )


def test_cpr_case_jurisdiction_country_mismatch_and_subdivision_scope_mismatch():
    """The reported certificate: NTRFR-419964010 asserted against a Guadeloupe country-level jurisdiction."""
    findings = _lint(
        organization_identifier="NTRFR-419 964 010",
        jurisdiction_country="GP",
        jurisdiction_state_or_province="Guadeloupe",
        jurisdiction_locality="Basse-Terre",
    )

    assert findings == {
        _COUNTRY_MISMATCH,
        _SUBDIVISION_ABSENT_STP_PRESENT,
        _SUBDIVISION_ABSENT_LOCALITY_PRESENT,
    }


def test_country_mismatch_only():
    assert _lint(
        organization_identifier="NTRFR-419964010", jurisdiction_country="GP"
    ) == {_COUNTRY_MISMATCH}


def test_subdivision_level_ntr_registration_with_subdivision_jurisdiction():
    assert (
        _lint(
            organization_identifier="NTRUS+CA-12345678",
            jurisdiction_country="US",
            jurisdiction_state_or_province="California",
        )
        == set()
    )


def test_subdivision_level_ntr_registration_without_jurisdiction_stateprovince():
    assert _lint(
        organization_identifier="NTRUS+CA-12345678", jurisdiction_country="US"
    ) == {_SUBDIVISION_PRESENT_STP_ABSENT}


def test_vat_scheme_subdivision_check_not_applied():
    """Only the NTR scheme conveys a subdivision, so no scope finding is reported for VAT."""
    assert (
        _lint(
            organization_identifier="VATFR-12345678",
            jurisdiction_country="FR",
            jurisdiction_state_or_province="Ile-de-France",
        )
        == set()
    )


def test_vat_greece_traditional_country_code_normalized():
    assert (
        _lint(organization_identifier="VATEL-123456789", jurisdiction_country="GR")
        == set()
    )


def test_lei_global_scheme_country_not_compared():
    assert (
        _lint(
            organization_identifier="LEIXG-529900T8BM49AURSDO55",
            jurisdiction_country="FR",
        )
        == set()
    )
