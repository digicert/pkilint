from datetime import datetime, timezone

import pytest

from pkilint.pkix import time


def test_parse_generalizedtime_nocentury():
    val = "990101000000Z"

    with pytest.raises(ValueError):
        time.parse_generalizedtime(val)


def test_parse_generalizedtime_wrongtimezone():
    val = "19990101000000E"

    with pytest.raises(ValueError):
        time.parse_generalizedtime(val)


def test_parse_generalizedtime_notimezone():
    val = "19990101000000"

    with pytest.raises(ValueError):
        time.parse_generalizedtime(val)


def test_parse_generalizedtime():
    val = "19990101000000Z"

    parsed = time.parse_generalizedtime(val)
    expected = datetime(1999, 1, 1, 0, 0, 0, 0, timezone.utc)

    assert parsed == expected


def test_parse_utctime_wrongtimezone():
    val = "990101000000E"

    with pytest.raises(ValueError):
        time.parse_utctime(val)


def test_parse_utctime_notimezeone():
    val = "990101000000"

    with pytest.raises(ValueError):
        time.parse_utctime(val)


def test_parse_utctime_49():
    val = "490101000000Z"

    parsed = time.parse_utctime(val)
    expected = datetime(2049, 1, 1, 0, 0, 0, 0, timezone.utc)

    assert parsed == expected


def test_parse_utctime_50():
    val = "500101000000Z"

    parsed = time.parse_utctime(val)
    expected = datetime(1950, 1, 1, 0, 0, 0, 0, timezone.utc)

    assert parsed == expected
