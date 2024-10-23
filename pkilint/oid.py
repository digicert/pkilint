from typing import Iterable

from pyasn1.type.univ import ObjectIdentifier


def format_oids(oids: Iterable[ObjectIdentifier]) -> str:
    return ", ".join(sorted(map(str, oids)))
