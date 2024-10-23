from typing import Optional

from pyasn1.type import univ

from pkilint import document


def get_string_value_from_attribute_node(node: document.PDUNode) -> Optional[str]:
    node = node.children["value"]

    try:
        _, node = node.child
    except ValueError:
        # attribute value has not been decoded
        return None

    # handle DirectoryString CHOICE
    if isinstance(node.pdu, univ.Choice):
        _, node = node.child

    return str(node.pdu)
