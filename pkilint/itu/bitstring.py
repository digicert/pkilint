def has_named_bit(node, bit_name):
    bit = node.pdu.namedValues[bit_name]
    return len(node.pdu) > bit and node.pdu[bit] != 0
