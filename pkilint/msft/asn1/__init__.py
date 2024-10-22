from pyasn1.type import univ, char, constraint

MAX = float("inf")

id_on_UserPrincipalName = univ.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


class UserPrincipalName(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)
