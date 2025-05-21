# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
from enum import Enum
from gurux_dlms.enums import Authentication


class AssociationLevelEnum(Enum):
    """
    Enumerate of the different association levels.
    It contains the DLMS client address, association notation, the security authentication
    and the password key name of the meter configuration associated for each association level.
    """
    PC_ASSOCIATION = (0x10, "PC", Authentication.NONE, None)
    MR_ASSOCIATION = (0x20, "MR", Authentication.LOW, "mr_password")
    US_ASSOCIATION = (0x30, "US", Authentication.HIGH, "us_password")
    PUSH_ASSOCIATION = (0x40, "push", Authentication.HIGH, None)
    FU_ASSOCIATION = (0x50, "FU", Authentication.HIGH, "fu_password")

    def __init__(self, client_address, notation, authentication, password_key):
        self.client_address = client_address
        self.notation = notation
        self.authentication = authentication
        self.password_key = password_key

    @classmethod
    def from_client_address(cls, client_address: int):
        """ Return the AssociationLevelEnum object corresponding to the client address.
        The client address must be chosen between 16, 32, 48, 64 and 80.
        """
        for association_name in AssociationLevelEnum.__members__:
            association_values = AssociationLevelEnum[association_name]
            if association_values.client_address == client_address:
                return association_values

    @classmethod
    def from_notation(cls, notation: str):
        """ Return the AssociationLevelEnum object corresponding to the notation.
        The notation must be chosen between "PC", "MR", "US", "push" and "FU".
        """
        for association_name in AssociationLevelEnum.__members__:
            association_values = AssociationLevelEnum[association_name]
            if association_values.notation == notation:
                return association_values
