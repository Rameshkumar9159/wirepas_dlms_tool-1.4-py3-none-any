# Copyright 2024 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
from collections.abc import Iterable
from enum import Enum


class Endpoint:
    """ Endpoint class to store the value of an endpoint and its meaning.

    attributes:

    * value (int): Real value of the endpoint.
    * enum (EndpointEnum): Enumerate of the endpoint instance.
    """
    def __init__(self, value: int, source: bool):
        """ Create an Endpoint instance.

        Args:
            value (int): Value of the endpoint.
            source (bool): True if is the Endpoint a source endpoint,
                           otherwise it is a destination enpoint.
        """
        self.value = value
        self.from_source = "Source" if source else "Destination"
        if source:
            self.enum = SourceEndpointEnum.from_endpoint(value)
        else:
            self.enum = DestinationEndpointEnum.from_endpoint(value)

    def __str__(self):
        return f"{self.from_source} endpoint: {self.value} -> {self.enum.name}"

    def __repr__(self):
        return self.__str__()


class EndpointEnum(Enum):
    """ Interface to define the destination and source endpoints enumerate methods. """
    def __init__(self, endpoint):
        """ Create an EndpointEnum instance.

        Args:
            endpoint: Possible values of the endpoint.
        """
        self.endpoint = endpoint

    @classmethod
    def get_all_values(cls) -> list:
        """ Return all the authorized values of an endpoint. """
        values = []
        for association_name in cls.__members__:
            association_enum = cls[association_name]
            if isinstance(association_enum.value, int):
                values.append(association_enum.value)
            elif isinstance(association_enum.value, Iterable):
                values += list(association_enum.value)

        return values

    @classmethod
    def unknown_endpoint(cls):
        """ Return the unknown endpoint. """
        return None

    @classmethod
    def from_endpoint(cls, endpoint: int):
        """ Return the EndpointEnum object corresponding to the endpoint value. """
        for association_name in cls.__members__:
            association_enum = cls[association_name]
            if isinstance(association_enum.value, int) and endpoint == association_enum.value:
                return association_enum
            elif isinstance(association_enum.value, Iterable) and endpoint in association_enum.value:
                return association_enum

        return cls.unknown_endpoint()

    def include(self, endpoint: int):
        """ Verify whether an endpoint is included in the definition of the Enumerate object."""
        if isinstance(self.endpoint, int) and endpoint == self.endpoint:
            return True
        elif isinstance(self.endpoint, Iterable) and endpoint in self.endpoint:
            return True

        return False


class SourceEndpointEnum(EndpointEnum):
    """
    The source endpoint helps to distinguish the type of device and whether the data
    is self-generated (push notifications) or is a part of the response
    to a query (on-demand data).
    """
    UNKNOW_ENDPOINT = -1
    ENERGY_METER_PUSH_NOTIFICATION = 1
    ENERGY_METER_ON_DEMAND_DATA = 2
    WATER_METER_PUSH_NOTIFICATION = 3
    WATER_METER_ON_DEMAND_DATA = 4
    GAS_METER_PUSH_NOTIFICATION = 5
    GAS_METER_ON_DEMAND_DATA = 6
    IN_HOME_DISPLAY = 7
    HANDHELD_DEVICE = 8
    TRANSPARENT_MODE = 65

    @classmethod
    def unknown_endpoint(cls):
        return cls.UNKNOW_ENDPOINT


class DestinationEndpointEnum(EndpointEnum):
    """
    The destination endpoint helps to further
    classify the message based on the meter data type.
    Also, it is used to send meter response to correct HES server instance.
    """
    UNKNOW_ENDPOINT = -1
    LEGACY_ON_DEMAND = 1  # Kept for backward compatibility with dlms app v1.0
    NIC_STATUS_WORD_PUSH = 2
    NAME_PLATE_DETAILS = 3
    INSTANTANEOUS_PROFILE = 4
    BLOCK_LOAD_PROFILE = 5
    DAILY_LOAD_PROFILE = 6
    BILLING_PROFILE = 7
    EVENT_LOGS = 8
    LAST_GASP_NOTIFICATION = 9
    ESW_NOTIFICATION = 10
    EXPORT_BILLING_PROFILE = 11
    ON_DEMAND_DATA = range(32, 64)
    TRANSPARENT_MODE = 65

    @classmethod
    def unknown_endpoint(cls):
        return cls.UNKNOW_ENDPOINT
