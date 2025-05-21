# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
from enum import Enum


class ProfileGeneric(Enum):
    """
    Enumerate to store the obis code of the different DLMS profile generic,
    their scaler obis when it exists and the event code obis for the events.
    """
    INSTANTANEOUS = ("1.0.94.91.0.255", "1.0.94.91.3.255", None)
    BLOCK_LOAD = ("1.0.99.1.0.255", "1.0.94.91.4.255", None)
    DAILY_LOAD = ("1.0.99.2.0.255", "1.0.94.91.5.255", None)
    BILLING = ("1.0.98.1.0.255", "1.0.94.91.6.255", None)
    NAME_PLATE = ("0.0.94.91.10.255", None, None)
    VOLTAGE_EVENTS_LOG = ("0.0.99.98.0.255", "1.0.94.91.7.255", "0.0.96.11.0.255")
    CURRENT_EVENTS_LOG = ("0.0.99.98.1.255", "1.0.94.91.7.255", "0.0.96.11.1.255")
    POWER_EVENTS_LOG = ("0.0.99.98.2.255", "1.0.94.91.7.255", "0.0.96.11.2.255")
    TRANSACTION_EVENTS_LOG = ("0.0.99.98.3.255", "1.0.94.91.7.255", "0.0.96.11.3.255")
    OTHER_EVENTS_LOG = ("0.0.99.98.4.255", "1.0.94.91.7.255", "0.0.96.11.4.255")
    NON_ROLLOVER_EVENTS_LOG = ("0.0.99.98.5.255", "1.0.94.91.7.255", "0.0.96.11.5.255")
    CONTROL_EVENTS_LOG = ("0.0.99.98.6.255", "1.0.94.91.7.255", "0.0.96.11.6.255")

    def __init__(self, obis_code: str, scaler_obis_code: str, event_code_obis: str):
        self.obis_code = obis_code
        self.scaler_obis_code = scaler_obis_code
        self.event_code_obis = event_code_obis
