# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
import logging
from datetime import datetime
from enum import Enum
from gurux_dlms import GXByteBuffer, GXReplyData
from gurux_dlms.enums import ErrorCode
from .endpoint_enum import Endpoint

from typing import Any


class NotificationObisEnum(Enum):
    """
    Enumerate to describe all the notification related obis code and name.
    It contains the obis code and the obis name of the data notification.
    """
    EVENT_STATUS_WORD_PUSH = ("0.4.25.9.0.255", "Event Status Word push")
    INSTANTANEOUS_PROFILE = ("0.0.25.9.0.255", "Instantaneous profile")
    BLOCK_LOAD_PROFILE = ("0.5.25.9.0.255", "Block load profile")
    DAILY_LOAD_PROFILE = ("0.6.25.9.0.255", "Daily load profile")
    BILLING_PROFILE = ("0.103.25.9.0.255", "Billing profile")
    NAME_PLATE_DETAILS = ("0.104.25.9.0.255", "Name plate details")
    NIC_STATUS_WORD = ("0.105.25.9.0.255", "NIC status word notification")
    CURRENT_BILLING_PROFILE = ("0.106.25.9.0.255", "Current billing profile")
    EXPORT_BILLING_PROFILE = ("0.107.25.9.0.255", "Export billing profile")

    VOLTAGE_EVENTS_LOG_PROFILE = ("0.120.25.9.0.255", "Voltage related events log profile")
    CURRENT_EVENTS_LOG_PROFILE = ("0.121.25.9.0.255", "Current related events log profile")
    POWER_EVENTS_LOG_PROFILE = ("0.122.25.9.0.255", "Power related events log profile")
    TRANSACTION_EVENTS_LOG_PROFILE = ("0.123.25.9.0.255", "Transaction related events log profile")
    OTHER_EVENTS_LOG_PROFILE = ("0.124.25.9.0.255", "Other events log profile")
    NON_ROLLOVER_EVENTS_LOG_PROFILE = ("0.125.25.9.0.255", "Non-rollover events log profile")
    CONTROL_EVENTS_LOG_PROFILE = ("0.126.25.9.0.255", "Control events log profile")
    #this below obis code is not used in the current implementation this is manually added by the developer
    # to test the parsing of the notification
    TOTAL_IMPORT_ENERGY = ("1.0.1.8.0.255", "Total Active Energy Import")
    TOTAL_EXPORT_ENERGY = ("1.0.2.8.0.255", "Total Active Energy Export")
    #meter serial number
    METER_SERIAL_NUMBER = ("0.0.96.1.0.255", "Meter Serial Number")

    def __init__(self, obis_code: str, obis_name: str):
        self.obis_code = obis_code
        self.obis_name = obis_name

    @classmethod
    def from_obis_code(cls, obis_code: str):
        """ Return the Notification object corresponding to the obis code. """
        for association_name in NotificationObisEnum.__members__:
            association_values = NotificationObisEnum[association_name]
            if association_values.obis_code == obis_code:
                return association_values


class ConnectionStatusEnum(Enum):
    """ Connection status enumerate for the association between the NIC and the meter. """
    TESTED_SUCCESSFUL = "1"  # Association tested and successful.
    TESTED_UNSUCCESSFUL = "0"  # Association tested but unsuccessful.

    @classmethod
    def from_bit_string(cls, string: str):
        """ Return the ConnectionStatusEnum corresponding to a bitstring. """
        assert isinstance(string, str) and len(string) == 1, "A connection status must be string of length 1."
        return ConnectionStatusEnum(string)


class NicStatusReason(Enum):
    """ Nic Status reason to enumerate the reason a NIC status is sent by a meter. """
    COMMUNICATION_PROBLEM = 0
    NIC_REBOOT = 1
    NIC_REGISTRATION = 2
    METER_ASSOCIATION_ISSUE = 3
    SINK_CHANGE = 4

    @staticmethod
    def nic_status_reasons_list_from_string(string: str) -> list:
        """ Get the NIC status reasons list from a string:

        For example, nic_status_reasons_list_from_string('11010000') will return
        [NicStatusReason.COMMUNICATION_PROBLEM, NicStatusReason.NIC_REBOOT,
         NicStatusReason.METER_ASSOCIATION_ISSUE]
        """
        assert isinstance(string, str) and len(string) >= 6, \
            "Nic status reasons list must be generated from a string of size at least 6."

        reasons_list = []
        for index, bit in enumerate(string):
            try:
                if bit == "1":
                    reasons_list.append(NicStatusReason(index))
            except ValueError:
                logging.warning("A nic status reason could not be parsed. index: %d in string %s",
                                index, string)

        return reasons_list


class ParsedData:
    """ Object to manipulate DLMS data information. It contains the following attributes:

    * source_address (int): Source address of the message.
    * target_address (int): Destination address of the message.
    * invoke_id_and_priority (int): Invoke id and priority value of the message.
    * msg_error_code (ErrorCode): Error code of the message when it is parsed by gurux.
    * value (any): Content value of the message.
    * xml (str): Xml string to represent the parsed data.
    * payload (bytes): DLMS message raw payload. This payload can be encrypted.
    """
    def __init__(self,
                 source_address: int,
                 target_address: int,
                 invoke_id_and_priority: int,
                 msg_error_code: ErrorCode,
                 value: Any = None,
                 xml: str = None,
                 payload: bytes = None):

        self.source_address: int = source_address
        self.target_address: int = target_address
        self.invoke_id_and_priority: int = invoke_id_and_priority
        self.msg_error_code: ErrorCode = ErrorCode(msg_error_code)
        self.value: Any = value
        self.xml: str = xml
        self.src_ep = None
        self.dst_ep = None
        self.payload = payload

    def set_endpoints(self, src_ep: Endpoint = None, dst_ep: Endpoint = None):
        if src_ep:
            self.src_ep = src_ep
        if dst_ep:
            self.dst_ep = dst_ep

    @classmethod
    def from_payload(cls, client, payload: bytes):
        """ Create an instance of the class from a payload and a wirepas_dlms_tool.Client to parse the message. """
        xml = None
        try:
            reply = GXReplyData()
            notify = GXReplyData()
            xml = client.message_to_xml(payload.hex())
            is_not_notify = client.gx_client.getData(GXByteBuffer(payload), reply, notify)
            if not is_not_notify:
                logging.warning("The payload could not be parsed.")
                return

            # Set up a new class instance with the data and notify parsed
            return ParsedData(source_address=reply.targetAddress or notify.targetAddress,
                              target_address=reply.sourceAddress or notify.sourceAddress,
                              invoke_id_and_priority=reply.invokeId or notify.invokeId,
                              msg_error_code=ErrorCode(reply.error),
                              value=reply.value,
                              xml=xml,
                              payload=payload)
        except ValueError as err:
            logging.error("A value error occured: %s", err)
            if xml:
                return ParsedData(source_address=None, target_address=None,
                                  invoke_id_and_priority=None,
                                  msg_error_code=ErrorCode.OTHER_REASON,
                                  value=None, xml=xml, payload=payload)
        except Exception:
            if xml:
                return ParsedData(source_address=None, target_address=None,
                                  invoke_id_and_priority=None,
                                  msg_error_code=ErrorCode.OTHER_REASON,
                                  value=None, xml=xml, payload=payload)

    def __str__(self):
        # Return a string containing the class name and all the attributes values of the instance in separate lines.
        classname = self.__class__.__name__
        return classname + "\n" + "\n".join(
                [
                    attribute + ": " + str(value)
                    for attribute, value in self.__dict__.items()
                    if attribute != "xml"
                ]
            )


class WirepasNotification(ParsedData):
    """ Object to manipulate Wirepas DLMS data notification information. It contains the following attributes:

    * source_address (int): Source address of the message.
    * target_address (int): Destination address of the message.
    * invoke_id_and_priority (int): Invoke id and priority value of the message.
    * message_time (datetime): Time of the message when it was sent by the NIC.
    * device_id (bytes): Device ID of the meter sending the data notification message.
    * obis_code (str): String representation of the obis code of the data notification in xxx.xxx.xxx.xxx.xxx.xxx format.
    * obis_name (str): String name associated to the obis code of the message.
    * msg_error_code (ErrorCode): Error code of the message when it is parsed by gurux.
    * value (list): Content value of the message.
    * xml (str): Xml string to represent the parsed data.
    * payload (bytes): DLMS message raw payload. This payload can be encrypted.
    """
    def __init__(self,
                 source_address: int,
                 target_address: int,
                 invoke_id_and_priority: int,
                 message_time: datetime,
                 device_id: bytes,
                 obis_code: str,
                 msg_error_code: ErrorCode,
                 value: list = None,
                 xml: str = None,
                 payload: bytes = None):

        super().__init__(source_address, target_address, invoke_id_and_priority, msg_error_code, value, xml, payload)
        self.message_time = message_time
        self.device_id = device_id
        self.obis_code = obis_code

        notification_obis = NotificationObisEnum.from_obis_code(self.obis_code)
        self.obis_name: str = "Unknown obis code"
        if notification_obis:
            self.obis_name = notification_obis.obis_name

    @classmethod
    def from_payload(cls, client, payload: bytes):
        try:
            notify = GXReplyData()
            data = GXReplyData()
            is_not_notify = client.gx_client.getData(GXByteBuffer(payload), data, notify)
            if is_not_notify or not isinstance(notify.value, list) or len(notify.value) < 4:
                return

            notif_obis = ".".join([str(k) for k in notify.value[1]])
            message_time = client.to_datetime(notify.value[2])
            xml = client.message_to_xml(payload.hex())

            if len(notify.value) == 4:
                value = notify.value[3]
            else:
                return

            # Set up a new class instance with the data and notify parsed
            return WirepasNotification(source_address=data.targetAddress or notify.targetAddress,
                                       target_address=data.sourceAddress or notify.sourceAddress,
                                       invoke_id_and_priority=data.invokeId or notify.invokeId,
                                       message_time=message_time,
                                       device_id=bytes(notify.value[0]),
                                       obis_code=notif_obis,
                                       msg_error_code=ErrorCode(notify.error),
                                       value=value,
                                       xml=xml,
                                       payload=payload)
        except Exception:
            return None


class NicStatusWord(WirepasNotification):
    """ Object to manipulate Wirepas DLMS data notification information. It contains the following attributes:

    * source_address (int): Source address of the message.
    * target_address (int): Destination address of the message.
    * invoke_id_and_priority (int): Invoke id and priority value of the message.
    * message_time (datetime): Time of the message when it was sent by the NIC.
    * device_id (bytes): Device ID of the meter sending the data notification message. \
            (None if the meter hasn't been provisioned).
    * serial_number (bytes): Serial Number of the meter.
    * obis_code (str): String representation of the obis code of the data notification in xxx.xxx.xxx.xxx.xxx.xxx format.
    * obis_name (str): String name associated to the obis code of the message.
    * nic_system_title (bytes): System title of the NIC server.
    * US_invocation_counter (int): Invocation counter of the NIC server for US association.
    * PC_connection_status (ConnectionStatusEnum): Connection status of the PC association between the nic and the meter.
    * MR_connection_status (ConnectionStatusEnum): Connection status of the MR association between the nic and the meter.
    * US_connection_status (ConnectionStatusEnum): Connection status of the US association between the nic and the meter.
    * FU_connection_status (ConnectionStatusEnum): Connection status of the FU association between the nic and the meter.
    * dlms_app_fw_version (str): Version of the dlms app firmware version.
    * nic_status_reason (list): List of the NIC status reasons enumerates.
    * msg_error_code (ErrorCode): Error code of the message when it is parsed by gurux.
    * value (list): Content value of the message. These values are also stored in the object attributes.
    * xml (str): Xml string to represent the parsed data.
    * payload (bytes): DLMS message raw payload. This payload can be encrypted.
    """
    def __init__(self,
                 US_invocation_counter: int,
                 PC_connection_status: ConnectionStatusEnum,
                 MR_connection_status: ConnectionStatusEnum,
                 US_connection_status: ConnectionStatusEnum,
                 FU_connection_status: ConnectionStatusEnum,
                 nic_system_title: bytes,
                 dlms_app_fw_version: str,
                 *args,
                 nic_status_reason: list = None,
                 serial_number: bytes = None,
                 **kwargs):

        super().__init__(*args, **kwargs)
        self.nic_system_title = nic_system_title
        self.US_invocation_counter = US_invocation_counter
        self.PC_connection_status = PC_connection_status
        self.MR_connection_status = MR_connection_status
        self.US_connection_status = US_connection_status
        self.FU_connection_status = FU_connection_status
        self.dlms_app_fw_version = dlms_app_fw_version
        self.nic_status_reason = nic_status_reason
        self.serial_number = serial_number

    @classmethod
    def from_payload(cls, client, payload: bytes):
        notification = WirepasNotification.from_payload(client, payload)
        if not notification:
            return None
        elif len(notification.value) != 6:
            logging.warning("NIC status word buffer expected to have 6 fields, but found %d fields.",
                            len(notification.value))

        try:
            # Parse all NIC status fields.
            nic_system_title = bytes(notification.value[0])
            us_invocation_counter = int(notification.value[1])
            dlms_app_fw_version = notification.value[2].decode("utf-8")
            serial_number = bytes(notification.value[5])
            nic_status_reason = NicStatusReason.nic_status_reasons_list_from_string(notification.value[3].value)

            connections_status = notification.value[4].value
            if len(connections_status) < 4:
                logging.error("Connection status must contain at least 4 bits, 1 bit for each association!")

            pc_connection_status = ConnectionStatusEnum.from_bit_string(connections_status[0])
            mr_connection_status = ConnectionStatusEnum.from_bit_string(connections_status[1])
            us_connection_status = ConnectionStatusEnum.from_bit_string(connections_status[2])
            fu_connection_status = ConnectionStatusEnum.from_bit_string(connections_status[3])

            return NicStatusWord(nic_system_title=nic_system_title,
                                 US_invocation_counter=us_invocation_counter,
                                 PC_connection_status=pc_connection_status,
                                 MR_connection_status=mr_connection_status,
                                 US_connection_status=us_connection_status,
                                 FU_connection_status=fu_connection_status,
                                 dlms_app_fw_version=dlms_app_fw_version,
                                 nic_status_reason=nic_status_reason,
                                 serial_number=serial_number,
                                 source_address=notification.source_address,
                                 target_address=notification.target_address,
                                 invoke_id_and_priority=notification.invoke_id_and_priority,
                                 message_time=notification.message_time,
                                 device_id=notification.device_id,
                                 obis_code=notification.obis_code,
                                 msg_error_code=notification.msg_error_code,
                                 value=notification.value,
                                 xml=notification.xml,
                                 payload=payload)
        except Exception:
            return None
