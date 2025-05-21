# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
from __future__ import annotations  # Typing hints helper
import logging
from copy import deepcopy
from datetime import datetime
import functools
from queue import Queue
import re
from threading import Event, Lock, Thread
from typing import Any, Callable, Union

from gurux_dlms import GXBitString, GXByteBuffer, GXDateTime, GXReplyData, GXWriteItem
from gurux_dlms.enums import RequestTypes, DataType, ObjectType
from gurux_dlms.internal._GXCommon import _GXCommon
from gurux_dlms.objects import GXDLMSObject, GXDLMSClock, GXDLMSDisconnectControl, \
    GXDLMSProfileGeneric, GXDLMSRegister, GXDLMSData, GXDLMSActionSchedule, GXDLMSActivityCalendar, \
    GXDLMSLimiter, GXDLMSPushSetup, GXDLMSAssociationLogicalName, GXDLMSImageTransfer, GXDLMSScriptTable, GXDLMSScript

from .client import Client, DLMS_METER_ADDRESS, DLMS_NIC_ADDRESS, NIC_CLIENT_SYSTEM_TITLE
from .association_level_enum import AssociationLevelEnum
from .endpoint_enum import DestinationEndpointEnum, Endpoint, SourceEndpointEnum
from .error_code_enum import ErrorCodeEnum
from .parsed_data import WirepasNotification, NotificationObisEnum, NicStatusWord
from .profile_generic import ProfileGeneric
from .response import Response


GET_DEFAULT_KEY: str = "uninitialized key"  # Uninitialized keys need to be taken from Meter attributes by default.


class MeterConfiguration:
    """ Class representing a meter configuration.
    It contains the keys and secrets in hexadecimal used by a meter. """
    def __init__(self,
                 authentication_key: str = None,
                 block_cipher_key: str = None,
                 dedicated_key: str = None,
                 key_encryption_key: str = None,
                 mr_password: str = None,
                 us_password: str = None,
                 fu_password: str = None):

        # Verification of key and password type and length and remove the space from the strings.
        self.authentication_key = self._key_formatting(authentication_key, "authentication key")
        self.block_cipher_key = self._key_formatting(block_cipher_key, "block cipher key")
        self.dedicated_key = self._key_formatting(dedicated_key, "dedicated key")
        self.key_encryption_key = self._key_formatting(key_encryption_key, "key encryption key")
        self.mr_password = self._key_formatting(mr_password, "MR password")
        self.us_password = self._key_formatting(us_password, "US password")
        self.fu_password = self._key_formatting(fu_password, "FU password")

    def _key_formatting(self, key: str, key_name: str, string_size: int = 32) -> str:
        """ Format the key hex string by removing the spaces.
        Raises AttributeError if the key is not a string or has not the good length.
        """
        if key:
            if not isinstance(key, str):
                raise AttributeError(f"{key_name} must be a hex string"
                                     f" but type found is {type(key)}: {key}")

            key = key.replace(" ", "")
            if "password" in key_name and (len(key) > string_size or len(key) % 2):
                raise AttributeError(f"{key_name} hex string length must be an even number smaller than "
                                     f"{string_size} but is of length {len(key)}: {key}")

            elif "password" not in key_name and len(key) != string_size:
                raise AttributeError(f"{key_name} hex string must be of length {string_size}"
                                     f" but input is of length {len(key)}: {key}")

            return key

    def get_password(self, authentication_level: AssociationLevelEnum) -> str:
        """ Get the password in hexadecimal corresponding to the meter association. """
        if authentication_level.password_key == "mr_password":
            if self.mr_password:
                return self.mr_password
        elif authentication_level.password_key == "us_password":
            if self.us_password:
                return self.us_password
        elif authentication_level.password_key == "fu_password":
            if self.fu_password:
                return self.fu_password

    def to_client(self, authentication_level: AssociationLevelEnum, NIC_server: bool = False) -> Client:
        """ Create and return a Client object from the meter configuration.

        Args:
            authentication_level: Authentication level of the client.
            NIC_server: Boolean to assert if the client needs to exchange with the NIC.
                Default to False.
        """
        # Get the password associated to the authentication level found with the client address
        server_address = DLMS_NIC_ADDRESS if NIC_server else DLMS_METER_ADDRESS

        if authentication_level == AssociationLevelEnum.PC_ASSOCIATION:
            meter_client = Client(
                client_address=authentication_level.client_address,
                server_address=server_address
            )
        else:
            password = self.get_password(authentication_level)
            meter_client = Client(
                client_address=authentication_level.client_address,
                server_address=server_address,
                authentication_key=self.authentication_key,
                block_cipher_key=self.block_cipher_key,
                dedicated_key=self.dedicated_key,
                password=password
            )

        return meter_client

    def __str__(self):
        classname = self.__class__.__name__
        return classname + ":\n" + "\n".join([attribute + ": " + str(value) for attribute, value in self.__dict__.items()])


class Meter:
    """ Class module to abstract meters in the Wirepas network and to query these.

    It manages the meter configurations and, especially, it handles the ciphering settings
    that are used to encrypt/decrypt messages exchanged with a meter in all association modes.
    It also provides methods to connect to, to query the meters and to parse their responses.
    All request methods can be used as is to query values from the meter,
    and they will return a Response object possessing the response error code,
    the meter response payload, the value that was queried and
    the xml representation of the response message.

    The meter requests in pass-through do not need any application association establishment.
    But, the establish_AA_NIC method should be used to establish the association with the NIC
    before doing queries to the NIC server and the release_AA_NIC method should be used at the end of the exchange
    to free the meter association with the NIC. The pass-through requests might not work
    if a NIC association is established but not released.

    For example, the following code can be used to query a meter in pass-through:

    .. code-block:: python

        response = meter.get_meter_device_ID()
        if response.error_code == ErrorCodeEnum.RES_OK:
            print(f"The device ID of the meter is {response.value}")


    Plus, the following code can be used to provision a meter:

    .. code-block:: python

        if meter.establish_AA_NIC():
            result = meter.set_NIC_security_material_from_config(configuration)
            if result.error_code == ErrorCodeEnum.RES_OK:
                print(f"The meter has been provisioned!")
            meter.release_AA_NIC()

    Notes:

    * All DLMS requests methods containing "NIC" in their name are sent to the NIC and \
        the DLMS requests methods containing "meter" in their name are sent in passthrough.
    * establish_AA_NIC and release_AA_NIC are the only methods sending DLMS requests \
        that return boolean. The others return a Response object.
    * DLMS requests in passthrough create/set automatically a new client before generating the payload.
    * establish_AA_NIC method creates/sets a new client that will only handle the NIC requests. \
        This client is destroyed on release of the association.
    """
    class _MeterSession:
        """ Internal class represetning the session associated to the meter.
        It should represent the communication state of a meter object.

        Attributes:
            last_received_response: Last response received by the meter.
            data_received_event: Threading event to make the meter object wait for responses.
            send_msg_lock: Lock used to send a message to the meter so that only one request is done at a time.
        """
        def __init__(self):
            self.last_received_response: Response = None
            self.data_received_event: Event = Event()
            self.send_msg_lock: Lock = Lock()

        def get_lock(self) -> Lock:
            return self.send_msg_lock

        def get_received_response(self) -> Response:
            """ Get the last response received by the meter. """
            return self.last_received_response

        def set_received_response(self, response: Response) -> None:
            """ Set the last response received by the meter. """
            self.last_received_response = response

        def set_data(self, data: Union[Response, None]) -> None:
            """ Set the data and stop waiting for a message. """
            self.set_received_response(data)
            self.data_received_event.set()

        def prepare_reception(self) -> None:
            """ Wait for data to be received from the meter. """
            self.set_received_response(None)
            self.data_received_event.clear()

        def wait_for_message(self, timeout_s) -> None:
            """ Make the meter object waiting for a message. """
            self.data_received_event.wait(timeout_s)

        def has_received_a_response(self):
            """ Return True if the meter has received a response recently, return False otherwise. """
            return self.data_received_event.is_set()

        def is_waiting(self) -> bool:
            """ Return whether the meter is waiting for a message. """
            return not self.has_received_a_response() and self.send_msg_lock.locked()

    def __init__(self,
                 dni,
                 node_id: int,
                 meter_configuration: MeterConfiguration,
                 nic_system_title: bytes = None,
                 NIC_status_cb: Callable = None,
                 notification_cb: Callable = None,
                 unparsed_cb: Callable = None,
                 response_timeout_s: int = 20):
        """ Create a meter object.
        The callbacks must be provided to log the corresponding messages.

        Args:
            dni: DLMS network interface to communicate with the network.
            node_id: Node id of the NIC associated to the meter.
            meter_configuration: Ciphering meter configuration.
            nic_system_title: Local storage for system title of the NIC.
                If wrong, the requests to the meter might not be answered, but the message are still unencrypted correctly.
                When connecting to the NIC server, its value will be updated so that messages can be exchanged.
            NIC_status_cb: Callback that will be called when receiving a NIC status word notification.
                The callback must take a meter object and the NicStatusWord object in argument.
            notification_cb: The callback that will be called when receiving a data notification.
                The callback must take a meter object and a WirepasNotification object in arguments.
            unparsed_cb: The callback that will be called when being unable to parse a payload.
                The callback must take the meter object and the payload as bytes in arguments.
            response_timeout_s: Timeout in seconds to wait for receiving responses.
        """

        # Sets the MQTT configuration
        self.dni = dni
        self.node_id = node_id
        self.session = Meter._MeterSession()

        # Sets the tests
        self.response_timeout_s = response_timeout_s

        # Sets the callbacks
        self.NIC_status_cb = NIC_status_cb
        self.notification_cb = notification_cb
        self.unparsed_cb = unparsed_cb

        # Temporary dictionary containing the keys for which a set request has been sent to the NIC server.
        self._keys_to_change = {}
        # Keys for which the NIC server validated the set request, they are changed after the releasing of the AA.
        self._keys_validated_to_change = {}

        # Initialization of the clients. client and NIC_client are set when sending request/ establishing AA.
        self.client = None  # Client used for the queries/responses to the meter in passthrough.
        self.NIC_client = None  # Client used for the queries/responses to the NIC server.
        self.notification_client = None  # Client used to translate notification message

        # Additional informations used to create the clients.
        # Authorize the usage of invoke id to recognize the message.
        self.incremente_invoke_id = True
        # Variable storing the IC of the meter that is used for both passthrough and NIC requests.
        self.invoke_id = 0
        # NIC IC is incremented each time we try to send an encrypted message and reflects meter IC.
        self.invocation_counter = None

        # Meter configuration settings
        self.nic_system_title = nic_system_title
        self.meter_configuration = meter_configuration

        # Network informations
        self.gateway_id = None
        self.sink_id = None

        # Create a queue to store received messages for this Meter object and a thread to dispatch them.
        self.callbacks_to_execute = Queue()
        self.cbs_handler_thread = Thread(target=self._handle_callbacks)
        self.cbs_handler_thread.daemon = True
        self.cbs_handler_thread.start()

    @property
    def meter_configuration(self):
        return self._meter_configuration

    @meter_configuration.setter
    def meter_configuration(self, meter_configuration):
        """
        Setter for meter_configurations. It copies the argument,
        and updates the ciphering settings of the tranlation clients accordingly.
        """
        self._meter_configuration = deepcopy(meter_configuration)
        if meter_configuration is None:
            return

        # Update client ciphering settings.
        if self.client is not None:
            self.client.update_keys(self._meter_configuration)
        if self.NIC_client is not None:
            self.NIC_client.update_keys(self._meter_configuration)

        # Update notification client if it exists otherwise create it.
        if self.notification_client is None:
            self.notification_client = self._create_client(AssociationLevelEnum.PUSH_ASSOCIATION, NIC_server=True)
        elif self.notification_client is not None:
            self.notification_client.update_keys(self._meter_configuration)

    def _set_client(self, client):
        self.client = client

    def _set_NIC_client(self, client):
        self.NIC_client = client

    def is_waiting_for_response(self) -> bool:
        """ Return whether the object is currently waiting for a response from the meter/NIC."""
        return self.session.is_waiting()

    def get_client(self, NIC_server: bool):
        """ Get current client used to communicate with the meter.

        Args:
            NIC_server: Boolean asserting whether the client is used to communicate with the NIC.
        """
        if NIC_server:
            return self.NIC_client
        else:
            return self.client

    def update_network_settings(self, gateway_id: str, sink_id: str):
        """ Update the network informations of a meter.

        Args:
            gateway_id: gateway id linked to the NIC attached to the meter.
            sink_id: sink id linked to the NIC attached to the meter.
        """
        self.gateway_id = gateway_id
        self.sink_id = sink_id

    def get_network_settings(self) -> tuple[str, str]:
        """ Return the network informations of a meter as a tuple (gateway_id, sink_id). """
        return self.gateway_id, self.sink_id

    def update_meter(self,
                     meter_configuration: MeterConfiguration = None,
                     NIC_status_cb: Callable = None,
                     notification_cb: Callable = None,
                     unparsed_cb: Callable = None,
                     response_timeout_s: int = 20) -> Meter:
        """ Update the meter object attributes with the not null values.

        Args:
            meter_configuration: Ciphering meter configuration.
            NIC_status_cb: Callback that will be called when receiving a NIC status word notification.
                The callback must take a meter object and the NicStatusWord object in argument.
            notification_cb: The callback that will be called when receiving a data notification.
                The callback must take a meter object and a WirepasNotification object in arguments.
            unparsed_cb: The callback that will be called when being unable to parse a payload.
                The callback must take the meter object and the payload as bytes in arguments.
            response_timeout_s: timeout in seconds to wait for receiving responses.
        """
        if meter_configuration:
            self.meter_configuration = meter_configuration
        if NIC_status_cb:
            self.NIC_status_cb = NIC_status_cb
        if notification_cb:
            self.notification_cb = notification_cb
        if unparsed_cb:
            self.unparsed_cb = unparsed_cb
        if response_timeout_s:
            self.response_timeout_s = response_timeout_s

    def set_incremente_invoke_id(self, incremente_invoke_id: bool):
        """ Assert if invoke id can be incremented when requesting the meter.
        Some meter do not authorize invoke id and they don't respond to requests that use it.
        If set to True, each time a request is sent, the invoke id will be incremented by 1.
        If set to False, invoke id will be set to 1 for all requests
        and responses can't be differenciated with their invoke id.
        It can be dangerous when doing request in bulk with timeout occurring.
        """
        self.incremente_invoke_id = incremente_invoke_id

    @staticmethod
    def generate_system_title(flag: str, node_id: int) -> bytes:
        """ Generate the system title of a NIC from its node id and a manufacturer flag.
        Take the flag string of length 3 and add the 5 first bytes of the node id.
        An AssertionError is raised if the flag is not a string of length 3.

        For example:

        .. code-block:: python

            system_title = Meter.generate_system_title(flag='TBC', node_id=123456789)
        """
        assert isinstance(flag, str) and len(flag) == 3, f"Flag must be a string of length 3, but found {flag}"
        return flag.encode() + int.to_bytes(node_id, 5, "big")

    def add_callback_to_execute(self, callback, *args, **kwargs) -> None:
        """ Add a callback to execute in the tasks queue. """
        self.callbacks_to_execute.put((callback, args, kwargs))

    def terminate(self):
        """ Terminate the thread executing the callbacks. """
        self.callbacks_to_execute.put(None)

    def _handle_callbacks(self) -> None:
        while True:
            try:
                task, args, kwargs = self.callbacks_to_execute.get()
                task(*args, **kwargs)
            except TypeError:
                # When a task is None in the queue and the task is invoked
                # a type error is raised. This condition is used to terminate the Thread
                break
            except Exception as e:
                logging.exception(e)

    def on_data_received_cb(self, data, src_ep: Endpoint = None, dst_ep: Endpoint = None) -> None:
        """
        Callback to be called when data are received from the network from the associated meter.
        The notification callback is called if the message can be parsed as a Wirepas data notification.
        The nic status callback is called if the message can be parsed as a Wirepas NIC status word notification.
        If the message is a response from the meter that can be parsed the session infos are updated.
        If the message can not be parsed, the unparsed callback is called.

        Note:

        * If the nic status cb is defined, the NIC status update the IC/ST of this object when received.
        """
        # Logs the received message
        logging.info("RX: A payload of size %d has been received from node 0x%X(%d) "
                     "from network 0x%X(%d) with gateway %s/%s on endpoints (%d, %d)",
                     len(data.data_payload.hex())//2, self.node_id, self.node_id,
                     data.network_address, data.network_address, data.gw_id, data.sink_id,
                     src_ep.value, dst_ep.value)
        logging.debug("RX: %s", data.data_payload.hex())
        source_address, _ = self.notification_client.get_addresses_from_payload(data.data_payload)

        # Try to parse the payload as NIC status word notification.
        if self._handle_nic_status_word(data.data_payload, src_ep, dst_ep):  # TODO add endpoints filter
            return

        # Try to parse the payload as a data notification if the meter can handle notification.
        if self._handle_notification(data.data_payload, src_ep, dst_ep):
            return

        # Try to parse the payload as a response if the meter is waiting for it.
        if self._handle_response(data.data_payload, source_address==DLMS_NIC_ADDRESS, src_ep, dst_ep):
            return

        # If the payload could not be parsed, the unparsed data callback is called.
        logging.info("A message from %s could not be parsed.", self.node_id)
        if self.unparsed_cb is not None:
            self.add_callback_to_execute(self.unparsed_cb, self, data.data_payload)

    def reparse_payload(self, payload: bytes, src_ep, dst_ep) -> bool:
        """
        Method to call to parse a DLMS packet.
        Return True if the payload could be parse, otherwise return False.

        The notification callback is called if the message can be parsed as a Wirepas data notification.
        The nic status callback is called if the message can be parsed as a Wirepas NIC status word notification.
        If the message is a response from the meter that can be parsed the session infos are updated.
        If the message can not be parsed, nothing will happen.

        Note:

        * If the nic status cb is defined, the NIC status update the IC/ST of this object when received.
        """
        # Logs the received message
        logging.info("Try to re parse a payload!")
        source_address, _ = self.notification_client.get_addresses_from_payload(payload)

        # Try to parse the payload as NIC status word notification.
        if self._handle_nic_status_word(payload, src_ep, dst_ep):
            return True

        # Try to parse the payload as a data notification if the meter can handle notification.
        if self._handle_notification(payload, src_ep, dst_ep):
            return True

        # Try to parse the payload as a response if the meter is waiting for it.
        if self._handle_response(payload, source_address==DLMS_NIC_ADDRESS, src_ep, dst_ep):
            return True

        # If the payload could not be parsed, the unparsed data callback is called.
        logging.info("A message from %s could not be parsed.", self.node_id)
        return False

    def _handle_nic_status_word(self, payload: bytes, src_ep: Endpoint = None, dst_ep: Endpoint = None) -> bool:
        """
        Try to parse a dlms data packet as a nic status word.
        Return True if it was possible, otherwise False.
        """
        nic_status_word = NicStatusWord.from_payload(self.dni.default_client, payload)
        if nic_status_word and nic_status_word.obis_code == NotificationObisEnum.NIC_STATUS_WORD.obis_code:
            logging.info("The message is a NIC status word.")

            # Verify endpoints
            if src_ep.enum != SourceEndpointEnum.ENERGY_METER_PUSH_NOTIFICATION \
                    or dst_ep.enum not in (
                    DestinationEndpointEnum.LEGACY_ON_DEMAND,
                    DestinationEndpointEnum.NIC_STATUS_WORD_PUSH):
                logging.warning("Endpoints for a NIC status word are wrong: found (%d, %d), ",
                                src_ep.value, dst_ep.value)

            if self.NIC_status_cb:
                logging.debug("Xml representation of the message: %s", nic_status_word.xml)

                # Update invocation counter and system title from nic status word informations.
                self.nic_system_title = nic_status_word.nic_system_title
                logging.debug("Set invocation counter of %d meter object to %d.",
                              self.node_id, nic_status_word.US_invocation_counter)
                self.set_invocation_counter(nic_status_word.US_invocation_counter)
                nic_status_word.set_endpoints(src_ep, dst_ep)

                self.add_callback_to_execute(self.NIC_status_cb, self, nic_status_word)
            return True

        return False

    def _handle_notification(self, payload: bytes, src_ep: Endpoint = None, dst_ep: Endpoint = None) -> bool:
        """
        Try to parse a dlms data packet as a notification.
        Return True if it was possible, otherwise False.
        """
        if self.notification_client is not None:
            notification = WirepasNotification.from_payload(self.notification_client, payload)
            if notification:
                # If the message is a notification, the notification callback is called.
                logging.info("The message is a Wirepas notification.")

                # Verify endpoints
                if src_ep.enum != SourceEndpointEnum.ENERGY_METER_PUSH_NOTIFICATION \
                        or dst_ep.enum not in (
                        DestinationEndpointEnum.LEGACY_ON_DEMAND,
                        DestinationEndpointEnum.NAME_PLATE_DETAILS,
                        DestinationEndpointEnum.INSTANTANEOUS_PROFILE,
                        DestinationEndpointEnum.BLOCK_LOAD_PROFILE,
                        DestinationEndpointEnum.DAILY_LOAD_PROFILE,
                        DestinationEndpointEnum.BILLING_PROFILE,
                        DestinationEndpointEnum.EVENT_LOGS,
                        DestinationEndpointEnum.LAST_GASP_NOTIFICATION,
                        DestinationEndpointEnum.ESW_NOTIFICATION,
                        DestinationEndpointEnum.EXPORT_BILLING_PROFILE,
                    ):
                    logging.warning("Endpoints for a Data notification are wrong: found (%d, %d), ",
                                    src_ep.value, dst_ep.value)

                if self.notification_cb is not None:
                    logging.debug("Xml representation of the message: %s", notification.xml)

                    # Print the bits that are set to 1 if the notification is an ESW push.
                    if notification.obis_code == NotificationObisEnum.EVENT_STATUS_WORD_PUSH.obis_code:
                        self.notification_client.log_activated_ESW_bits(notification.value.value)

                    # Check the addresses of the notification.
                    self.notification_client.check_parsed_data(notification)
                    notification.set_endpoints(src_ep, dst_ep)

                    self.add_callback_to_execute(self.notification_cb, self, notification)
                return True

        return False

    def _handle_response(self, payload: bytes, from_NIC_server=False, src_ep: Endpoint = None, dst_ep: Endpoint = None) -> bool:
        """
        Try to parse a dlms data packet as a reponse.
        Return True if it was possible, otherwise False.
        """
        def parse_response(payload, from_NIC_server) -> Response:
            if self.is_waiting_for_response() and not from_NIC_server and self.client is not None:
                response = self.client.get_response_from_msg(payload, estimated_invoke_id)
            elif self.is_waiting_for_response() and from_NIC_server and self.NIC_client is not None:
                response = self.NIC_client.get_response_from_msg(payload, estimated_invoke_id)
            else:
                client = self._create_client(AssociationLevelEnum.US_ASSOCIATION, from_NIC_server)
                response = client.get_response_from_msg(payload, estimated_invoke_id)

            return response

        valid_response_codes = [ErrorCodeEnum.RES_OK, ErrorCodeEnum.RES_MESSAGE_IS_AN_ERROR]
        response: Response = None
        estimated_invoke_id: int = None

        response = parse_response(payload, from_NIC_server)
        if response and response.error_code in valid_response_codes:
            logging.info("The message is a response from the meter.")

            if not (src_ep.enum == SourceEndpointEnum.ENERGY_METER_ON_DEMAND_DATA
                    or self.dni.destination_endpoint == dst_ep.value) and \
                    not (SourceEndpointEnum.TRANSPARENT_MODE.include(src_ep.value)
                         or DestinationEndpointEnum.TRANSPARENT_MODE.include(dst_ep.value)):
                logging.warning("Endpoints for a response are wrong: found (%d, %d), but expected (%d, %d)",
                                src_ep.value, dst_ep.value,
                                SourceEndpointEnum.ENERGY_METER_ON_DEMAND_DATA.endpoint,
                                self.dni.destination_endpoint)

            if self.is_waiting_for_response():
                if self.incremente_invoke_id:
                    estimated_invoke_id = self.invoke_id - 1 & 0xF

                if response.xml:
                    logging.debug("Xml representation of the message: %s", response.xml)

                response.set_endpoints(src_ep, dst_ep)
                self.session.set_data(response)
            return True

        return False

    def get_next_message(self, timeout_s: int):
        """ Return the next message received from the meter/NIC. """
        class Message:
            def __init__(self, data=None, src_ep_value=None, dst_ep_value=None):
                self.data = data
                self.src_ep_value = src_ep_value
                self.dst_ep_value = dst_ep_value

        def new_on_data_received(data, src_ep, dst_ep, *args, **kwargs):
            """ Callback to add the next message received in the buffer and call the normal callback. """
            nonlocal message, data_event
            message = Message(data.data_payload, src_ep.value, dst_ep.value)
            former_data_received_cb(data, src_ep, dst_ep, *args, **kwargs)
            data_event.set()

        message = Message()  # Buffer for the next message to receive from the meter.
        data_event = Event()  # Event to stop waiting when receiving a message

        # Temporarily change the "on data received" callback for the next message received.
        former_data_received_cb, self.on_data_received_cb = self.on_data_received_cb, new_on_data_received
        data_event.wait(timeout_s)
        self.on_data_received_cb = former_data_received_cb
        return message

    def set_invoke_id(self, new_counter: int):
        """ Set and update invoke id of all active clients.

        Args:
            new_counter: invoke id to set to the clients. Int taken between 0 and 15 included.
        """
        self.invoke_id = new_counter & 0xF
        if self.client:
            self.client.set_invoke_id(self.invoke_id)
        if self.NIC_client:
            self.NIC_client.set_invoke_id(self.invoke_id)

    def set_invocation_counter(self, new_counter: int):
        """ Set and update invocation counter of all active clients. """
        self.invocation_counter = new_counter
        if self.client:
            self.client.set_invocation_counter(self.invocation_counter)
        if self.NIC_client:
            self.NIC_client.set_invocation_counter(self.invocation_counter)

    def _update_all_keys(self):
        """ Update keys of the meter configuration which will update the credentials for the clients. """
        if self._keys_validated_to_change:
            new_meter_configuration = deepcopy(self.meter_configuration)
            new_keys = {
                "authentication_key": self._keys_validated_to_change.get("authentication_key", None),
                "block_cipher_key": self._keys_validated_to_change.get("encryption_key", None),
                "key_encryption_key": self._keys_validated_to_change.get("key_encryption_key", None),
                "mr_password": self._keys_validated_to_change.get("mr_password", None),
                "us_password": self._keys_validated_to_change.get("us_password", None),
                "fu_password": self._keys_validated_to_change.get("fu_password", None)
            }

            if new_keys["authentication_key"]:
                new_meter_configuration.authentication_key = new_keys["authentication_key"]
            if new_keys["block_cipher_key"]:
                new_meter_configuration.block_cipher_key = new_keys["block_cipher_key"]
            if new_keys["key_encryption_key"]:
                new_meter_configuration.key_encryption_key = new_keys["key_encryption_key"]
            if new_keys["mr_password"]:
                new_meter_configuration.mr_password = new_keys["mr_password"]
            if new_keys["us_password"]:
                new_meter_configuration.us_password = new_keys["us_password"]
            if new_keys["fu_password"]:
                new_meter_configuration.fu_password = new_keys["fu_password"]

            self.meter_configuration = new_meter_configuration
            logging.info("Keys have been updated for meter %s", self.node_id)
            self._keys_validated_to_change = {}

    def _get_default_keys(self,
                          authentication_key: str = GET_DEFAULT_KEY,
                          block_cipher_key: str = GET_DEFAULT_KEY,
                          dedicated_key: str = GET_DEFAULT_KEY) -> tuple:
        """
        Return the default values for the keys that are uninitialized from the meter configuration
        and the values of those already initialized.
        """
        if authentication_key == GET_DEFAULT_KEY:
            authentication_key = self.meter_configuration.authentication_key
        if block_cipher_key == GET_DEFAULT_KEY:
            block_cipher_key = self.meter_configuration.block_cipher_key
        if dedicated_key == GET_DEFAULT_KEY:
            dedicated_key = self.meter_configuration.dedicated_key

        return authentication_key, block_cipher_key, dedicated_key

    def _get_password(self,
                      authentication_level: AssociationLevelEnum,
                      password: str = GET_DEFAULT_KEY) -> str:
        """
        Return the default value for the password if it is uninitialized
        otherwise returns the password itself.

        Args:
            authentication_level: Authentication level of the client.
            password: Password in hexadecimal. If GET_DEFAULT_KEY is provided,
                the password will be taken from the meter configuration.
        """
        if password != GET_DEFAULT_KEY:
            return password

        return self.meter_configuration.get_password(authentication_level)

    def _create_client(self,
                       authentication_level: AssociationLevelEnum,
                       NIC_server: bool = False,
                       authentication_key: str = GET_DEFAULT_KEY,
                       block_cipher_key: str = GET_DEFAULT_KEY,
                       dedicated_key: str = GET_DEFAULT_KEY,
                       password: str = GET_DEFAULT_KEY) -> Client:
        """
        Create and return a Client with the provided keys and authentication level.
        If passwords are not provided and if the client is supposed to be secured,
        their values are taken from the meter configuration.

        Args:
            authentication_level: Authentication level of the client.
            NIC_server: Boolean to assert if the client needs to exchange with the NIC.
                Default to False.
            authentication_key: Authentication key in hexadecimal for the connection with the meter.
            block_cipher_key: Block cipher key in hexadecimal for the connection with the meter.
            dedicated_key: Dedicated key in hexadecimal for the connection with the meter.
            password: Password in hexadecimal used for the connection with the meter.
        """
        server_address = DLMS_NIC_ADDRESS if NIC_server else DLMS_METER_ADDRESS
        if authentication_level == AssociationLevelEnum.PC_ASSOCIATION:
            client = Client(client_address=authentication_level.client_address,
                            server_address=server_address,
                            nic_system_title=self.nic_system_title)
        else:
            authentication_key, block_cipher_key, dedicated_key = self._get_default_keys(
                authentication_key, block_cipher_key, dedicated_key)
            password = self._get_password(authentication_level, password)

            client = Client(
                client_address=authentication_level.client_address,
                server_address=server_address,
                authentication_key=authentication_key,
                block_cipher_key=block_cipher_key,
                dedicated_key=dedicated_key,
                password=password,
                nic_system_title=self.nic_system_title
            )

            # Set the client system title to be the same as the NIC in passthrough.
            # The system title is not exchanged with the NIC, as there is no AA in passthrough.
            # This system title must be the one advertised by the NIC in its NIC status word.
            if server_address == DLMS_METER_ADDRESS and self.nic_system_title:
                client.set_client_system_title(self.nic_system_title)
            elif server_address == DLMS_NIC_ADDRESS:  # Set the client system title to be an arbitrary value for the NIC connection.
                client.set_client_system_title(NIC_CLIENT_SYSTEM_TITLE)

            if self.invocation_counter is not None:
                client.set_invocation_counter(self.invocation_counter)

        client.set_invoke_id(self.invoke_id)
        return client

    def _set_new_client(self, connection_type: AssociationLevelEnum, NIC_server: bool = False):
        """ Set a new client with the corresponding association.

        Args:
            connection_type: Default to None. Type of connection of the client to set.
                If None, no set is done, but the addresses are verified.
            NIC_server: Boolean to assert if the client needs to exchange with the NIC.
                Default to False (passthrough mode).
        """
        if not self.meter_configuration:
            raise ValueError("The meter configuration must be provided to create a client to communicate with the meter.")

        client = self._create_client(connection_type, NIC_server)
        if NIC_server:
            self._set_NIC_client(client)
        else:
            self._set_client(client)

        return client

    def _verify_NIC_configuration(func):
        """
        Verify that the NIC client does exist.
        This function should be called internally before creating the request for the NIC server.
        """
        @functools.wraps(func)  # Keep the doc and the signature of the wrapped function.
        def wrapper(self, *args, **kwargs):
            if not self.NIC_client:
                raise ValueError("The connection with the NIC has not been established yet. "
                                 "establish_AA_NIC method must be used before sending requests to the nic server.")

            return func(self, *args, **kwargs)

        return wrapper

    def _set_keys_update(self, response):
        """ Update locally the keys that are changed successfully in the NIC server and
        that need to be updated in the next release AA.

        Args:
            response: Response from the NIC server of the set security materials.
        """
        if not response.xml:
            logging.warning("The set security materials didn't work.")
            self._keys_to_change = {}
            return

        # Parse the set security materials results
        set_key_results = re.findall('<DataAccessResult Value="(.*)" />', response.xml)
        if len(self._keys_to_change) != len(set_key_results):
            logging.error("%d keys were queried to be set but found %d results for this set!",
                          len(self._keys_to_change), len(set_key_results))
            return

        for key_name, key_result in zip(self._keys_to_change, set_key_results):
            if key_result == "Success":
                logging.info("The %s will be set to %s the next release AA to the NIC server!",
                             key_name.replace('_', ' '), self._keys_to_change[key_name])
                self._keys_validated_to_change[key_name] = self._keys_to_change[key_name]
            else:
                logging.warning("The %s could not be set!", key_name.replace('_', ' '))

        self._keys_to_change = {}

    def _request(self, request_to_send: bytes, NIC_server: bool = False) -> Response:
        """ Method used for sending message to the meter thanks to the DLMS network interface. """
        # Increment invoke id and invocation counter if they are used.
        if self.incremente_invoke_id:
            self.set_invoke_id(self.invoke_id + 1 & 0xF)

        if self.invocation_counter is not None and \
                self.get_client(NIC_server).authentication_level != AssociationLevelEnum.PC_ASSOCIATION:
            # IC is incremented each time we try to send an encrypted message.
            self.set_invocation_counter(self.invocation_counter + 1)

        response = self.dni.send_request(request_to_send, self, NIC_server)

        # Update the meter object credentials if there are keys that were set to change in the NIC server.
        if self._keys_to_change:
            self._set_keys_update(response)

        return response

    @_verify_NIC_configuration
    def _aarq_request(self) -> Response:
        """ Send an aarq request to the NIC server."""
        aarq_request = self.NIC_client.gx_client.aarqRequest()
        payload = bytes(aarq_request[0])
        return self._request(payload, NIC_server=True)

    @_verify_NIC_configuration
    def _application_association_request(self) -> Response:
        """ Send an application association request to the NIC server."""
        association_request = self.NIC_client.gx_client.getApplicationAssociationRequest()
        if not association_request:
            raise ValueError("Association request could not be generated.")

        payload = bytes(association_request[0])
        return self._request(payload, NIC_server=True)

    # Methods to handle application association with the NIC
    def establish_AA_NIC(self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION) -> bool:
        """
        Establish Application Association with the NIC corresponding to the node id.
        Return True if the connection is established otherwise return False.
        Update the NIC system title for this meter object when the AARE response is parsed.
        """
        try:
            logging.info("Establishing AA with %d with %s association.",
                         self.node_id, connection_type.notation)
            client = self._set_new_client(connection_type, NIC_server=True)
            gx_client = client.gx_client

            # Verify that the password is set for secured association.
            if connection_type != AssociationLevelEnum.PC_ASSOCIATION and not gx_client.getPassword():
                logging.error("NIC client does not have any configured password (%s) for %s association.",
                              client.authentication_level.password_key,
                              client.authentication_level.notation)
                return False

            # Send AARQ request
            logging.info("AARQ request is sent to %d.", self.node_id)
            aare_response = self._aarq_request()
            if not aare_response.payload:
                logging.error("No valid response was received from the AARQ request.")
                return False

            # Parse the aare response
            logging.info("AARE response from %d is being parsed.", self.node_id)
            reply = GXReplyData(RequestTypes.DATABLOCK)
            gx_client.getData(GXByteBuffer(aare_response.payload), reply, None)
            gx_client.parseAareResponse(reply.data)
            if gx_client.sourceSystemTitle:
                self.nic_system_title = bytes(gx_client.sourceSystemTitle)
                self.NIC_client.set_nic_system_title(self.nic_system_title)
                logging.info("NIC system title of the meter %d has been set to %s (%s).",
                             self.node_id, self.nic_system_title.hex(), self.nic_system_title)

            if connection_type == AssociationLevelEnum.PC_ASSOCIATION or \
                    connection_type == AssociationLevelEnum.MR_ASSOCIATION:
                logging.info("Application association has been established with %s", self.node_id)
                return True

            # Send application association request
            logging.info("Application association request is sent to %d.", self.node_id)
            association_response = self._application_association_request()
            if not association_response.payload:
                logging.error("No valid response was received from the Application Association request.")
                return False

            # Parse the application association response
            logging.info("Application association response from %d is being parsed.", self.node_id)
            reply = GXReplyData()
            gx_client.getData(GXByteBuffer(association_response.payload), reply, None)
            gx_client.parseApplicationAssociationResponse(reply.data)
            logging.info("Application association has been established with %s", self.node_id)
            return True
        except Exception as e:
            logging.error("Application association could not be established with %s", self.node_id)
            logging.exception(e)
            return False

    @_verify_NIC_configuration
    def release_AA_NIC(self) -> bool:
        """
        Release Application Association with the NIC corresponding to the node id.
        Return True if the connection is released otherwise return False.
        """
        logging.info("Releasing AA with %d.", self.node_id)
        release_request = self.NIC_client.gx_client.releaseRequest()
        if not release_request:
            raise ValueError("Release request could not be generated.")

        release_request = release_request[0]

        # Check if GuruX library duplicates the last 4 bytes of the release request APDU
        if len(release_request) > 9 \
                and release_request[-4:] == release_request[-8:-4] == bytearray(b'\x03\x80\x01\x00'):
            release_request = release_request[:-4]  # Remove the last 4 bytes.
            release_request[-6] -= 4  # The length of the APDU is 4 less now.

        response = self.dni.send_request(bytes(release_request), self, True)
        self._set_NIC_client(None)  # Delete the actual client, as the connection is closed.
        self._update_all_keys()

        if response.error_code == ErrorCodeEnum.RES_OK and "ReleaseResponse" in response.xml:
            logging.info("Application association with %s has been released.", self.node_id)
            return True

        logging.error("Release AA response is invalid.")
        return False

    # Private generic methods to query the meter
    def _generic_create_get_request(self, gx_client, gurux_object: GXDLMSObject, attribute_id: int) -> bytes:
        """
        Create a get request from gurux client based on COSEM attribute ids.

        Args:
            gurux_object: Gurux object to create the get request from.
            attribute_id: Attribute id of the object to get.
        """
        return bytes(gx_client.read(gurux_object, attribute_id)[0])

    def _generic_create_set_request(self, gx_client, gurux_object: GXDLMSObject,
                                    value_to_set: Any, attribute_id: int) -> bytes:
        """
        Create a set request from gurux client based on COSEM attribute ids.

        Args:
            gurux_object: Gurux object to create the set request from.
            value_to_set: Value to be set.
            attribute_id: Attribute id of the object to set.
        """
        gx_client.updateValue(gurux_object, attribute_id, value_to_set)
        return bytes(gx_client.write(gurux_object, attribute_id)[0])

    # Public methods to query the meter
    def get_meter_data(
        self,
        obis_code: str,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
    ) -> Response:
        """ Send a get data request to the meter.

        Args:
            obis_code: Obis code of the COSEM data object.
            connection_type: Default to US association. Connection type (association level).
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSData(ln=obis_code), attribute_id=2)
        logging.info("A get request of a data object is being sent to the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def set_meter_data(
        self,
        obis_code: str,
        value_to_set: Any,
        attribute_type: DataType,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
    ) -> Response:
        """ Send a set data request to the meter.

        Args:
            obis_code: Obis code of the COSEM data object.
            value_to_set: Value to set.
            attribute_type: Attribute type of the object.
            connection_type: Default to US association. Connection type (association level).
        """
        client = self._set_new_client(connection_type, False)
        gurux_object = GXDLMSData(ln=obis_code)
        gurux_object.setDataType(2, attribute_type)
        payload = self._generic_create_set_request(client.gx_client,
                                                   gurux_object=gurux_object,
                                                   value_to_set=value_to_set,
                                                   attribute_id=2)

        logging.info("A set request of a data object is being sent to the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    @_verify_NIC_configuration
    def get_NIC_data(self, obis_code: str) -> Response:
        """ Send a get data request to the NIC.

        Args:
            obis_code: Obis code of the COSEM data object.
            attribute_id: Attribute id of the object to get.
        """
        payload = self._generic_create_get_request(
                self.NIC_client.gx_client, GXDLMSData(ln=obis_code), attribute_id=2)
        logging.info("A get request of a data object is being sent to the NIC server.")
        return self._request(payload, NIC_server=True)

    @_verify_NIC_configuration
    def set_NIC_data(self,
                     obis_code: str,
                     value_to_set: Any,
                     attribute_type: DataType) -> Response:
        """ Send a set request to the NIC for a Data COSEM object value.

        Args:
            obis_code: Obis code of the Data object.
            value_to_set: Value to set to the Data object in the NIC.
                It must be compatible with the attribute type input.
            attribute_type: Attribute type defined by GuruX to describe the type of the value to set.
        """
        gurux_object = GXDLMSData(ln=obis_code)
        gurux_object.setDataType(2, attribute_type)
        payload = self._generic_create_set_request(self.NIC_client.gx_client,
                                                   gurux_object=gurux_object,
                                                   value_to_set=value_to_set,
                                                   attribute_id=2)

        logging.info("A set request of a data object is being sent to the NIC server.")
        return self._request(payload, NIC_server=True)

    def get_meter_register(
            self, obis_code: str,
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Send a request to get a register attribute value of the meter.

        Args:
            connection_type: Default to US association. Connection type (association level).
            attribute_id: Default to 2. Attribute id of the CODEM object to get a value from.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(
                client.gx_client, GXDLMSRegister(ln=obis_code), attribute_id)
        logging.info("A get register of an object is being sent to the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_disconnect_control_data(
            self,
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Send a request to get a disconnect control data attribute value of the meter.

        Args:
            connection_type: Default to US association. Connection type (association level).
            attribute_id: Default to 2. Attribute id of the CODEM object to get a value from.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(
            client.gx_client, GXDLMSDisconnectControl(ln="0.0.96.3.10.255"), attribute_id)
        logging.info("Send a get disconnect control data of the attribute %d to the meter.", attribute_id)
        return self._request(payload, NIC_server=False)

    def get_meter_image_transfer_attrib(self, attribute_id: int = 6) -> Response:
        """ Send a request to get the image tranfer attribute value of the meter.

        Args:
            attribute_id: Default to 6. Attribute id of the image transfer to get a value from.
        """
        client = self._set_new_client(AssociationLevelEnum.FU_ASSOCIATION, False)
        payload = self._generic_create_get_request(
                client.gx_client, GXDLMSImageTransfer(ln="0.0.44.0.0.255"), attribute_id)
        logging.info("A get image transfer attribute id %s request is being sent to the meter in passthrough.",
                     attribute_id)
        return self._request(payload, NIC_server=False)

    def meter_image_transfer_verify(self):
        """ Send a image transfer verify request to the meter. """
        client = self._set_new_client(AssociationLevelEnum.FU_ASSOCIATION, False)
        image_tranfer = GXDLMSImageTransfer()
        logging.info("An image transfer image verify request is being sent to the meter in passthrough.")
        payload = bytes(image_tranfer.imageVerify(client.gx_client)[0])
        return self._request(payload, NIC_server=False)

    def set_NIC_security_material_from_config(self, meter_config: MeterConfiguration) -> Response:
        """ Set security material to the NIC server with sending a list of keys
        encoded in hexadecimal in one message that are from a meter configuration object.
        The keys will be updated in the Meter object instance when releasing AA.

        Args:
            meter_config: Meter configuration.
        """
        return self.set_NIC_security_material_with_list(
            mr_password=meter_config.mr_password,
            us_password=meter_config.us_password,
            fu_password=meter_config.fu_password,
            global_unicast_enc_key=meter_config.block_cipher_key,
            authentication_key=meter_config.authentication_key,
            key_encryption_key=meter_config.key_encryption_key)

    @_verify_NIC_configuration
    def set_NIC_security_material_with_list(self,
                                            mr_password: str = None,
                                            us_password: str = None,
                                            fu_password: str = None,
                                            global_unicast_enc_key: str = None,
                                            authentication_key: str = None,
                                            key_encryption_key: str = None) -> Response:
        """ Set security material to the NIC server for the node with node_id
        with sending a list of keys encoded in hexadecimal in one message.
        The keys will be updated in the Meter object instance when releasing AA.

        ..warning::
            release_AA_NIC method must be called directly after this request to update the credentials.

        Args:
            mr_password: meter MR association HLS secret in hexadecimal to send.
            us_password: meter US association HLS secret in hexadecimal to send.
            fu_password: meter FU association HLS secret in hexadecimal to send.
            global_unicast_enc_key: meter global unicast encryption key in hexadecimal to send.
            authentication_key: meter authentication key in hexadecimal to send.
            key_encryption_key: meter key encryption key in hexadecimal to send.
        """
        # Encrypt the keys to send with the actual key encryption key.
        ciphering_kek = self.meter_configuration.key_encryption_key

        if (global_unicast_enc_key or authentication_key or key_encryption_key) and not ciphering_kek:
            raise ValueError("A ciphering key encryption key must be set in the meter configuration to encrypt the keys.")

        if self.NIC_client.authentication_level != AssociationLevelEnum.US_ASSOCIATION:
            raise ValueError(f"The keys can't be set in {self.NIC_client.authentication_level.notation} association !")

        keys_to_change = {}  # Keys to be changed when releasing the association.

        GXWriteItem.getDataType = lambda self: self.target.getDataType(self.index)
        list_obis_value = []
        if mr_password is not None:
            list_obis_value.append({"obis": "0.0.40.0.2.250", "value": mr_password})
            keys_to_change['mr_password'] = mr_password
        if us_password is not None:
            list_obis_value.append({"obis": "0.0.40.0.3.250", "value": us_password})
            keys_to_change['us_password'] = us_password
        if fu_password is not None:
            list_obis_value.append({"obis": "0.0.40.0.5.250", "value": fu_password})
            keys_to_change['fu_password'] = fu_password
        if global_unicast_enc_key is not None:
            wrapped_key = self.NIC_client.gx_client.encrypt(bytes.fromhex(ciphering_kek),
                                                            bytes.fromhex(global_unicast_enc_key))
            list_obis_value.append({"obis": "0.0.43.0.0.251", "value": wrapped_key})
            keys_to_change['encryption_key'] = global_unicast_enc_key
        if authentication_key is not None:
            wrapped_key = self.NIC_client.gx_client.encrypt(bytes.fromhex(ciphering_kek),
                                                            bytes.fromhex(authentication_key))
            list_obis_value.append({"obis": "0.0.43.0.0.253", "value": wrapped_key})
            keys_to_change['authentication_key'] = authentication_key
        if key_encryption_key is not None:
            wrapped_key = self.NIC_client.gx_client.encrypt(bytes.fromhex(ciphering_kek),
                                                            bytes.fromhex(key_encryption_key))
            list_obis_value.append({"obis": "0.0.43.0.0.254", "value": wrapped_key})
            keys_to_change['key_encryption_key'] = key_encryption_key

        assert len(list_obis_value), \
            "Secrets or keys must be provided to setup the NIC/meter security material"
        self._keys_to_change = keys_to_change

        write_item_list = []
        for data in list_obis_value:
            data_object = GXDLMSData(data["obis"])
            data_object.setDataType(2, DataType.OCTET_STRING)
            self.NIC_client.gx_client.updateValue(data_object, 2, data["value"])

            write_item = GXWriteItem(attributeIndex=2)
            write_item.target = data_object
            write_item_list.append(write_item)

        payload = bytes(self.NIC_client.gx_client.writeList(write_item_list)[0])
        logging.info("Set NIC server security material.")
        return self._request(payload, NIC_server=True)

    def get_meter_clock(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Send a get request to the meter in passthrough to get the clock.

        Example:

        .. code-block:: python

            clock_resp = meter.get_meter_clock()
            print("Time of the meter: ", meter.client.to_datetime(clock_resp.value))

        Args:
            connection_type: Default to US association. Connection type (association level).
            attribute_id: Default to 2. Attribute id of the clock object to get.
        """

        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSClock("0.0.1.0.0.255"), attribute_id)
        logging.info("Send a get clock request to the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    @_verify_NIC_configuration
    def set_NIC_clock(self, value: datetime) -> Response:
        """ Send a set request to the NIC to set the clock in the meter
        after the NIC compensate travel time of the message.

        Example:

        .. code-block:: python

            import pytz
            from datetime import datetime, timedelta

            # Set the local time in Asia/Kolkata timezone.
            # Check `pytz.all_timezones` to know all the available timzeones in pytz library.
            meter.set_NIC_clock(datetime.now(pytz.timezone('Asia/Kolkata')))

        Args:
            value: A datetime object representing the clock to be set in the meter.
                For example, you can use `value=datetime.now()` to send local current time to the NIC.
            attribute_id: Attribute id of the object to set.
        """
        payload = self._generic_create_set_request(
            self.NIC_client.gx_client, GXDLMSClock("0.0.1.0.0.255"), value, attribute_id=2)
        logging.info("Send a set clock request to the NIC server.")
        return self._request(payload, NIC_server=True)

    def disconnect_meter(self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION) -> Response:
        """ Send a disconnect request to the meter. """
        client = self._set_new_client(connection_type, False)
        gurux_object = GXDLMSDisconnectControl(ln="0.0.96.3.10.255")
        payload = bytes(gurux_object.remoteDisconnect(client.gx_client)[0])
        logging.info("Send a disconnect request to the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def reconnect_meter(self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION) -> Response:
        """ Send a reconnect request to the meter. """
        client = self._set_new_client(connection_type, False)
        gurux_object = GXDLMSDisconnectControl(ln="0.0.96.3.10.255")
        payload = bytes(gurux_object.remoteReconnect(client.gx_client)[0])
        logging.info("Send a reconnect request to the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_profile_generic_by_attribute(
            self, obis_code: str,
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Generic method to request meter profile generic by attributes.

        Note:
            Generic profiles buffers should be requested with their associated method.
            Check also :py:meth:`~Meter.get_meter_billing_profile`, :py:meth:`~Meter.get_meter_name_plate_details`.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSProfileGeneric(ln=obis_code), attribute_id)
        logging.info("Get a profile generic attribute %d from the meter in passthrough.", self.node_id)
        return self._request(payload, NIC_server=False)

    def get_meter_profile_generic_by_entries(
            self, obis_code: str,
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            index: int = 1, count: int = 1, columns=None) -> Response:
        """ Generic method to request meter profile generic by entries.

        Note:
            Generic profiles buffers should be requested with their associated method.
            Check also :py:meth:`~Meter.get_meter_instantaneous_profile`, :py:meth:`~Meter.get_meter_voltage_related_events_log`,
            :py:meth:`~Meter.get_meter_current_related_events_log`, :py:meth:`~Meter.get_meter_power_related_events_log`,
            :py:meth:`~Meter.get_meter_transaction_related_events_log`, :py:meth:`~Meter.get_meter_other_events_log`,
            :py:meth:`~Meter.get_meter_non_rollover_events_log`, :py:meth:`~Meter.get_meter_control_events_log`.
        """
        client = self._set_new_client(connection_type, False)
        pg = GXDLMSProfileGeneric(ln=obis_code)
        request = client.gx_client.readRowsByEntry(pg=pg, index=index, count=count, columns=columns)[0]
        payload = bytes(request)
        logging.info("Get a profile generic by entries from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_profile_generic_by_range(
            self, obis_code: str, start: datetime, end: datetime,
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            columns=None) -> Response:
        """ Generic method to request meter profile generic by range.

        Note:
            Generic profiles buffers should be requested with their associated method.
            Check also :py:meth:`~Meter.get_meter_block_load_profile`, :py:meth:`~Meter.get_meter_daily_load_profile`.
        """
        client = self._set_new_client(connection_type, False)
        pg = GXDLMSProfileGeneric(ln=obis_code)
        request = client.gx_client.readRowsByRange(pg=pg, start=start, end=end, columns=columns)[0]
        payload = bytes(request)
        logging.info("Get a profile generic by range from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_action_scheduler(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.MR_ASSOCIATION,
            attribute_id: int = 4) -> Response:
        """ Get a activity calendar object attribute value from the meter in passthrough.

        Args:
            connection_type: Default to MR association. Connection type (association level).
            attribute_id: Default to 4. Attribute id of the COSEM object to get value from.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSActionSchedule(ln="0.0.15.0.0.255"), attribute_id)
        logging.info("Get an action scheduler object attribute from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_activity_calendar(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.MR_ASSOCIATION,
            attribute_id: int = 10) -> Response:
        """ Get a activity calendar object attribute value from the meter in passthrough.

        Args:
            connection_type: Default to MR association. Connection type (association level).
            attribute_id: Default to 10. Attribute id of the COSEM object to get value from.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSActivityCalendar(ln="0.0.13.0.0.255"), attribute_id)
        logging.info("Get an activity calendar object attribute from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_limiter(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 4) -> Response:
        """ Get a limiter object attribute value from the meter in passthrough.

        Args:
            connection_type: Default to US association. Connection type (association level).
            attribute_id: Default to 4. Attribute id of the COSEM object to get value from.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSLimiter(ln="0.0.17.0.0.255"), attribute_id)
        logging.info("Get a limiter object attribute from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def set_meter_limiter(
            self, value_to_set: Any,
            attribute_type: DataType = DataType.UINT32,
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 4) -> Response:
        """ Set a limiter object attribute value from the meter in passthrough.

        Args:
            value_to_set: Value to set. It should be aligned with the attribyte type input.
            attribute_type: Default to DataType.UINT32. Date type of the attribute value to set.
            connection_type: Connection type (association level).
            attribute_id: Default to 4. Attribute id of the COSEM object to get value from.
        """
        client = self._set_new_client(connection_type, False)
        gurux_object = GXDLMSLimiter(ln="0.0.17.0.0.255")
        gurux_object.setDataType(attribute_id, attribute_type)
        payload = self._generic_create_set_request(client.gx_client,
                                                   gurux_object=gurux_object,
                                                   value_to_set=value_to_set,
                                                   attribute_id=attribute_id)

        logging.info("Set a limiter object attribute of the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_push_setup(
            self, obis_code: str = "0.7.25.9.0.255",
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Get a push setup object attribute from the meter in passthrough.

        Args:
            obis_code: Obis code of the COSEM Push Setup object.
            connection_type: Connection type (association level).
            attribute_id: attribute id of the COSEM object to get value from.
        """
        client = self._set_new_client(connection_type, False)
        payload = self._generic_create_get_request(client.gx_client, GXDLMSPushSetup(ln=obis_code), attribute_id)
        logging.info("Get a push setup object attribute from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    def get_meter_list_supported_obis(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.PC_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Send a get request of the AssociationLogicalName object of the meter for an association.

        ..warning::
            Meter response can be heavy and might not be returned by the NIC.

        Args:
            connection_type: Association to query the AssociationLogicalName.
            attribute_id: attribute id to request (default to 2 to query the object list).
        """
        client = self._set_new_client(connection_type, False)
        gurux_object = GXDLMSAssociationLogicalName(ln="0.0.40.0.0.255")
        payload = self._generic_create_get_request(client.gx_client, gurux_object, attribute_id)
        logging.info("Get a push setup object attribute from the meter in passthrough.")
        return self._request(payload, NIC_server=False)

    @_verify_NIC_configuration
    def get_NIC_list_supported_obis(self, attribute_id: int = 2) -> Response:
        """ Send a get request of the AssociationLogicalName object of the NIC server.

        Args:
            attribute_id: attribute id to request (default to 2 to query the object list).
        """
        gurux_object = GXDLMSAssociationLogicalName(ln="0.0.40.0.100.255")
        payload = self._generic_create_get_request(self.NIC_client.gx_client, gurux_object, attribute_id)
        logging.info("Get all supported obis from the NIC server.")
        return self._request(payload, NIC_server=True)

    def get_meter_serial_number(
        self, connection_type: AssociationLevelEnum = AssociationLevelEnum.PC_ASSOCIATION
    ) -> Response:
        """ Get the serial number of the meter in passthrough. """
        logging.info("Get the serial number of the meter in passthrough.")
        return self.get_meter_data(obis_code="0.0.96.1.0.255", connection_type=connection_type)

    def get_meter_device_ID(
        self, connection_type: AssociationLevelEnum = AssociationLevelEnum.MR_ASSOCIATION
    ) -> Response:
        """ Get the device ID of the meter in passthrough. """
        logging.info("Get the device ID of the meter in passthrough.")
        return self.get_meter_data(obis_code="0.0.96.1.2.255", connection_type=connection_type)

    def get_meter_ESW1(
        self, connection_type: AssociationLevelEnum = AssociationLevelEnum.MR_ASSOCIATION,
    ) -> Response:
        """ Get the Event Status Word 1 of the meter in passthrough. """
        logging.info("Get the Event Status Word 1 of the meter in passthrough.")
        resp = self.get_meter_data(obis_code="0.0.94.91.18.255",
                                   connection_type=connection_type)

        if resp.error_code == ErrorCodeEnum.RES_OK and resp.value.value:
            self.notification_client.log_activated_ESW_bits(resp.value.value)

        return resp

    def get_meter_profile_generic_capture_objects(
        self, pg: ProfileGeneric,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
    ) -> Response:
        """ Get a profile generic capture objects of the meter in passthrough. """
        logging.info("Get the %s profile capture objects of the meter in passthrough.",
                     pg.name.title().replace('_', ' '))
        return self.get_meter_profile_generic_by_attribute(
            obis_code=pg.obis_code, connection_type=connection_type, attribute_id=3)

    def get_meter_profile_generic_scaler(
        self, pg: ProfileGeneric,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
    ) -> Response:
        """ Get a profile generic profile scaler of the meter in passthrough. """
        if not pg.scaler_obis_code:
            raise ValueError(f"{pg} has no scaler, therefore it can't be requested.")

        logging.info("Get the %s scaler profile capture objects of the meter in passthrough.",
                     pg.name.title().replace('_', ' '))
        return self.get_meter_profile_generic_by_attribute(
            obis_code=pg.scaler_obis_code, connection_type=connection_type, attribute_id=2)

    def get_meter_profile_generic_event_code(
        self, pg: ProfileGeneric,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
    ) -> Response:
        """ Get a profile generic profile event code of the meter in passthrough. """
        if not pg.event_code_obis:
            raise ValueError(f"{pg} has no event code, as it is not an event logs.")

        logging.info("Get the %s profile event code of the meter in passthrough.",
                     pg.name.title().replace('_', ' '))
        return self.get_meter_data(obis_code=pg.event_code_obis, connection_type=connection_type)

    def get_meter_instantaneous_profile(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Get the instantaneous profile by querying COSEM object attribute of the meter in passthrough. """
        logging.info("Get the instantaneous profile of the meter in passthrough.")
        return self.get_meter_profile_generic_by_attribute(
            obis_code=ProfileGeneric.INSTANTANEOUS.obis_code,
            connection_type=connection_type,
            attribute_id=attribute_id)

    def get_meter_block_load_profile(
        self, start: datetime, end: datetime,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the block load profile by time range of the meter in passthrough. """
        logging.info("Get the block load profile of the meter in passthrough.")
        return self.get_meter_profile_generic_by_range(
            obis_code=ProfileGeneric.BLOCK_LOAD.obis_code, start=start,
            end=end, connection_type=connection_type, columns=columns)

    def get_meter_daily_load_profile(
        self, start: datetime, end: datetime,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the daily load profile by time range of the meter in passthrough. """
        logging.info("Get the daily load profile of the meter in passthrough.")
        return self.get_meter_profile_generic_by_range(
            obis_code=ProfileGeneric.DAILY_LOAD.obis_code, start=start,
            end=end, connection_type=connection_type, columns=columns)

    def get_meter_billing_profile(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the billing profile by entries of the meter in passthrough. """
        logging.info("Get the billing profile of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.BILLING.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_voltage_related_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the voltage related events log by entries of the meter in passthrough. """
        logging.info("Get the voltage related events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.VOLTAGE_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_current_related_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the current related events log by entries of the meter in passthrough. """
        logging.info("Get the current related events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.CURRENT_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_power_related_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the power related events log by entries of the meter in passthrough. """
        logging.info("Get the power related events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.POWER_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_transaction_related_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the transaction related events log by entries of the meter in passthrough. """
        logging.info("Get the transaction related events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.TRANSACTION_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_other_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the other events log by entries of the meter in passthrough. """
        logging.info("Get the other events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.OTHER_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_non_rollover_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the non rollover events log by entries of the meter in passthrough. """
        logging.info("Get the non rollover events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.NON_ROLLOVER_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns)

    def get_meter_control_events_log(
        self, index: int = 1, count: int = 1,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ) -> Response:
        """ Get the control events log by entries of the meter in passthrough. """
        logging.info("Get the control events log of the meter in passthrough.")
        return self.get_meter_profile_generic_by_entries(
            obis_code=ProfileGeneric.CONTROL_EVENTS_LOG.obis_code,
            connection_type=connection_type, index=index, count=count, columns=columns
        )

    def get_meter_name_plate_details(
            self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
            attribute_id: int = 2) -> Response:
        """ Get the name plate details by attribute of the meter in passthrough. """
        logging.info("Get the name plate details of the meter in passthrough.")
        return self.get_meter_profile_generic_by_attribute(
            obis_code=ProfileGeneric.NAME_PLATE.obis_code,
            connection_type=connection_type,
            attribute_id=attribute_id)

    def get_NIC_instantaneous_push_interval(self) -> Response:
        """ Get the instantaneous push interval of the NIC server. """
        logging.info("Get the instantaneous push interval of the NIC server.")
        return self.get_NIC_data(obis_code="0.100.25.9.0.250")

    def set_NIC_instantaneous_push_interval(self, interval_minutes: int = 30) -> Response:
        """ Set the instantaneous push interval of the NIC.

        Note: The NIC will change this period after sending its next instantaneous profile push.

        Args:
            interval_minutes: Push interval of the instantaneous profiles in minutes.
                It must be chosen between 15 and 1440 minutes.
            attribute_id: Attribute id of the object to set.
        """
        assert 15 <= interval_minutes <= 1440, \
               "Instantaneous capture period value should be set between 15 and 1440 minutes," \
               f" but found: {interval_minutes}"

        logging.info("Set the instantaneous push interval of the NIC server.")
        return self.set_NIC_data(obis_code="0.100.25.9.0.250",
                                 value_to_set=interval_minutes,
                                 attribute_type=DataType.UINT16)

    def get_NIC_push_enable_configuration(self) -> Response:
        """ Get the push enable configuration object bit string of length 12
        from the NIC and following these rules:

        1 char per profile. 0 To Disable, 1 to Enable:

        - Char 0: Instantaneous profile push disable/enable
        - Char 1: Block load profile push disable/enable
        - Char 2: Daily load profile push disable/enable
        - Char 3: Billing profile push disable/enable
        - Char 4: Voltage related events log profile push disable/enable
        - Char 5: Current related events log profile push disable/enable
        - Char 6: Power related events log profile push disable/enable
        - Char 7: Transaction related events log profile push disable/enable
        - Char 8: Other events log profile push disable/enable
        - Char 9: Non-rollover events log profile push disable/enable
        - Char 10: Control events log profile push disable/enable
        - Char 11: Export Billing profile push disable/enable

        Note: char 0 must be placed on the left and so on...
        """
        logging.info("Get the push enable configuration of the NIC server.")
        return self.get_NIC_data(obis_code="0.101.25.9.0.250")

    def set_NIC_push_enable_configuration(self, value_to_set: str) -> Response:
        """ Set the push enable configuration object of the NIC server.

        value_to_set: String of size 12:

        1 char per profile. 0 To Disable, 1 to Enable:

        - Char 0: Instantaneous profile push disable/enable
        - Char 1: Block load profile push disable/enable
        - Char 2: Daily load profile push disable/enable
        - Char 3: Billing profile push disable/enable
        - Char 4: Voltage related events log profile push disable/enable
        - Char 5: Current related events log profile push disable/enable
        - Char 6: Power related events log profile push disable/enable
        - Char 7: Transaction related events log profile push disable/enable
        - Char 8: Other events log profile push disable/enable
        - Char 9: Non-rollover events log profile push disable/enable
        - Char 10: Control events log profile push disable/enable
        - Char 11: Export Billing profile push disable/enable

        Note: char 0 must be placed on the left and so on...
        """
        if not isinstance(value_to_set, str) and not isinstance(value_to_set, GXBitString):
            raise AttributeError(f"Push enable configuration should be set as a string but found {type(value_to_set)}")
        elif len(value_to_set) != 12:
            raise AttributeError("push enable configuration should be a string of length 12 "
                                 f"but a string of length {len(value_to_set)} has been found")

        logging.info("Set the push enable configuration of the NIC server.")
        return self.set_NIC_data(obis_code="0.101.25.9.0.250", value_to_set=value_to_set,
                                 attribute_type=DataType.BITSTRING)

    def get_meter_block_load_capture_period(
        self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
    ) -> Response:
        """ Get the block load capture period from the meter in passthrough. """
        logging.info("Get the block load capture period of the meter in passthrough.")
        return self.get_meter_data(obis_code="1.0.0.8.4.255", connection_type=connection_type)

    def set_meter_block_load_capture_period(
        self, value_to_set: int = 900,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
    ) -> Response:
        """ Set the block load capture period of the meter in passthrough.

        Note: The NIC will change its query period to get the block load after its next query.

        Args:
            value_to_set: Period of the block load in seconds.
                It must be chosen between 900, 1800, and 3600 seconds
            connection_type: Connection type (association level).
            attribute_id: Attribute id of the object to set.
        """
        if value_to_set not in [900, 1800, 3600]:
            logging.warning("Block load profile capture period should be set to 900, 1800 or 3600s. Found: %d", value_to_set)

        logging.info("Set the block load capture period of the meter in passthrough.")
        return self.set_meter_data(
            obis_code="1.0.0.8.4.255", value_to_set=value_to_set,
            attribute_type=DataType.UINT16, connection_type=connection_type)

    def get_meter_daily_load_capture_period(
        self, connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
    ) -> Response:
        """ Get the daily load capture period from the meter in passthrough. """
        logging.info("Get the daily load capture period of the meter in passthrough.")
        return self.get_meter_data(obis_code="1.0.0.8.5.255", connection_type=connection_type)

    def get_NIC_invocation_counter(self) -> Response:
        """ Get NIC invocation counter and update the value locally so that it can be reused for the next request.

        Example of how to get the invocation counter of the NIC server:
        .. code-block:: python

            if meter.establish_AA_NIC():
                result = meter.get_NIC_invocation_counter()
                meter.release_AA_NIC()
        """
        logging.info("Get the invocation counter of the NIC server.")
        res = self.get_NIC_data(obis_code="0.0.43.1.3.255")
        if res.error_code == ErrorCodeEnum.RES_OK and res.value:
            logging.debug("Set invocation counter of %d meter object to %d.", self.node_id, res.value)
            self.set_invocation_counter(res.value)

        return res

    def set_NIC_transparent_mode_configuration(self, activate: bool):
        """ Set the transparent mode configuration data attribute 2 in the NIC server.

        If set to True: Optimized communication is disabled and transparent mode communication is enabled.
        If set to False: Optimized communication is enabled and transparent mode communication is disabled.

        .. warning::
            Once the transparent mode is activated, the requests to the passthrough
            and to the NIC server do not work anymore.
        """
        logging.info("Set %s to the transparent mode configuration in the NIC server.", activate)
        res = self.set_NIC_data(obis_code="0.200.25.9.0.250",
                                value_to_set=activate,
                                attribute_type=DataType.BOOLEAN)

        return res

    def set_NIC_billing_day(self, day: int):
        """ Send a set billing day to the NIC server.

        Args:
            day: Must be an int between 1 and 31 representing the day of the month
        """
        assert isinstance(day, int) and 1 <= day <= 31, \
            "Day must be an int between 1 and 31 representing the day of the month"

        logging.info("Send a set billing day to the NIC server.")
        return self.set_NIC_data(obis_code="0.102.25.9.0.250", value_to_set=day,
                                 attribute_type=DataType.UINT8)

    def send_meter_md_reset(
            self, obis_code: str = "0.0.10.0.1.255",
            connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION
        ):
        """ Send a md reset in passthrough to the meter."""
        client = self._set_new_client(connection_type, False)
        script_table = GXDLMSScriptTable(obis_code)
        payload = bytes(script_table.execute(client.gx_client, GXDLMSScript())[0])
        return self._request(payload, NIC_server=False)

    def set_NIC_registration_status(self, registred: bool = True):
        """ Method to set the NIC registration object in the meter to True.
        """
        logging.info("Set the registration status in the NIC server to %s.", registred)
        res = self.set_NIC_data(obis_code="0.0.96.0.1.255",
                                value_to_set=registred,
                                attribute_type=DataType.BOOLEAN)

        return res

    def do_registration(self, send_keys: bool, new_configuration: MeterConfiguration=None,
                        set_registration: bool = False) -> bool:
        """ Method to ease the registration of the meter.
        If set, establish the connection in PC with the NIC to set a new configuration.
        Then, if set establish the connection in US with the NIC.

        If the keys can not be set, the registration status will not be set.

        Args:
            send_keys: Boolean to assert that a new configuration need to be set.
            new_configuration: New meter configuration of the NIC status that needs to be set.
            set_registration: Boolean to assert that the registration need to be set to True.
        """
        logging.info("Register meter %d", self.node_id)
        if send_keys or set_registration:
            error_code = ErrorCodeEnum.RES_OK
            if self.establish_AA_NIC():
                if send_keys:
                    logging.info("Set a new configuration in the NIC!")
                    res_set_keys = self.set_NIC_security_material_from_config(new_configuration)

                    error_code = res_set_keys.error_code
                    if error_code == ErrorCodeEnum.RES_OK:
                        logging.info(f"The meter {self.node_id} has been provisioned!")
                    else:
                        logging.info(f"Provisioning failed !")
                        self.release_AA_NIC()
                        return False
                else:
                    res_set_keys = ErrorCodeEnum.RES_OK

                if set_registration and error_code == ErrorCodeEnum.RES_OK:
                    self.set_NIC_registration_status(True)

                self.release_AA_NIC()
                return True

    def read_meter_by_range_selector(
        self,
        profile_generic: ProfileGeneric,
        start,
        end,
        range_value_type=DataType.OCTET_STRING,
        object_to_sort=None,
        connection_type: AssociationLevelEnum = AssociationLevelEnum.US_ASSOCIATION,
        columns=None
    ):
        """Send a read events logs by range selector in pass-through.

        Example of uses:

        Example 1: Read block load profiles by clock
            meter.read_meter_by_range_selector(ProfileGeneric.BLOCK_LOAD, datetime.now(), datetime.now() - timedelta(hours=1))

        Example 2: Read current events log by event log sequences
            from gurux_dlms.enums import DataType
            from gurux_dlms.objects import GXDLMSData

            meter.read_meter_by_range_selector(
                ProfileGeneric.CURRENT_EVENTS_LOG, 5, 10,
                range_value_type=DataType.UINT32,
                object_to_sort=GXDLMSData("0.0.96.15.1.255")
            )

        Example 3: Read selected columns from the current events log
            from gurux_dlms.enums import DataType
            from gurux_dlms.objects import GXDLMSCaptureObject, GXDLMSClock, GXDLMSData

            meter.read_meter_by_range_selector(
                ProfileGeneric.CURRENT_EVENTS_LOG, 5, 10,
                range_value_type=DataType.UINT32, object_to_sort=GXDLMSData("0.0.96.15.1.255"),
                columns=[(GXDLMSClock(), GXDLMSCaptureObject(2, 0))]
            )
        """
        gx_client = self._set_new_client(connection_type, False).gx_client

        pg = GXDLMSProfileGeneric(profile_generic.obis_code)

        pg.buffer = list()
        gx_client.settings.resetBlockIndex()

        # Refer to IEC 62056-6-2:2017 page 62 Parameters for selective access to the buffer attribute
        # Add AccessSelector
        # Range selector
        buff = GXByteBuffer(51)
        buff.setUInt8(0x01)
        buff.setUInt8(DataType.STRUCTURE)
        buff.setUInt8(0x04)

        # Field 1/4 restricting_object
        buff.setUInt8(DataType.STRUCTURE)
        buff.setUInt8(0x04)

        if object_to_sort:
            ot = object_to_sort.objectType
            ln = object_to_sort.logicalName
        else:
            ot = ObjectType.CLOCK
            ln = "0.0.1.0.0.255"
            if not isinstance(start, GXDateTime):
                start = GXDateTime(start)
            if not isinstance(end, GXDateTime):
                end = GXDateTime(end)

        _GXCommon.setData(gx_client.settings, buff, DataType.UINT16, ot)
        _GXCommon.setData(gx_client.settings, buff, DataType.OCTET_STRING, _GXCommon.logicalNameToBytes(ln))
        _GXCommon.setData(gx_client.settings, buff, DataType.INT8, 2)
        _GXCommon.setData(gx_client.settings, buff, DataType.UINT16, 0)

        # Field 2/4 range start value
        _GXCommon.setData(gx_client.settings, buff, range_value_type, start)

        # Field 3/4 range end value
        _GXCommon.setData(gx_client.settings, buff, range_value_type, end)

        # Field 4/4 selected columns
        buff.setUInt8(DataType.ARRAY)
        if not columns:
            # Empty array to catch all columns
            buff.setUInt8(0x00)
        else:
            _GXCommon.setObjectCount(len(columns), buff)
            for it in columns:
                buff.setUInt8(DataType.STRUCTURE)
                buff.setUInt8(4)
                _GXCommon.setData(gx_client.settings, buff, DataType.UINT16, it[0].objectType)
                _GXCommon.setData(gx_client.settings, buff, DataType.OCTET_STRING, _GXCommon.logicalNameToBytes(it[0].logicalName))
                _GXCommon.setData(gx_client.settings, buff, DataType.INT8, it[1].attributeIndex)
                _GXCommon.setData(gx_client.settings, buff, DataType.UINT16, it[1].dataIndex)

        payload = bytes(gx_client._read(pg.name, ObjectType.PROFILE_GENERIC, 2, buff)[0])
        return self._request(payload, NIC_server=False)
