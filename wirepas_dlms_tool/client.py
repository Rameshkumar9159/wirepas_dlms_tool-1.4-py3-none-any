# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
import logging
import struct

from gurux_dlms import GXByteBuffer, GXDLMSXmlClient, TranslatorSimpleTags
from gurux_dlms.enums import Authentication, DataType, ErrorCode, InterfaceType, Security, Standard

from .association_level_enum import AssociationLevelEnum
from .error_code_enum import ErrorCodeEnum
from .parsed_data import ParsedData
from .response import Response

DLMS_METER_ADDRESS: int = 1
DLMS_NIC_ADDRESS: int = 100
NIC_CLIENT_SYSTEM_TITLE: bytes = b"CLI12345"  # System title used by the client to connect to the NICs.


class Client:
    def __init__(self,
                 client_address: int = 16,
                 server_address: int = 1,
                 authentication_key: str = None,
                 block_cipher_key: str = None,
                 dedicated_key: str = None,
                 password: str = None,
                 nic_system_title: bytes = None):
        """ Interface handling a Gurux client capable of decoding/encoding messages
        from/to the NIC and the meter in passthrough with ciphering options if needed.
        It handles the creation of the client, but it also sets up the translator and
        it is able to convert the DLMS data payloads into readable XML strings and
        is able to check the correctness of a meter response.

        Args:
            client_address: Client address of the DLMS backend used.
                            It depends on the authentication level chosen.
            server_address: Server address of the server.
                            It depends the message are sent to the NIC or the meter.
            authentication_key: Authentication key in hexadecimal for the connection with the meter.
            block_cipher_key: Block cipher key in hexadecimal for the connection with the meter.
            dedicated_key: Dedicated key in hexadecimal for the connection with the meter.
            password: Password in hexadecimal used for the connection with the meter.
            nic_system_title: System title of the NIC in bytes.
        """

        self.gx_client = self._get_unsecured_gx_client()
        if nic_system_title:
            self.set_nic_system_title(nic_system_title)
            self.set_client_system_title(nic_system_title)

        self.set_addresses(client_address=client_address,
                           server_address=server_address)

        self.authentication_level = AssociationLevelEnum.from_client_address(client_address)
        self.set_authentication(self.authentication_level.authentication)

        self.set_ciphering_parameters(
            authentication_key=authentication_key,
            block_cipher_key=block_cipher_key,
            dedicated_key=dedicated_key,
            password=password,
        )

    def _get_unsecured_gx_client(self) -> GXDLMSXmlClient:
        """
        Generate and return an unsecured Gurux DLMS Client capable of sending
        unsecured messages and containing a translator.
        """
        gx_client = GXDLMSXmlClient()
        gx_client.translator.comments = True

        # Set the secure client parameters as we cannot pass the arguments in GXDLMSXmlClient.
        gx_client.setInterfaceType(InterfaceType.WRAPPER)
        gx_client.setStandard(Standard.INDIA)
        gx_client.useUtc2NormalTime = True

        return gx_client

    def set_nic_system_title(self, nic_system_title: bytes = None):
        assert isinstance(nic_system_title, bytes), \
            f"NIC system title must be a bytes type, but found {type(nic_system_title)}."
        assert len(nic_system_title) == 8, \
            f"NIC system title must be of length 8, but found {len(nic_system_title)}."

        self.gx_client.translator.serverSystemTitle = nic_system_title

    def set_client_system_title(self, client_system_title: bytes = None):
        assert isinstance(client_system_title, bytes), \
            f"The system title must be a bytes type, but found {type(client_system_title)}."
        assert len(client_system_title) == 8, \
            f"The system title must be of length 8, but found {len(client_system_title)}."

        self.gx_client.translator.systemTitle = client_system_title
        self.gx_client.setServerSystemTitle(client_system_title)

        # Update client system title from the new translator configuration.
        self.gx_client.translator.getCiphering(self.gx_client.settings, True)

    def set_invoke_id(self, invoke_id: int):
        self.gx_client.settings.invokeId = invoke_id

    def set_invocation_counter(self, invocation_counter: int):
        self.gx_client.ciphering.invocationCounter = invocation_counter

    def set_addresses(self, client_address: int = 16, server_address: int = 1):
        """ Set the client and server addresses of a gurux client. """
        self.gx_client.setClientAddress(client_address)
        self.gx_client.serverAddress = server_address

    def set_authentication(self, authentication: Authentication):
        """ Set the authentication level of the gurux client. """
        if isinstance(authentication, Authentication):
            self.gx_client.setAuthentication(authentication)
        else:
            logging.error("Authentication level could not be set, as "
                          "the input does not have the good type. Found: %s",
                          type(authentication))

    def set_ciphering_parameters(self,
                                 authentication_key: str = None,
                                 block_cipher_key: str = None,
                                 dedicated_key: str = None,
                                 password: str = None) -> GXDLMSXmlClient:
        """
        Set ciphering settings of the Gurux DLMS Client from hexadecimal ciphering keys and password.
        """
        if password:
            self.gx_client.setPassword(GXByteBuffer.hexToBytes(password))

        # Reset keys, so that we are sure to set all the keys in the next code block
        self.gx_client.translator.authenticationKey = None
        self.gx_client.translator.blockCipherKey = None
        self.gx_client.translator.dedicatedKey = None

        # set the security keys
        if authentication_key:
            self.gx_client.translator.authenticationKey = GXByteBuffer.hexToBytes(authentication_key)
        if block_cipher_key:
            self.gx_client.translator.blockCipherKey = GXByteBuffer.hexToBytes(block_cipher_key)
            # if not dedicated_key:
            #     dedicated_key = "%032x" % randrange(16**32)
            #     logging.debug("The dedicated key was randomly assigned to %s", dedicated_key)
            if dedicated_key:
                self.gx_client.translator.dedicatedKey = GXByteBuffer.hexToBytes(dedicated_key)

        # set the security according to the keys input
        if authentication_key and block_cipher_key:
            self.gx_client.translator.security = Security.AUTHENTICATION_ENCRYPTION
        elif block_cipher_key:
            self.gx_client.translator.security = Security.ENCRYPTION
        elif authentication_key:
            self.gx_client.translator.security = Security.AUTHENTICATION
        else:
            self.gx_client.translator.security = Security.NONE

        # apply security keys to the client translator
        self.gx_client.translator.getCiphering(self.gx_client.settings, True)

    def update_keys(self, configuration):
        """ Update the keys of the Client object from a new configuration
        if the authentication level is not PC.

        Args:
            configuration: Meter configuration to use to setup the new client keys.
        """
        client_address = self.gx_client.getClientAddress()
        authentication_level = AssociationLevelEnum.from_client_address(client_address)
        if authentication_level != AssociationLevelEnum.PC_ASSOCIATION:
            password = configuration.get_password(authentication_level)
            self.set_ciphering_parameters(authentication_key=configuration.authentication_key,
                                          block_cipher_key=configuration.block_cipher_key,
                                          password=password)

    def to_datetime(self, time: bytearray):
        """ Transform a byte array from gurux to a datetime interpretion of the time."""
        if time:
            return self.gx_client.changeType(time, DataType.DATETIME, True).value

    def get_addresses_from_payload(self, payload: bytes) -> tuple:
        """ Get client and server addresses from a payload.
        Return (-1, -1) if the payload is too short to be DLMS.
        """
        if len(payload) < 11:
            logging.error("DLMS payload is too short.")
            return (-1, -1)

        source_address = struct.unpack(">H", payload[2:4])[0]
        target_address = struct.unpack(">H", payload[4:6])[0]
        return (source_address, target_address)

    def message_to_xml(self, msg: str) -> str:
        """ Decrypt an encoded message thanks to the client's translator
        and returns the corresponding xml string.
        Return None if the payload could not be translated.

        Args:
            msg (str): message to decode in hexadecimal.
        """
        try:
            return self.gx_client.translator.messageToXml(GXByteBuffer(msg))
        except Exception:
            return

    def check_parsed_data(self, parsed_data: ParsedData, invoke_id: int = None) -> bool:
        """
        Check the invoke id and the source/target addresses of the parsed dlms
        message from a message and return whether they have the good values.

        Args:
            parsed_data: Parsed data to verify settings.
            invoke_id: Invoke id of the sent message. It should only be used for on demand query.
                If it is provided, the response should have the same invoke id value.
                The value should be contained between 0 and 15.
        """
        result = True
        if invoke_id is not None and parsed_data.invoke_id_and_priority \
                and parsed_data.invoke_id_and_priority & 0xF != invoke_id:
            logging.warning("The response has a different invoke id than expected. Expected: %s, found: %s",
                            invoke_id, parsed_data.invoke_id_and_priority & 0xF)
            result = False

        if parsed_data.source_address != self.gx_client.serverAddress or \
                parsed_data.target_address != self.gx_client.getClientAddress():
            logging.warning(
                "Expected DLMS source/destination of the data: (%s, %s), found: (%s, %s)",
                self.gx_client.serverAddress, self.gx_client.getClientAddress(),
                parsed_data.source_address, parsed_data.target_address)
            result = False

        return result

    def get_response_from_msg(self, payload: bytes, invoke_id: int = None) -> Response:
        """ Return the xml of the content of a valid DLMS message.
        If the message is not valid, it will return None.

        Args:
            payload: Payload of the message in bytes to validate.
            invoke_id: Invoke id of the sent message. If it is provided,
                the response should have the same invoke id value.
                The value should be contained between 0 and 15.
        """
        if payload is None:
            logging.error("A timeout occured when waiting for the response!")
            return Response(ErrorCodeEnum.RES_TIMEOUT, None, None)

        message = payload.hex()
        parsed_data = ParsedData.from_payload(self, payload)

        # Check if the xml contains Gurux translation errors directly in the xml.
        if not parsed_data or parsed_data.xml is None:
            logging.error("The following message could not be translated: %s", message)
            return Response(ErrorCodeEnum.RES_ERROR, None, payload)

        # If the data value has been parsed, return it in the Response object.
        xml = parsed_data.xml
        value = parsed_data.value

        # Check if the message is valid
        error_comments = ["Error: Failed to descypt data.", "Block is not complete.", "Invalid", "UnacceptableFrame"]
        for error_comment in error_comments:
            if error_comment in xml:
                logging.error("The message is invalid and could not be translated: %s", message)
                return Response(ErrorCodeEnum.RES_INVALID_MESSAGE, xml, payload, value)

        # Check if the xml translated secured message content if it is ciphered.
        secured_tag_list = {}
        TranslatorSimpleTags.getGloTags(secured_tag_list)
        TranslatorSimpleTags.getDedTags(secured_tag_list)
        for secured_tag in secured_tag_list.values():
            if secured_tag in xml:
                if not ("<!--Decrypt data:" in xml or "<!--Decrypted data:" in xml):
                    logging.error("The message could not be decrypted when trying to translate: %s", message)
                    return Response(ErrorCodeEnum.RES_INVALID_KEYS, xml, payload, value)
                break

        # Check if the message is a response error from the meter.
        if parsed_data.msg_error_code != ErrorCode.OK or "ServiceError" in xml:
            if parsed_data.msg_error_code == ErrorCode.OK:
                logging.error("The response of the meter is a service error.")
            else:
                logging.error("The response of the meter is a '%s' error.",
                              parsed_data.msg_error_code.name)

            return Response(ErrorCodeEnum.RES_MESSAGE_IS_AN_ERROR, xml, payload, value)

        # Check if the addresses and the invoke id are well set.
        self.check_parsed_data(parsed_data, invoke_id)

        return Response(ErrorCodeEnum.RES_OK, xml, payload, value)

    def log_activated_ESW_bits(self, ews_string_value):
        """ Log all bits that are set to 1 from the ESW bit string value. """
        esw_bit_values = {
            0: "R Phase - Voltage missing",
            1: "Y Phase - Voltage missing",
            2: "B Phase - Voltage missing",
            3: "Over voltage in any phase",
            4: "Low voltage in any phase",
            5: "Voltage unbalance",
            6: "R Phase current reverse (Import type only)",
            7: "Y Phase current reverse (Import type only)",
            8: "B Phase current reverse (Import type only)",
            9: "Current unbalance",
            10: "Current bypass/short",
            11: "Over current in any phase",
            12: "Very low PF",
            51: "Earth Loading",
            81: "Influence of permanent magnet or ac/dc electromagnet",
            82: "Neutral disturbance - HF, dc or alternate method",
            83: "Meter cover opening",
            84: "Meter load disconnected/Meter load connected",
            85: "Last Gasp - Occurrence",
            86: "First Breath - Restoration",
            87: "Increment in billing counter (Manual/MRI reset)"
        }

        if len(ews_string_value) < 88:
            logging.warning("ESW string is too short to enumerate its bits.")
            return

        for index, esw_field in esw_bit_values.items():
            if ews_string_value[index] == '1':
                logging.debug("The following ESW field is activated : %s", esw_field)
