# Copyright 2023 Wirepas Ltd licensed under Apache License, Version 2.0
#
# See file LICENSE for full license details.
#
import logging
from random import choice
from time import sleep, time
from typing import Callable, Dict, List
from wirepas_mqtt_library import WirepasNetworkInterface

from .association_level_enum import AssociationLevelEnum
from .client import Client
from .endpoint_enum import DestinationEndpointEnum, Endpoint, SourceEndpointEnum
from .error_code_enum import ErrorCodeEnum
from .meter import Meter, MeterConfiguration
from .response import Response


class DLMSNetworkInterface:
    def __init__(self,
                 wni: WirepasNetworkInterface,
                 default_NIC_status_cb: Callable = None,
                 default_notification_cb: Callable = None,
                 default_unparsed_cb: Callable = None,
                 network: int = None,
                 nodes: List[int] = None,
                 destination_endpoint: int = None):
        """ Class used to communicate with the meters inside a Wirepas network.
        It redirects the messages from gateways to the corresponding meter objects.
        Futhermore, it also updates its network informations (gateway and sink ids)
        when receiving a message so that meters are always up-to-date.
        When a DLMS message is received from an unknown node,
        the associated meter object is created with default callbacks before redirecting its message.

        Args:
            wni: Wirepas network interface to communicate with the NIC.
            default_NIC_status_cb: Default 'NIC status word' callback of the meters that it creates.
                This callback will be called when receiving a NIC status word from this meter.
                The callback must take a meter object and the NicStatusWord object in argument.
            default_notification_cb: Default 'notification' callback of the meters that it creates
                This callback will be called when receiving a data notification from this meter.
                The callback must take a meter object and a WirepasNotification object in arguments.
            default_unparsed_cb: Default 'unparsed' callback of the meters that it creates.
                This callback will be called when receiving a message from this meter that it can't parse.
                The callback must take the meter object and the payload as bytes in arguments.
            network: Network address of the NICs in the Wirepas network to get the message from.
                Default to None not to filter any received messages.
            nodes: Node address of the NICs in the Wirepas network to get the message from.
                Default to None not to filter any received messages.
        """
        # Sets the callbacks
        self.default_NIC_status_cb = default_NIC_status_cb
        self.default_notification_cb = default_notification_cb
        self.default_unparsed_cb = default_unparsed_cb

        # Sets the MQTT configuration
        self.nodes = nodes
        self.wni = wni
        self.wni.register_data_cb(self._on_data_received_cb,
                                  network=network)

        # Sets the meter informations
        self.meters: Dict[int, Meter] = {}

        # Sets an unsecured client to try parsing NIC status word notifications
        self.default_client = Client()

        # Set the destination endpoint for this object randomly between the expected values if not set.
        if destination_endpoint is None:
            destination_endpoint = choice(DestinationEndpointEnum.ON_DEMAND_DATA.endpoint)

        self.destination_endpoint = destination_endpoint
        logging.info("Destination endpoint for on demand requests set to %d", self.destination_endpoint)

        # Wait for the MQTT connection.
        if not self._wait_for_connection():
            raise TimeoutError("It is impossible to connect to the MQTT")

    def _wait_for_connection(self, timeout: int = 10) -> bool:
        """ Wait for the connection with the MQTT client.
        Return True the Wirepas network interface is connected otherwise return False.

        Args:
            timeout: Timeout in seconds to wait for the connection with the MQTT client.
        """
        start = time()
        logging.info("Waiting for the Wirepas network interface to be connected...")
        while (not self.wni._mqtt_client.is_connected() and time() - start < timeout):
            sleep(0.1)

        if not self.wni._mqtt_client.is_connected():
            logging.error("The Wirepas network interface could not connect.")
            return False

        logging.info("The Wirepas network interface is connected.")
        return True

    def _on_data_received_cb(self, data) -> None:
        """
        Callback to be called when data are received from the network.
        If the sender is not known, a new meter object is created for this node.
        Then, the corresponding meter object will receive the data.

        Note: If the meter is created with the default callbacks and its meter configuration remains empty.
              The meter informations need to be update with its method update_meter if needed.
        """
        node_id = data.source_address
        if self.nodes and node_id not in self.nodes:
            return

        meter = self.get_meter(node_id)
        if meter:
            meter.update_network_settings(gateway_id=data.gw_id, sink_id=data.sink_id)

        if data.source_endpoint not in SourceEndpointEnum.get_all_values() \
                or data.destination_endpoint not in DestinationEndpointEnum.get_all_values():
            return  # Not a DLMS packet
        elif not meter:  # Reference the new meters.
            logging.debug("First message from %d has been received. The associated meter object is being created.", node_id)
            meter = self.create_meter(node_id, meter_configuration=MeterConfiguration(),
                                      gateway=data.gw_id, sink=data.sink_id)

        meter.on_data_received_cb(data, src_ep=Endpoint(data.source_endpoint, True),
                                  dst_ep=Endpoint(data.destination_endpoint, False))

    def send_request(self, payload: bytes, meter: Meter, NIC_server: bool = False) -> Response:
        """
        Send the message content to the network and return the meter response.
        The returned response contains a timeout error code if the response was not received in time.

        Args:
            payload: Request content to send.
            meter: Meter object sending the data to the network.
            NIC_server: Default to False. Boolean asserting if the message is sent for the NIC server
                to display its content.
        """
        gateway, sink = meter.get_network_settings()
        if not isinstance(payload, bytes):
            logging.error("Payloads to send must be in bytes, found a type: %s", type(payload))
            return Response(ErrorCodeEnum.RES_ERROR, None, None)

        assert gateway and sink, \
               "Meter object must be attached to a gateway and a sink id to send request, " \
               f"found: (gateway_id, sink_id) = {(gateway, sink)}"

        logging.info("TX: Sending a message of size %d to node 0x%X(%d) through gateway %s/%s and endpoints (%d, %d)",
                     len(payload), meter.node_id, meter.node_id, gateway, sink,
                     SourceEndpointEnum.ENERGY_METER_ON_DEMAND_DATA.endpoint,
                     self.destination_endpoint)
        logging.debug("TX: %s", payload.hex())

        # Print the xml representation of the DLMS message.
        client = meter.get_client(NIC_server)
        if not client:  # Create a client to translate the DLMS message
            client = meter._create_client(AssociationLevelEnum.US_ASSOCIATION, NIC_server)

        xml = client.message_to_xml(payload.hex())
        if xml is not None:
            logging.debug(xml)
        else:
            logging.debug("The request could not be translated.")

        # Send the DLMS message to the meter.
        with meter.session.get_lock():
            meter.session.prepare_reception()
            try:
                self.wni.send_message(gateway, sink, meter.node_id,
                                      SourceEndpointEnum.ENERGY_METER_ON_DEMAND_DATA.endpoint,
                                      self.destination_endpoint, payload)
            except TimeoutError:
                logging.error("A timeout occured when sending the message to the MQTT broker!")
                return Response(ErrorCodeEnum.RES_TIMEOUT, None, None)

            # Wait for the response of the request
            meter.session.wait_for_message(meter.response_timeout_s)

        # Verify the event was set (a message has been received)
        if not meter.session.has_received_a_response():
            logging.error("A timeout occured while waiting for response from node %d", meter.node_id)
            return Response(ErrorCodeEnum.RES_TIMEOUT, None, None)

        return meter.session.get_received_response()

    def create_meter(self,
                     node_id: int,
                     meter_configuration: MeterConfiguration,
                     nic_system_title: bytes = None,
                     gateway: str = None,
                     sink: str = None,
                     NIC_status_cb: Callable = None,
                     notification_cb: Callable = None,
                     unparsed_cb: Callable = None,
                     response_timeout_s: int = 20) -> Meter:
        """ Create a meter and add it to the reference of this class for the provided node id.
        This method is automatically called with default parameters
        when a message is received from an unknown meter to reference it.
        The meter configuration needs to be updated after that. (check :py:meth:`~Meter.update_meter`)

        Args:
            node_id: Node id of the NIC associated to the meter.
            meter_configuration: Ciphering meter configuration.
            gateway: Current gateway id of the NIC associated to the meter.
            sink: Current sink id of the NIC associated to the meter.
            NIC_status_cb: Callback that will be called when receiving a NIC status word notification.
                The callback must take the node_id as an integer, the gateway_id as a string,
                the sink_id as a string and the WirepasNotification object in argument.
                If not provided, the default_NIC_status_cb callback is used.
            notification_cb: The callback that will be called when receiving a data notification.
                The callback must take a meter object and a WirepasNotification object in arguments.
                If not provided, the default_notification_cb callback is used.
            unparsed_cb: The callback that will be called when being unable to parse a payload.
                The callback must take a meter object and the payload in bytes in arguments.
                If not provided, the default_unparsed_cb callback is used.
            response_timeout_s: timeout in seconds to wait for receiving responses.
        """
        NIC_status_cb = NIC_status_cb or self.default_NIC_status_cb
        notification_cb = notification_cb or self.default_notification_cb
        unparsed_cb = unparsed_cb or self.default_unparsed_cb

        new_meter = Meter(dni=self, node_id=node_id, meter_configuration=meter_configuration,
                          nic_system_title=nic_system_title, NIC_status_cb=NIC_status_cb,
                          notification_cb=notification_cb, unparsed_cb=unparsed_cb,
                          response_timeout_s=response_timeout_s)

        if new_meter.node_id in self.meters:
            logging.warning("Meter with node id %d already exist in the DLMS network interface.",
                          new_meter.node_id)
            return self.meters[new_meter.node_id]

        self.meters[new_meter.node_id] = new_meter
        new_meter.update_network_settings(gateway_id=gateway, sink_id=sink)
        return new_meter

    def delete_meter(self, node_id: int):
        """ Delete a meter from the DLMS network interface references. """
        meter = self.get_meter(node_id)
        if meter:
            meter.terminate()
            self.meters.pop(node_id)
        else:
            logging.warning("meter %d was not found when trying to delete it.", node_id)

    def get_meter(self, node_id: int):
        """ Get the meter with the provided node id. Return None if the meter is not found. """
        return self.meters.get(node_id, None)

    def get_meters(self) -> List[Meter]:
        """ Get all known meters. """
        return list(self.meters.values())
