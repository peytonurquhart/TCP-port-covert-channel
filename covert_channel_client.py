import pyshark

INTERFACE = 'Wi-Fi'                 # The local network interface both parties will use.
SNIFF_LIMIT = None                  # The maximum amount of packets checked before a handshake is found.
DST_TARGET = '100.100.100.100'      # The agreed upon web address the CovertServer will be attempting to establish a connection with.
HANDSHAKE_PORT = 10001              # The agreed upon port that will be paired with 'DSD_TARGET' by the CovertServer to handshake the CovertClient
SEGMENT_LENGTH = 4                  # The length of each segment (port number) used by the CovertServer to convey information, sniffed by the CovertClient

DST_DEFAULT = '0.0.0.0'  
TCP_ITEM = 'TCP'
IP_ITEM = 'IP'
DESTINATION_FIELD = 'dst'
TCP_RETRANSMISSION_FIELD = 'analysis_retransmission'
TCP_DST_PORT_FIELD = 'dstport'

#
#   CovertClient listens to outgoing HTTP requests on a local network interface such as 'Wi-Fi',
#   these packets are not routed to the CovertClient, rather they are routed to an external web address
#   like 'www.google.com'.
#
#   Using the CovertServer, one may make HTTP requests to an agreed upon external web address, attempting
#   to connect with different port numbers. When a request from the CovertServer is made to the external
#   web address with the agreed upon 'handshake port (len > 4)', a connection with the CovertClient is established.
#
#   Once a connection is established, the CovertServer will attempt to connect to the external web adress 2
#   more times. The first attempt will use a port number describing the length of the integer encoded data that will be
#   transmitted. The second attempt will use a port number to describe the number of segments that will be transmitted.
#
#   The CovertClient will now continue to sniff for packets routed to the agreed upon external web adress, attempt
#   to connect from the CovertServer will use a port number that describes the integer encoded message sequentially.
#
#   All port numbers the CovertServer uses are concatinated until the number of segments specified by the server is
#   reached. Then, these sequential port numbers are decoded in the message that was sent. Each port number used
#   as part of the message body must be of length < 5. All ports of length > 5 are in the domain of possible handshake
#   port numbers, and if a handshake port number is detected, the transmission restarts.
#
#   CovertClient completely ignores TCP retransmissions on the local network interface.
#
#   Prerequisites: You must have WireShark installed to use this, because it uses executable produced by wireshark
#   to help sniff for packets on the network.
#
class CovertClient:
    def __init__(self, handshake_port, segment_length, log_progress=True):
        self.handshake_port = handshake_port
        self.segment_length = segment_length
        self.log_progress = log_progress
        self.buffer = ""
        self.amount_recieved = 0
        self.shaken_hands = False
        self.incoming_length = None
        self.incoming_segments = None
        self.num_segments_recieved = 0

    # Begin sniffing for packets sent by the client to the external web address
    #   interface: local network interface used by both parties, e.g. 'Wi-Fi'
    #   limit: max packets to search on the network until the agreed upon handshake packet is found
    #   dst_default: default web address for packets that dont contain a web address (must be different than dst_target)
    #   dst_target: the agreed upon external web address the CovertServer will try to connect to
    def sniff(self, interface, limit, dst_default, dst_target):
        capture = pyshark.LiveCapture(interface=interface)
        packet_stream = capture.sniff_continuously(packet_count=limit)
        for packet in packet_stream:
            if self.dst_matches(packet, dst_target, dst_default) and not self.is_suspected_retransmission(packet):
                if self.on_target_detected(packet):
                    yield self.decode(int(self.buffer))

    # Method called when a target packet which matches web address 'dst_target' and port 'handshake_port' is found.
    def on_target_detected(self, packet):
        message = self.get_dst_port(packet, 0)
        if self.is_handshake(message):
            self.clear()
            self.shaken_hands = True
            self.log('Incoming message detected: 0.00 %')
            return
        if self.incoming_length == None:
            self.incoming_length = int(message)
            self.log(f'Incoming message encoded length: {self.incoming_length}')
            return
        if self.incoming_segments == None:
            self.incoming_segments = int(message)
            self.log(f'Incoming message segments: {self.incoming_segments}')
            return
        message = str(message)
        if self.should_append_leading_zero(message):
            message = '0' + message
        self.buffer += message
        self.amount_recieved += len(message)
        self.num_segments_recieved += 1
        self.log(f'Segment: {self.num_segments_recieved} recieved: {str(self.num_segments_recieved / self.incoming_segments * 100)[0:5]} %')
        if self.num_segments_recieved == self.incoming_segments:
            return True
        return False

    # Reset the channel
    def clear(self):
        self.buffer = ""
        self.amount_recieved = 0
        self.shaken_hands = False
        self.incoming_length = None
        self.incoming_segments = None
        self.num_segments_recieved = 0

    # Decode the encoded message found while sniffing packets
    def decode(self, i):
        return (i.to_bytes(((i.bit_length() + 7) // 8), byteorder='big')).decode()

    # Is the packet found a handshake packet?
    def is_handshake(self, message):
        return int(message) == int(self.handshake_port)

    # Call before adding to self buffer
    def should_append_leading_zero(self, message):
        # if last segment
        if self.num_segments_recieved == self.incoming_segments - 1:
            if (len(self.buffer) + len(str(message))) < self.incoming_length:
                return True
        else:
            if len(message) < self.segment_length:
                return True
        return False
     
    # Does the destination for a packet match the 'dst_target' destination?
    def dst_matches(self, packet, dst_target, dst_default):
        dst_observed = self.get_dst_address(packet, dst_default)
        return str(dst_observed) == str(dst_target)

    # Is this packet a TCP retransmission?
    def is_suspected_retransmission(self, packet):
        tcp_layer = packet.__getitem__(TCP_ITEM)
        if tcp_layer and tcp_layer.get_field_value(TCP_RETRANSMISSION_FIELD):
            return True
        return False

    # Get the destination port number for a packet
    def get_dst_port(self, packet, default=0):
        try:
            tcp_layer = packet.__getitem__(TCP_ITEM)
            dst_port = tcp_layer.get_field_value(TCP_DST_PORT_FIELD)
        except:
            return default
        return dst_port

    # Get the destination address for a packet
    def get_dst_address(self, packet, default):
        try:
            ip_layer = packet.__getitem__(IP_ITEM)
            dest_addr = ip_layer.get_field_value(DESTINATION_FIELD)
        except:
            return default
        return dest_addr

    # Print to stdout 'log_progress'
    def log(self, args):
        if self.log_progress:
            print(args)

def main():

    # Create the client that will accept handshakes when a packet if found using 'handshake_port'
    client = CovertClient(handshake_port=HANDSHAKE_PORT, segment_length=SEGMENT_LENGTH)

    # Begin listening for all types of messages on the LAN interface
    for message in client.sniff(INTERFACE, SNIFF_LIMIT, DST_DEFAULT, DST_TARGET):
        print(f'\nMessage found: {message}\n')

if __name__ == '__main__':
    main()