import socket
import multiprocessing
import math
import sys
import time

TIMEOUT = .25
HOST = "100.100.100.100" 
REQUEST = f"GET / HTTP/1.1\r\nHost:{HOST}\r\n\r\n"
HANDSHAKE_PORT = 10001

#
#   CovertServer sends messages over a covert channel to a CovertClient. Messages are conveyed
#   by determining an external web address and handshake port number that will be known by both the
#   CovertServer and the CovertClient. The client must be sniffing packets on a local area connection which
#   the server is also connected to. The server will then attempt to connect to the pre-determined external web address
#   using a port number equal to the agreed upon HANDSHAKE_PORT number. Once the server does this, a connection is established.
#
#   The server will then make two more attempts to connect to the predetermined external web address. Attempt 1 will be done
#   using a port number equal to the length of the integer encoded data that will be transmitted. Attempt 2 will be done using
#   a port number equal to the number of segments that will be transmitted.
#
#   The server will then continue to attempt to connect to the agreed upon external web address, each time using a port number
#   that will sequentially convey the integer encoded message until the specified number of segments has been reached.
#
#   When the server wants to send a new message to the client, it simply must attempt to connect to the external web address
#   again using the predetermined handshake port number.
#

# Encode a string message into an integer, which can be parsed again as a string and
# be used as port numbers for attempted connection.
def encode(s):
    return int.from_bytes(str(s).encode(), byteorder='big')

# Get the number of segments that must be used for a specific message
def get_num_segments(i_encoded):
    return math.ceil(len(str(i_encoded)) / 4)

# To be used by a child process to send the raw data to the external web address using
# a specific port to convery information
def transmit(host, port, request):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    client.connect((host,port))
    client.send(request.encode())

# Creates a child process to send a message to the external web address, the process
# is terminated after a specified timeout. All retransmissions are ignored by the
# client anyways.
def send_on_child_proc(host, port, timeout, request):
    t = multiprocessing.Process(target=transmit, args=(host, port, request))
    t.start()
    time.sleep(timeout)
    t.terminate()

# Send a handshake message to be sniffed by the client, and establish a covert connection
def send_handshake():
    send_on_child_proc(HOST, HANDSHAKE_PORT, TIMEOUT, REQUEST)

# Send the number of segments
def send_num_segments(i_encoded):
    segments = get_num_segments(i_encoded)
    send_on_child_proc(HOST, segments, TIMEOUT, REQUEST)
    return segments

# Send the length of encoded data
def send_len(i_encoded):
    send_on_child_proc(HOST, len(str(i_encoded)), TIMEOUT, REQUEST)

# Send all segments
def send_all_segments(i_encoded):
    msg = str(i_encoded)
    index = 0
    for i in range(0, get_num_segments(i_encoded)):
        send_on_child_proc(HOST, int(msg[index:index+4]), TIMEOUT, REQUEST)
        index += 4

# Send the message
def send_message(s):
    i = encode(s)
    print(i)
    send_handshake()
    send_len(i)
    send_num_segments(i)
    send_all_segments(i)

def main():
    if len(sys.argv) < 2:
        raise Exception('You must specify a message')
    message = ""
    for i in range(1, len(sys.argv)):
        message += ' ' + sys.argv[i]
    send_message(message)

if __name__ == '__main__':
    main()