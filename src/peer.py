import pickle
import argparse
import hashlib
import util.bt_utils as bt_utils
import socket
import struct
import util.simsocket as simsocket
import select
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
HEADER_LEN = struct.calcsize("HBBHHII")
TEAM_NUM = 1
MAGIC = 52035
WHOHAS, IHAVE, GET, DATA, ACK, DENIED = (0, 1, 2, 3, 4, 5)

output_file = None
received_chunk = dict()
downloading_chunkhash = ""


def process_download(sock:socket.socket, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global output_file
    global received_chunk
    global downloading_chunkhash
    
    output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        index, datahash_str = cf.readline().strip().split(" ")
        received_chunk[datahash_str] = bytes()
        downloading_chunkhash = datahash_str

        # hex_str to bytes
        datahash = bytes.fromhex(datahash_str)
        download_hash = download_hash + datahash

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte type |1byte team|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    # Magic, Team, Type, hlen, plen, Seq, Ack
    # H: unsigned short, B: unsigned char, I: unsigned int
    whohas_header = struct.pack("HBBHHII", socket.htons(MAGIC),TEAM_NUM, WHOHAS, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(download_hash)), socket.htonl(0), socket.htonl(0))
    whohas_packet = whohas_header+download_hash
    print(whohas_packet)
    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            # [id] [ip] [port]
            sock.sendto(whohas_packet, (p[1], int(p[2])))

def process_inbound_udp(sock:socket.socket):
    # Receive pkt
    global sending_chunkhash
    global config
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(
        "HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    
    if Type==WHOHAS:
        # check if self has the chunk
        whohas_chunkhash = data[:20]
        chunkhash_str = bytes.hex(whohas_chunkhash)
        sending_chunkhash = chunkhash_str
        if chunkhash_str in config.haschunks:
            ihave_header = struct.pack("HBBHHII",socket.htons(52305), TEAM_NUM, IHAVE, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(whohas_chunkhash)), socket.htonl(0), socket.htonl(0))
            ihave_pkt = ihave_header+whohas_chunkhash
            sock.sendto(ihave_pkt, from_addr)
    elif Type==IHAVE:
        pass


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument(
        '-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument(
        '-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument(
        '-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
