import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import time
"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

#packet information
MAX_PAYLOAD = 1024
CHUNK_DATA_SIZE = 512*1024
BUF_SIZE = 1400
HEADER_LEN = struct.calcsize("HBBHHII")
TEAM_NUM = 1
MAGIC = 52035
WHOHAS, IHAVE, GET, DATA, ACK, DENIED = (0, 1, 2, 3, 4, 5)

#这个peer的信息
output_file = None
sending_to_peer_num = 0 # how many peers its sending data to
received_chunk = dict()#这个peer需要下载的chunk，key为hash,value为数据
chunk_belong_to=dict()#这个chunk决定由谁下载，用于判断是否已经下载完成，key为hash，value为identify

identity_dict=dict()#用于通过ip和port查找identity {(ip,port): identity}


downloading_chunkhash = dict()#可能需要是一个dict，对应每个address，原来为一个chunkhash的str，应该存储每个address对应下载的东西的hash值
timer=dict()#对于每个的计时器 {identity:[True/False,time.time()]}
queue=dict()#对于其他每个peer的队列 用list模拟queue {identity:[]}
eRTT=dict()#对于跟其他每个peer的rtt估计 {identity: value}
base_number=dict()#对于跟每个peer的队列的确认序号 {identity: value}
N=15 #暂时设定窗口长度为15,窗口中的包全部已经发送

class pkt_in_queue:#对于每个存在queue中的数据结构
    def __init__(self,packet,send_time,ack_number=0,retran_number=0,receive=False):
        self.packet = packet #这个包的全部信息，包括header和body
        self.ack_number = ack_number #这个包被ack的次数，用于快速重传。不应被清0，快速重传应当仅进行一次，剩下的应该都通过超时进行重传
        self.retran_number = retran_number #重传次数，用于计算重传的包的超时时间
        self.receive=receive # 确认这个包是否已经被接收到，用于选择确认。应该是个bool值
        self.send_time=time.time()#这个包的发送时间，用于计算eRTT

def process_download(sock:socket.socket, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global output_file
    global received_chunk
    # global downloading_chunkhash
    
    output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()# whohas包的body部分
    with open(chunkfile, 'r') as cf:
        lines = cf.readlines()
        for line in lines:
            index, datahash_str = line.strip().split(" ")
            received_chunk[datahash_str] = bytes()
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


#发送get也要初始化队列

#如果收到GET
#启动计时器
#把那些加到queue中
#设置base_number


def process_inbound_udp(sock:socket.socket):
    # Receive pkt
    global sending_chunkhash #原本用于现在正在传输的data的hash是什么，需要改为
    global config
    global sending_to_peer_num # how many peers its sending data to
    global chunk_belong_to
    global downloading_chunkhash
    global identity_dict
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(
        "HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    identity_global=identity_dict[from_addr]
    
    if Type==WHOHAS: #0
        # check if peer already reach max chunk
        if sending_to_peer_num>=config.max_conn:
            # set ack and seq of denied to all 0
            denied_pkt = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, DENIED, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), socket.htonl(0), socket.htonl(0))
            sock.sendto(denied_pkt,from_addr)
        # check if self has the chunk
        whohas_chunkhash_list=[data[i:i+20] for i in range(0,len(data),20)]
        chunkhash_str_list=[]
        for _ in whohas_chunkhash_list:
            chunkhash_str_list.append(bytes.hex(_))
        pkt_body=bytes()
        for i in range(len(chunkhash_str_list)):
            if chunkhash_str_list[i] in config.haschunks:
                pkt_body=pkt_body+whohas_chunkhash_list[i]
        if len(pkt_body)!=0:
            ihave_header = struct.pack("HBBHHII",socket.htons(52305), TEAM_NUM, IHAVE, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(pkt_body)), socket.htonl(0), socket.htonl(0))
            ihave_pkt = ihave_header+pkt_body
            sock.sendto(ihave_pkt, from_addr)
                
        # whohas_chunkhash = data[:20]
        # chunkhash_str = bytes.hex(whohas_chunkhash)
        # sending_chunkhash = chunkhash_str
        # if chunkhash_str in config.haschunks:
        #     ihave_header = struct.pack("HBBHHII",socket.htons(52305), TEAM_NUM, IHAVE, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(whohas_chunkhash)), socket.htonl(0), socket.htonl(0))
        #     ihave_pkt = ihave_header+whohas_chunkhash
        #     sock.sendto(ihave_pkt, from_addr)

    elif Type==IHAVE: #1
        # see what chunk sender has

        #需要判断收到的chunk是否已经向别人请求，对于缺少的chunk，访问第一个返还的ihave，这地方可以优化
        get_chunkhash_list=[data[i:i+20] for i in range(0,len(data),20)]

        #需要有个东西记录，缺失的chunk都在向谁请求
        #还要处理，如果第一轮无法传完包的情况，或者有两个chunk需要从另外的包上下载
        #这个在结束发包的时候判断

        #这里向谁发送GET的策略可以改变

        #维护两个东西downloading
        #如果当前包如果在等待的话，看看能不能加过来
        #后面ack的时候，也要维护这个,下载完成只用删除downloading的list头的值
        #还要维护belong_to

        #对于每个ihave包中的hash
        for get_chunkhash in get_chunkhash_list:
            #检查这个chunkhash的状态
            #状态0：这个chunk没有正在被下载，也没有存在与别的peer的下载队列中
            #状态1：这个chunk正在被下载
            #状态2：整个chunk还未下载，正在别人的队列中等待被下载
            #状态3：这个chunk已经下载完成
            chunk_state=0
            situation=0
            for downloading_list in downloading_chunkhash.values():
                for i in range(len(downloading_list)):
                    if get_chunkhash==downloading_list[i]:
                        if i==0:
                            chunk_state=1
                        else:
                            chunk_state=2
                            situation=i
                        break
            if chunk_state==0 and chunk_belong_to.has_key(get_chunkhash):
                chunk_state=3
            
            if chunk_state==0:
                downloading_chunkhash[identity_dict[from_addr]].append(get_chunkhash)
                chunk_belong_to[get_chunkhash]=identity_dict[from_addr]
                #修改belongto
            elif chunk_state==1:
                pass
            elif chunk_state==2:
                if situation>len(downloading_chunkhash[identity_dict[from_addr]]):
                    downloading_chunkhash[identity_dict[from_addr]].append(get_chunkhash)
                    #从那个identity的列表中删除，同时修改belongto
                    downloading_chunkhash[chunk_belong_to[get_chunkhash]].remove(get_chunkhash)
                    chunk_belong_to[get_chunkhash]=identity_dict[from_addr]
            elif chunk_state==3:
                pass
            
        #发送get也要初始化队列
        #是收到data要填充队列？
        #发送get的是接收方
        #接收方的队列也需要存之前发送过来的包，等待确认后，一起发送给reciew

        get_chunkhash = downloading_chunkhash[identity_dict[from_addr]][0]
        # send back GET
        get_header = struct.pack("HBBHHII",socket.htons(52305), TEAM_NUM, GET, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(get_chunkhash)), socket.htonl(0), socket.htonl(0))
        get_pkt = get_header+get_chunkhash
        sock.sendto(get_pkt, from_addr)

        base_number[identity_global]=0
        for i in range(N):
            #初始化接收方的队列
            queue[identity_global].append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))

    elif Type==GET: #2

        #如果收到GET
        #启动计时器
        #把那些加到queue中
        #设置base_number

        #这是发送方

        # sending chunk to new peer
        sending_to_peer_num+=1
        base_number[identity_global]=0
        
        for i in range(N):
            chunk_data = config.haschunks[sending_chunkhash][i*MAX_PAYLOAD:(i+1)*MAX_PAYLOAD]
            data_header = struct.pack("HBBHHII", socket.htons(52305),TEAM_NUM, DATA, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), socket.htonl(i), 0)#第一个包的seq值从0开始
            data_pkt=data_header+chunk_data
            queue[identity_global].append(pkt_in_queue(packet=data_pkt,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
            sock.sendto(data_pkt, from_addr)

        timer[identity_global]=[True,time.time()]


    elif Type==DATA: #3
    
        #接收方
        SEND=False
        if Seq==base_number[identity_global]:
            # 移动窗口，把信息发送给received_chunk
            # 返回新的ack值，同时设置option
            queue[identity_global][0].packet=pkt
            while queue[identity_global][0].packet!=None:
                base_number[identity_global]+=1
                received_chunk[downloading_chunkhash[identity_global][0]]+=queue[identity_global][0].packet[HEADER_LEN:]
                queue[identity_global].pop(0)
                queue[identity_global].append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
            
            SEND=True
                    
        elif Seq<base_number[identity_global]:
            # 返回一个basenumber的ack，同时设置option
            SEND=True

        elif Seq>base_number[identity_global] and Seq<base_number[identity_global]+N:
            # 返回一个basenumber的ack，同时设置option
            #先要把后面的包存下来
            queue[identity_global][Seq-base_number[identity_global]].packet=pkt
            queue[identity_global][Seq-base_number[identity_global]].receive=True
            

            SEND=True

        if SEND:
            ack_value=base_number[identity_global]

            option=encode_option(queue[identity_global])
            option=option[:4]
            for i in option:
                i[0]+=base_number[identity_global]
                i[1]+=base_number[identity_global]
            #构建传出的ack包
            if len(option)==0:
                ack_pkt = struct.pack("HBBHHII", socket.htons(52305),TEAM_NUM,  ACK,socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), 0, ack_value) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==1:
                
                ack_pkt = struct.pack("HBBHHIIHH", socket.htons(52305),TEAM_NUM,  ACK,socket.htons(struct.calcsize("HBBHHIIHH")), socket.htons(struct.calcsize("HBBHHIIHH")), 0, ack_value,option[0][0],option[0][1]) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==2:
                ack_pkt = struct.pack("HBBHHIIHHHH", socket.htons(52305),TEAM_NUM,  ACK,socket.htons(struct.calcsize("HBBHHIIHHHH")), socket.htons(struct.calcsize("HBBHHIIHHHH")), 0, ack_value,option[0][0],option[0][1],option[1][0],option[1][1]) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==3:
                ack_pkt = struct.pack("HBBHHIIHHHHHH", socket.htons(52305),TEAM_NUM,  ACK,socket.htons(struct.calcsize("HBBHHIIHHHHHH")), socket.htons(struct.calcsize("HBBHHIIHHHHHH")), 0, ack_value,option[0][0],option[0][1],option[1][0],option[1][1],option[2][0],option[2][1]) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==4:
                ack_pkt = struct.pack("HBBHHIIHHHHHHHH", socket.htons(52305),TEAM_NUM,  ACK,socket.htons(struct.calcsize("HBBHHIIHHHHHHHH")), socket.htons(struct.calcsize("HBBHHIIHHHHHHHH")), 0, ack_value,option[0][0],option[0][1],option[1][0],option[1][1],option[2][0],option[2][1],option[3][0],option[3][1]) 
                sock.sendto(ack_pkt, from_addr)


        # see if finished
        if len(received_chunk[downloading_chunkhash[identity_global][0]])==CHUNK_DATA_SIZE: # finished
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(output_file,"wb") as wf:
                output_dict=dict()
                output_dict[downloading_chunkhash[identity_global][0]]=received_chunk[downloading_chunkhash[identity_global][0]]
                pickle.dump(output_dict, wf)
            
            config.haschunks[downloading_chunkhash[identity_global][0]] = received_chunk[downloading_chunkhash[identity_global][0]]
            print(f"GOT {output_file}")
            downloading_chunkhash[identity_global].pop(0)
            if len(downloading_chunkhash[identity_global])!=0:
                #发送get包
                get_chunkhash = downloading_chunkhash[identity_dict[from_addr]][0]
                # send back GET
                get_header = struct.pack("HBBHHII",socket.htons(52305), TEAM_NUM, GET, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(get_chunkhash)), socket.htonl(0), socket.htonl(0))
                get_pkt = get_header+get_chunkhash
                sock.sendto(get_pkt, from_addr)

                base_number[identity_global]=0
                queue[identity_global].clear()
                for i in range(N):
                    #初始化接收方的队列
                    queue[identity_global].append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
            else:
                sending_to_peer_num-=1

        # # see if finished,这是example里的
        # if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
        #     # finished downloading this chunkdata!
        #     # dump your received chunk to file in dict form using pickle
        #     with open(ex_output_file, "wb") as wf:
        #         pickle.dump(ex_received_chunk, wf)

        #     # add to this peer's haschunk:
        #     config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]

        #     # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
        #     print(f"GOT {ex_output_file}")

        #     # The following things are just for illustration, you do not need to print out in your design.
        #     sha1 = hashlib.sha1()
        #     sha1.update(ex_received_chunk[ex_downloading_chunkhash])
        #     received_chunkhash_str = sha1.hexdigest()
        #     print(f"Expected chunkhash: {ex_downloading_chunkhash}")
        #     print(f"Received chunkhash: {received_chunkhash_str}")
        #     success = ex_downloading_chunkhash==received_chunkhash_str
        #     print(f"Successful received: {success}")
        #     if success:
        #         print("Congrats! You have completed the example!")
        #     else:
        #         print("Example fails. Please check the example files carefully.")


    elif Type == ACK: #4

        ack_num = socket.ntohl(Ack)
        real_header_length=socket.ntohl(hlen)
        if ack_num*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            print(f"finished sending {sending_chunkhash}")
        else:
            if ack_num>base_number[identity_global]:
                option=decode_option(real_header_length,HEADER_LEN,pkt)
                #记录option值
                #移动窗口，传递新的data，把窗口补满，重启计数器
                queue[identity_global][0].receive=True
                for i in option:
                    for j in range(i[0],i[1]):
                        queue[identity_global][j].receive=True
                while queue[identity_global][0].receive==True:
                    base_number[identity_global]+=1
                    queue[identity_global].pop(0)
                    #这个sending_chunkhash是什么鬼，还要check一下
                    chunk_data = config.haschunks[sending_chunkhash][(base_number[identity_global]+N-1)*MAX_PAYLOAD:(base_number[identity_global]+N)*MAX_PAYLOAD]
                    data_header = struct.pack("HBBHHII", socket.htons(52305),TEAM_NUM, DATA, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), socket.htonl((base_number[identity_global]+N-1)), 0)#第一个包的seq值从0开始
                    data_pkt=data_header+chunk_data
                    queue[identity_global].append(pkt_in_queue(packet=data_pkt,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
                    sock.sendto(data_pkt, from_addr)
                timer[identity_global]=[True,time.time()]
            elif ack_num<base_number[identity_global]:
                pass
                #这里不知道要不要增加重复ack的值
            elif ack_num==base_number[identity_global]:
                option=decode_option(real_header_length,HEADER_LEN,pkt)
                #记录option值
                #添加重复ack值，判断是否快速重传
                #如果快速重传，那么重启计时器
                queue[identity_global][0].receive=True
                for i in option:
                    for j in range(i[0],i[1]):
                        queue[identity_global][j].receive=True
                queue[identity_global][0].ack_number+=1
                if queue[identity_global][0].ack_number==3:
                    queue[identity_global][0].retran_number += 1
                    sock.sendto(queue[identity_global][0].packet, from_addr)
                    timer[identity_global]=[True,time.time()]

        # if ack_num*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
        #     # finished
        #     print(f"finished sending {sending_chunkhash}")
        # else:
        #     # split chunks into packets
        #     left = ack_num*MAX_PAYLOAD
        #     right = min((ack_num+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
        #     next_data = config.haschunks[sending_chunkhash][left:right]
        #     data_header = struct.pack("HBBHHII", socket.htons(52305),TEAM_NUM,3,socket.htons(HEADER_LEN),socket.htons(HEADER_LEN+len(next_data)),socket.htonl(ack_num+1),0)
        #     sock.sendto(data_header+next_data, from_addr)

def decode_option(real_header_length,HEADER_LEN,pkt):
    option_len=(real_header_length-HEADER_LEN)/struct.calcsize("HH")
    option=[]
    if option_len==0:
        pass
    elif option_len==1:
        #前面这些都是没有用的，只是单纯为了解包获取option的值
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01 = struct.unpack("HBBHHIIHH", pkt[:real_header_length])
        option.append([option00,option01])
    elif option_len==2:
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01,option10,option11 = struct.unpack("HBBHHIIHHHH", pkt[:real_header_length])
        option.append([option00,option01])
        option.append([option10,option11])
    elif option_len==3:
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01,option10,option11,option20,option21 = struct.unpack("HBBHHIIHHHHHH", pkt[:real_header_length])
        option.append([option00,option01])
        option.append([option10,option11])
        option.append([option20,option21])
    elif option_len==4:
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01,option10,option11,option20,option21,option30,option31 = struct.unpack("HBBHHIIHHHHHHHH", pkt[:real_header_length])
        option.append([option00,option01])
        option.append([option10,option11])
        option.append([option20,option21])
        option.append([option30,option31])
    else:
        print("fuck error")
    return option

def encode_option(pkt_list):
    option=[]
    state=0
    start=-1
    end=-1
    for i in range(len(pkt_list)):
        if pkt_list[i].receive==True:
            if state==0:
                start=i
                state=1
            if i==len(pkt_list)-1:
                end=i+1
                option.append([start,end])
        else:
            if state==1:
                end=i
                state=0
                option.append([start,end])
    return option

def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass
        

def peer_run(config):

    global timer
    global queue
    global eRTT
    global identity_dict
    global downloading_chunkhash
    #初始化
    for p in config.peers:
        if int(p[0]) != config.identity:
            # [id] [ip] [port]
            timer[p[0]]=[False,time.time()]
            queue[p[0]]=[]
            eRTT[p[0]]=1
            identity_dict[(p[1], int(p[2]))]=p[0]
            downloading_chunkhash[p[0]]=[]

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
                # 对于超时的处理
                for p in config.peers:
                    if int(p[0]) != config.identity:
                        # [id] [ip] [port]
                        # 注意只有发送方会启动计时器
                        if timer[p[0]][0]==True and len(queue[p[0]])!=0:
                            time_limit=config.timeout
                            if config.timeout==0:
                                time_limit=eRTT[p[0]]*(2**queue[p[0]][0].retran_number)#对于已经重传过的包，超时时间需要加倍处理

                            if time.time()-timer[p[0]][1]>time_limit:
                            # 进行超时重传处理 
                            # 重传队列头的包 同时重启计数器
                                sock.sendto(queue[p[0]][0].packet, (p[1], int(p[2])))
                                queue[p[0]][0].retran_number += 1
                                timer[p[0]]=[True,time.time()]
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
