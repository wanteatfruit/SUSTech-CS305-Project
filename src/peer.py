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
import matplotlib.pyplot as plt
import logging
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
ssthresh = 64
winInfo = dict()

#这个peer的信息
output_file = None
sending_to_peer_num = 0 # how many peers its sending data to
received_chunk = dict()#这个peer需要下载的chunk，key为hash,value为数据
chunk_belong_to=dict()#这个chunk决定由谁下载，用于判断是否已经下载完成，key为hash，value为identify
whohas_chunk=dict()#key为hash，value为identity的hash。表明都有谁有这个hash。用于crash处理

# 用于通过ip和port查找identity
# key:(ip,port) value:identity
identity_dict=dict()

identity_dict_reverse=dict()


# 与别的peer交互的时候，该peer为发送方
# key:identity,value:peer2peer
sender_dict=dict()
# 与别的peer交互的时候，该peer为接收方
# key:identity,value:peer2peer
receiver_dict=dict()

# 注：pack和unpack的时候请前面使用"！"，后面的所有内容都不应该使用sock.htonl()和sock.ntohl()
# https://github.com/orgs/SUSTech-CS305-Fall22/discussions/22

class peer2peer: #与别的peer交互的时候需要用到
    def __init__(self,from_addr,N=1,base_number=0,time_enable=False):
        self.N=N #窗口长度
        self.base_number=base_number# queue的base number，即为当前的确认号
        self.queue=[]# 接收队列，长度为N，使用list模拟queue
        self.timer=[time_enable,time.time()]#对于每个的计时器  [True/False,time.time()]，对于接收方，不需要重传，所以计数器为false
        self.downloading_chunkhash=[]# 需要发送/下载的chunkhash列表，里面存的是chunkhash。此时downloading_chunkhash[0]的chunk应该正在下载/发送。命名为downloading_chunkhash是历史遗留问题
        # rtt估计，用于超时评估，仅当该节点为发送方的时候有值（只有发送方需要重传）,初始化为1秒超时
        self.eRTT=1
        self.dRTT=0
        self.from_addr=from_addr
        self.control = 0 # 拥塞控制模式 表明这个peer作为发送方时处于哪个状态
        self.ack_list = dict()  # peer作为发送方时，存储收到的ack信息

class pkt_in_queue:#对于每个存在queue中的数据结构
    def __init__(self,packet,send_time,ack_number=0,retran_number=0,receive=False):
        self.receive=receive # 确认这个包是否已经被接收到，用于选择确认。应该是个bool值
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
    whohas_header = struct.pack("!HBBHHII", MAGIC,TEAM_NUM, WHOHAS, HEADER_LEN, HEADER_LEN+len(download_hash), 0, 0)
    whohas_packet = whohas_header+download_hash
    # print(whohas_packet)
    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            # [id] [ip] [port]
            sock.sendto(whohas_packet, (p[1], int(p[2])))


def process_inbound_udp(sock:socket.socket):
    # Receive pkt
    global config

    global output_file
    global sending_to_peer_num # how many peers its sending data to
    global received_chunk
    global chunk_belong_to
    global whohas_chunk

    global identity_dict
    global identity_dict_reverse

    global sender_dict
    global receiver_dict

    global ssthresh
    global winInfo

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(
        "!HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]

    identity_global=identity_dict[from_addr]#发送这个包的peer的identity
    
    if Type==WHOHAS: #0
        # check if peer already reach max chunk
        # if sending_to_peer_num>=config.max_conn:
        #     # set ack and seq of denied to all 0
        #     denied_pkt = struct.pack("!HBBHHII", 52305, TEAM_NUM, DENIED, HEADER_LEN, HEADER_LEN, 0,0)
        #     sock.sendto(denied_pkt,from_addr)
        # check if self has the chunk
        whohas_chunkhash_list=[data[i:i+20] for i in range(0,len(data),20)]
        chunkhash_str_list=[bytes.hex(_) for _ in whohas_chunkhash_list]
        pkt_body=bytes()
        for i in range(len(chunkhash_str_list)):
            if chunkhash_str_list[i] in config.haschunks:
                pkt_body=pkt_body+whohas_chunkhash_list[i]
        if len(pkt_body)!=0:
            ihave_header = struct.pack("!HBBHHII",52305, TEAM_NUM, IHAVE, HEADER_LEN, HEADER_LEN+len(pkt_body), 0,0)
            ihave_pkt = ihave_header+pkt_body
            sock.sendto(ihave_pkt, from_addr)

    elif Type==IHAVE: #1,此时该peer为接收方
        # see what chunk sender has

        # 对于缺失的包，究竟需要向谁请求的policy，这个policy还可以根据RTT优化

        '''
        需要判断每个chunk的状态:
            状态0：这个chunk没有正在被下载，也没有存在与别的peer的下载队列中
            状态1：这个chunk正在被下载
            状态2：整个chunk还未下载，正在别人的队列中等待被下载
            状态3：这个chunk已经下载完成
        '''
        '''
        策略：
            状态0:直接添加到downloading队列中
            状态1：pass
            状态2：看代码吧，我线下说，或者不懂也没关系
            状态3：pass
        '''

        '''
        #这个peer需要下载的chunk，key为hash,value为数据
        received_chunk = dict()

        #这个chunk决定由谁下载，用于判断是否已经下载完成，key为hash，value为identify
        chunk_belong_to=dict()#这个chunk决定由谁下载，用于判断是否已经下载完成，key为hash，value为identify

        # 需要发送/下载的chunkhash列表，里面存的是chunkhash。此时downloading_chunkhash[0]的chunk应该正在下载/发送
        sender_dict/receiver_dict.downloading_chunkhash=[]

        #key为hash，value为identity的hash。表明都有谁有这个hash。用于crash处理
        whohas_chunk=dict()
        '''
        
        ihave_chunkhash_list=[data[i:i+20] for i in range(0,len(data),20)]
        chunkhash_str_list=[bytes.hex(_) for _ in ihave_chunkhash_list]
        #对于每个ihave包中的hash
        for get_chunkhash in chunkhash_str_list:
            #检查这个chunkhash的状态
            #状态0：这个chunk没有正在被下载，也没有存在与别的peer的下载队列中
            #状态1：这个chunk正在被下载
            #状态2：整个chunk还未下载，正在别人的队列中等待被下载
            #状态3：这个chunk已经下载完成
            if get_chunkhash not in whohas_chunk:
                whohas_chunk[get_chunkhash]=[]
            whohas_chunk[get_chunkhash].append(identity_global)    
            chunk_state=0
            position=0
            for value in receiver_dict.values():
                for i in range(len(value.downloading_chunkhash)):
                    if get_chunkhash==value.downloading_chunkhash[i]:
                        if i==0:
                            chunk_state=1
                        else:
                            chunk_state=2
                            position=i
                        break
            if chunk_state==0 and get_chunkhash in chunk_belong_to:
                chunk_state=3
            
            if chunk_state==0:#决定请求这个
                chunk_belong_to[get_chunkhash]=identity_global
                if identity_global not in receiver_dict:
                    receiver_dict[identity_global]=peer2peer(from_addr=from_addr,N=512,base_number=0,time_enable=False)
                receiver_dict[identity_global].downloading_chunkhash.append(get_chunkhash)
            elif chunk_state==1:
                pass
            elif chunk_state==2:
                if identity_global not in receiver_dict:
                    receiver_dict[identity_global]=peer2peer(from_addr=from_addr,N=512,base_number=0,time_enable=False)
                    receiver_dict[identity_global].downloading_chunkhash.append(get_chunkhash)
                elif position>len(receiver_dict[identity_global].downloading_chunkhash):
                    receiver_dict[identity_global].downloading_chunkhash.append(get_chunkhash)
                    #从那个identity的列表中删除，同时修改belongto
                    receiver_dict[chunk_belong_to[get_chunkhash]].downloading_chunkhash.pop(position)
                    chunk_belong_to[get_chunkhash]=identity_global
            elif chunk_state==3:
                pass
            

        if identity_global in receiver_dict:
            get_chunkhash = bytes.fromhex(receiver_dict[identity_global].downloading_chunkhash[0])
            # send back GET
            get_header = struct.pack("!HBBHHII",52305, TEAM_NUM, GET, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0,0)
            get_pkt = get_header+get_chunkhash
            sock.sendto(get_pkt, from_addr)
            receiver_dict[identity_global].timer=[True,time.time()]

            #初始化接收方的队列，此时接收方还没有收到任何一个包，所以packet信息全部初始化为None
            for i in range(int(receiver_dict[identity_global].N)):
                receiver_dict[identity_global].queue.append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))

    elif Type==GET: #2, 此时该peer为发送方

    
        # sending chunk to new peer
        sending_to_peer_num+=1

        #每次收到get请求都要初始化，当收到最后一个ack，清理sender_dict
        #接收方应保证不会在不会对一个peer同时请求两个chunk
        assert identity_global not in sender_dict, '发送方在发送时受到对另一个chunk的GET'

        sender_dict[identity_global]=peer2peer(from_addr=from_addr,N=1,base_number=0,time_enable=False)

        get_chunkhash = data[:20]
        sending_chunkhash = bytes.hex(get_chunkhash)
        sender_dict[identity_global].downloading_chunkhash.append(sending_chunkhash)

        
        #把包加到队列中
        for i in range(int(sender_dict[identity_global].N)):
            chunk_data = config.haschunks[sending_chunkhash][i*MAX_PAYLOAD:(i+1)*MAX_PAYLOAD]
            data_header = struct.pack("!HBBHHII", 52305,TEAM_NUM, DATA, HEADER_LEN, HEADER_LEN, i, 0)#第一个包的seq值从0开始
            data_pkt=data_header+chunk_data
            sender_dict[identity_global].queue.append(pkt_in_queue(packet=data_pkt,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
            sock.sendto(data_pkt, from_addr)
        
        #启动计时器
        sender_dict[identity_global].timer=[True,time.time()]
        winInfo[identity_global]=[]

    elif Type==DATA: #3 此时peer为接收方
    
        #接收方
        if identity_global not in receiver_dict:
            pass
        else :
            receiver_dict[identity_global].timer=[True,time.time()]
            if Seq==receiver_dict[identity_global].base_number:
                # 移动窗口，把信息发送给received_chunk
                # 返回新的ack值，同时设置option
                receiver_dict[identity_global].queue[0].packet=pkt
                while receiver_dict[identity_global].queue[0].packet!=None:
                    receiver_dict[identity_global].base_number+=1
                    received_chunk[receiver_dict[identity_global].downloading_chunkhash[0]]+=receiver_dict[identity_global].queue[0].packet[HEADER_LEN:]
                    receiver_dict[identity_global].queue.pop(0)
                    receiver_dict[identity_global].queue.append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
                        
            elif Seq>receiver_dict[identity_global].base_number and Seq<receiver_dict[identity_global].base_number+int(receiver_dict[identity_global].N):
                # 返回一个basenumber的ack，同时设置option
                #先要把后面的包存下来
                receiver_dict[identity_global].queue[Seq-receiver_dict[identity_global].base_number].packet=pkt
                receiver_dict[identity_global].queue[Seq-receiver_dict[identity_global].base_number].receive=True

            
            ack_value=receiver_dict[identity_global].base_number

            option=encode_option(receiver_dict[identity_global].queue)
            option=option[:4]
            for i in option:
                i[0]+=receiver_dict[identity_global].base_number
                i[1]+=receiver_dict[identity_global].base_number
            #构建传出的ack包
            if len(option)==0:
                ack_pkt = struct.pack("!HBBHHII", 52305,TEAM_NUM,  ACK,HEADER_LEN, HEADER_LEN, 0, ack_value) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==1:
                    
                ack_pkt = struct.pack("!HBBHHIIHH", 52305,TEAM_NUM,  ACK,struct.calcsize("HBBHHIIHH"), struct.calcsize("HBBHHIIHH"), 0, ack_value,option[0][0],option[0][1]) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==2:
                ack_pkt = struct.pack("!HBBHHIIHHHH", 52305,TEAM_NUM,  ACK,struct.calcsize("HBBHHIIHHHH"), struct.calcsize("HBBHHIIHHHH"), 0, ack_value,option[0][0],option[0][1],option[1][0],option[1][1]) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==3:
                ack_pkt = struct.pack("!HBBHHIIHHHHHH", 52305,TEAM_NUM,  ACK,struct.calcsize("HBBHHIIHHHHHH"), struct.calcsize("HBBHHIIHHHHHH"), 0, ack_value,option[0][0],option[0][1],option[1][0],option[1][1],option[2][0],option[2][1]) 
                sock.sendto(ack_pkt, from_addr)
            elif len(option)==4:
                ack_pkt = struct.pack("!HBBHHIIHHHHHHHH", 52305,TEAM_NUM,  ACK,struct.calcsize("HBBHHIIHHHHHHHH"), struct.calcsize("HBBHHIIHHHHHHHH"), 0, ack_value,option[0][0],option[0][1],option[1][0],option[1][1],option[2][0],option[2][1],option[3][0],option[3][1]) 
                sock.sendto(ack_pkt, from_addr)

            #当收到最后一个data的时候，需要重新GET，或者清除receiver_dict()
            # see if finished
            downloading_id=receiver_dict[identity_global].downloading_chunkhash[0]
            if len(received_chunk[downloading_id])==CHUNK_DATA_SIZE: # finished
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle
                config.haschunks[downloading_id] = received_chunk[downloading_id]
                receiver_dict[identity_global].downloading_chunkhash.pop(0)

                #只有当所有包都收到的时候，才打包为output_file
                FINISH=True
                for value in received_chunk.values():
                    if len(value)!=CHUNK_DATA_SIZE:
                        FINISH=False
                        break
                if FINISH:
                    with open(output_file,"wb") as wf:
                        pickle.dump(received_chunk, wf)
                    print(f"GOT {output_file}")

                if len(receiver_dict[identity_global].downloading_chunkhash)!=0:
                    #发送get包
                    get_chunkhash = bytes.fromhex(receiver_dict[identity_global].downloading_chunkhash[0])
                    # send back GET
                    get_header = struct.pack("!HBBHHII",52305, TEAM_NUM, GET, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0,0)
                    get_pkt = get_header+get_chunkhash
                    sock.sendto(get_pkt, from_addr)

                    receiver_dict[identity_global].base_number=0
                    receiver_dict[identity_global].queue.clear()
                    #初始化接收方的队列
                    for i in range(int(receiver_dict[identity_global].N)):
                        receiver_dict[identity_global].queue.append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
                else:
                    receiver_dict.pop(identity_global)


    elif Type == ACK: #4 此时peer为发送方

        ack_num = Ack
        if ack_num*MAX_PAYLOAD >= CHUNK_DATA_SIZE:#ack_num==512 发送完毕 这里画图
            # finished
            sending_chunkhash=sender_dict[identity_global].downloading_chunkhash[0]
            sender_dict.pop(identity_global)
            sending_to_peer_num-=1
            print(f"finished sending {sending_chunkhash}")


            plot(self_identity=config.identity,opposite_identity=identity_global,sending_chunkhash=sending_chunkhash,winInfo=winInfo[identity_global])
            winInfo.pop(identity_global)
        else:
            if ack_num>sender_dict[identity_global].base_number:
                
                if ack_num==sender_dict[identity_global].base_number+1 and sender_dict[identity_global].queue[0].retran_number==0:
                    #计算eRTT,dRTT
                    sRTT=time.time()-sender_dict[identity_global].queue[0].send_time
                    sender_dict[identity_global].eRTT=0.875*sender_dict[identity_global].eRTT+0.125*sRTT
                    sender_dict[identity_global].dRTT=0.75*sender_dict[identity_global].dRTT+0.25*abs(sRTT-sender_dict[identity_global].eRTT)

                option=decode_option(hlen,HEADER_LEN,pkt)
                #记录option值
                #移动窗口，传递新的data，把窗口补满，重启计数器

                while sender_dict[identity_global].base_number!=ack_num:
                    sender_dict[identity_global].base_number+=1
                    if len(sender_dict[identity_global].queue)!=0:
                        sender_dict[identity_global].queue.pop(0)
                
                for i in option:
                    for j in range(i[0]-sender_dict[identity_global].base_number,i[1]-sender_dict[identity_global].base_number):
                        if j< len(sender_dict[identity_global].queue):
                            sender_dict[identity_global].queue[j].receive=True

                if sender_dict[identity_global].control == 0: # 慢启动
                        #收到了该ACK并且没有进行重传，需要扩大发送方的windowsize 根据是否是new ack进行讨论                     
                    if ack_num not in sender_dict[identity_global].ack_list:
                        sender_dict[identity_global].ack_list[ack_num] = 1
                        sender_dict[identity_global].N +=1 # 下面补齐
                        winInfo[identity_global].append((int(sender_dict[identity_global].N), time.time()))
                        # assert len(winInfo) != 0
                        # sender_dict[identity_global].queue.append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
                    else: #重复的 ack +1
                        sender_dict[identity_global].ack_list[ack_num] +=1
                    
                    if int(sender_dict[identity_global].N) >= ssthresh:#进入拥塞避免模式
                        sender_dict[identity_global].control = 1
                        
                elif sender_dict[identity_global].control == 1:
                    if ack_num not in sender_dict[identity_global].ack_list:
                        sender_dict[identity_global].N = sender_dict[identity_global].N + 1/sender_dict[identity_global].N
                        sender_dict[identity_global].ack_list[ack_num] = 1
                        winInfo[identity_global].append((int(sender_dict[identity_global].N),time.time()))
                    else:
                        sender_dict[identity_global].ack_list[ack_num] +=1 
                elif sender_dict[identity_global].control == 2:
                    if ack_num not in sender_dict[identity_global].ack_list:
                        # new ack 回到拥塞避免
                        # 清零dupACK
                        # if len(sender_dict[identity_global].queue)
                        # sender_dict[identity_global].queue[0].ack_number = 0
                        sender_dict[identity_global].control = 1
                    else:
                        sender_dict[identity_global].N +=1 # 下面补齐
                        winInfo[identity_global].append((int(sender_dict[identity_global].N), time.time()))
                  

                #这里要加最多到
                while sender_dict[identity_global].base_number+len(sender_dict[identity_global].queue)<512 and len(sender_dict[identity_global].queue)<int(sender_dict[identity_global].N):
                    sending_chunkhash=sender_dict[identity_global].downloading_chunkhash[0]
                    left=sender_dict[identity_global].base_number+len(sender_dict[identity_global].queue)
                    right=left+1
                    chunk_data = config.haschunks[sending_chunkhash][left*MAX_PAYLOAD:right*MAX_PAYLOAD]
                    data_header = struct.pack("!HBBHHII", 52305,TEAM_NUM, DATA, HEADER_LEN, HEADER_LEN, left, 0)#第一个包的seq值从0开始
                    data_pkt=data_header+chunk_data
                    sender_dict[identity_global].queue.append(pkt_in_queue(packet=data_pkt,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
                    sock.sendto(data_pkt, from_addr)
                sender_dict[identity_global].timer=[True,time.time()]
            elif ack_num==sender_dict[identity_global].base_number:
                option=decode_option(hlen,HEADER_LEN,pkt)
                #记录option值
                #添加重复ack值，判断是否快速重传
                #如果快速重传，那么重启计时器
                for i in option:
                    for j in range(i[0]-sender_dict[identity_global].base_number,i[1]-sender_dict[identity_global].base_number):
                        if j< len(sender_dict[identity_global].queue):
                            sender_dict[identity_global].queue[j].receive=True
                sender_dict[identity_global].queue[0].ack_number+=1
                if sender_dict[identity_global].queue[0].ack_number==3:
                    # 快速重传 同时从拥塞避免到慢启动
                    if sender_dict[identity_global].control == 0 or sender_dict[identity_global].control == 1:
                        sender_dict[identity_global].control = 2 # 慢启动到快速恢复
                        
                        ssthresh = int(sender_dict[identity_global].N/2) 
                        sender_dict[identity_global].N = ssthresh + 3
                        winInfo[identity_global].append((int(sender_dict[identity_global].N),time.time()))
                        if int(sender_dict[identity_global].N) > 6 :  # 变化之后winsize会减少
                            queue = []
                            for i in sender_dict[identity_global].queue:
                                queue.append(i)
                            sender_dict[identity_global].queue = queue.copy()
                        else:
                              # 变化之后winsize会增加
                            # 补全
                            while sender_dict[identity_global].base_number+len(sender_dict[identity_global].queue)<512 and len(sender_dict[identity_global].queue)<int(sender_dict[identity_global].N):
                                sending_chunkhash=sender_dict[identity_global].downloading_chunkhash[0]
                                left=sender_dict[identity_global].base_number+len(sender_dict[identity_global].queue)
                                right=left+1
                                chunk_data = config.haschunks[sending_chunkhash][left*MAX_PAYLOAD:right*MAX_PAYLOAD]
                                data_header = struct.pack("!HBBHHII", 52305,TEAM_NUM, DATA, HEADER_LEN, HEADER_LEN, left, 0)#第一个包的seq值从0开始
                                data_pkt=data_header+chunk_data
                                sender_dict[identity_global].queue.append(pkt_in_queue(packet=data_pkt,send_time=time.time(),ack_number=0,retran_number=0,receive=False))
                                sock.sendto(data_pkt, from_addr)
                    else:
                        pass
                    sender_dict[identity_global].queue[0].retran_number += 1
                    sock.sendto(sender_dict[identity_global].queue[0].packet, from_addr)
                    sender_dict[identity_global].timer=[True,time.time()]
            elif ack_num<sender_dict[identity_global].base_number:
                pass
    elif Type == DENIED: #5 此时peer为接收方
        #当收到DENIED，需要处理嘛
        #比如当需要的chunk仅peerA有，但peerA返还了一个DENIED包
        #是否还需要再次向peerA发送whohas
        pass
                
def plot(self_identity,opposite_identity,sending_chunkhash,winInfo):
    pass            


def decode_option(real_header_length,HEADER_LEN,pkt):
    option_len=(real_header_length-HEADER_LEN)/struct.calcsize("HH")
    option=[]
    if option_len==0:
        pass
    elif option_len==1:
        #前面这些都是没有用的，只是单纯通过解包获取option的值
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01 = struct.unpack("!HBBHHIIHH", pkt[:real_header_length])
        option.append([option00,option01])
    elif option_len==2:
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01,option10,option11 = struct.unpack("!HBBHHIIHHHH", pkt[:real_header_length])
        option.append([option00,option01])
        option.append([option10,option11])
    elif option_len==3:
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01,option10,option11,option20,option21 = struct.unpack("!HBBHHIIHHHHHH", pkt[:real_header_length])
        option.append([option00,option01])
        option.append([option10,option11])
        option.append([option20,option21])
    elif option_len==4:
        Magic__, Team__, Type__, hlen__, plen__, Seq__, Ack__,option00,option01,option10,option11,option20,option21,option30,option31 = struct.unpack("!HBBHHIIHHHHHHHH", pkt[:real_header_length])
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

    global sender_dict
    global receiver_dict
    global whohas_chunk
    global chunk_belong_to
    global identity_dict
    global identity_dict_reverse

    global ssthresh
    global winInfo

    #初始化identity_dict
    for p in config.peers:
        if int(p[0]) != config.identity:
            # [id] [ip] [port]
            identity_dict[(p[1], int(p[2]))]=p[0]
            # timer[p[0]]=[False,time.time()]
            # queue[p[0]]=[]
            # eRTT[p[0]]=1
            # downloading_chunkhash[p[0]]=[]
    identity_dict_reverse = {v:k for k,v in identity_dict.items()}


    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    crash_peer_list=[]

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
                # 对于超时的处理,只有当改节点为发送方的时候，才会重传包
                
                for key,value in sender_dict.items():
                    if key!=config.identity:#应该不会出现等于的情况
                        if value.timer[0]==True and len(value.queue)!=0:

                            time_limit=config.timeout#如果已有配置，则使用配置的超时时限，否则使用动态评估的
                            if config.timeout==0:
                                time_limit=(value.eRTT+4*value.dRTT)*(2**value.queue[0].retran_number)#对于已经重传过的包，超时时间需要加倍处理
                            
                            if time.time()-value.timer[1]>time_limit:
                                # 进行超时重传处理 
                                # 重传队列头的包 同时重启计数器
                                if value.control == 0:
                                    ssthresh = max(int(value.N/2),2)
                                    value.N = 1
                                    winInfo[key].append((int(value.N),time.time()))
                                    value.queue = [value.queue[0]]
                                elif value.control == 1:
                                    ssthresh = max(int(value.N/2),2)
                                    value.N = 1
                                    winInfo[key].append((int(value.N),time.time()))
                                    value.queue = [value.queue[0]]
                                    value.control = 0
                                else :
                                    # 快速恢复到慢启动
                                    ssthresh = max(int(value.N/2),2)
                                    value.N = 1
                                    winInfo[key].append((int(value.N),time.time()))
                                    value.queue = [value.queue[0]]
                                    value.control = 0
                                sock.sendto(value.queue[0].packet, value.from_addr)
                                value.queue[0].retran_number += 1
                                value.timer=[True,time.time()]

                pop_list=[]
                for key in list(receiver_dict.keys()):
                # for key,value in receiver_dict.items():#value是peer2peer
                    if key!=config.identity:#应该不会出现等于的情况
                        if receiver_dict[key].timer[0]==True:

                            time_limit=15
                            if time.time()-receiver_dict[key].timer[1]>time_limit:
                                crash_peer_list.append(key)
                                # 超时
                                # 应该直接舍弃这个节点
                                # 遍历这个节点downloading_chunkhash中所有hash
                                    # 找一个拥有这个hash的其他节点
                                    # 更改chunk_belong_to
                                    # 更改新请求的peer的receiver_dict.downloading_chunkhash
                                    # 看是否要重新发送get
                                # 删除掉这个peer2peer

                                for chunkhash in receiver_dict[key].downloading_chunkhash:
                                    received_chunk[chunkhash]=bytes()
                                    new_peer=-1;#新选择的节点
                                    new_len=1e7
                                    #遍历所有有这个chunk的peer
                                    for has_chunk_peer in whohas_chunk[chunkhash]:
                                        if has_chunk_peer not in receiver_dict and has_chunk_peer not in crash_peer_list:
                                            new_peer=has_chunk_peer
                                            break
                                        elif len(receiver_dict[has_chunk_peer].downloading_chunkhash)<new_len and has_chunk_peer not in crash_peer_list:
                                            new_peer=has_chunk_peer
                                            new_len=len(receiver_dict[has_chunk_peer].downloading_chunkhash)
                                    assert new_peer!=-1, '没有另一个节点拥有该chunk'
                                    chunk_belong_to[chunkhash]=new_peer
                                    if new_peer not in receiver_dict:
                                        receiver_dict[new_peer]=peer2peer(from_addr=identity_dict_reverse[new_peer],N=15,base_number=0,time_enable=False)
                                    receiver_dict[new_peer].downloading_chunkhash.append(chunkhash)
                                    #发送get
                                    if len(receiver_dict[new_peer].downloading_chunkhash)==1:
                                        get_chunkhash = bytes.fromhex(receiver_dict[new_peer].downloading_chunkhash[0])
                                        get_header = struct.pack("!HBBHHII",52305, TEAM_NUM, GET, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0,0)
                                        get_pkt = get_header+get_chunkhash
                                        sock.sendto(get_pkt, receiver_dict[new_peer].from_addr)
                                        receiver_dict[new_peer].timer=[True,time.time()]
                                        for i in range(receiver_dict[new_peer].N):
                                            receiver_dict[new_peer].queue.append(pkt_in_queue(packet=None,send_time=time.time(),ack_number=0,retran_number=0,receive=False))

                                
                                pop_list.append(key)
                
                for key in pop_list:
                    receiver_dict.pop(key)

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
