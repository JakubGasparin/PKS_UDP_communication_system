import os
import random
import socket
import sys
import threading
import time
from copy import copy

import libscrc

#### FLAGS ######

ACK = 0  # Acknowledgement
RDY = 1  # Ready for communication
END = 2  # End of communication
WRT = 3  # Write a message (from command prompt)
MPK = 4  # Multiple packets
PFL = 5  # File packet  (i.e. sending .jpg, or .docx)
NCK = 6  # Not Acknowledged
KAR = 7  # Keep Alive Request
SWR = 8  # Switch Roles
FIN = 9  # Finish communication

####### FLAGS ######


msgFromServer = "Hello UDP Client"
bytesToSend = str.encode(msgFromServer)

HOST = "192.168.56.1"
PORT = 5555

FRAGMENT_SIZE = 200
FRAGMENT_HEAD_SIZE = 13
PACKET_ORDER = 1
OPERATION = 0

PACKET_BUFFER = []

INITIAL_ACK = False
HAS_KAR_ARRIVED = True
SIMULATE_ERROR = False

TOTAL_SENT = 0
TOTAL_RECEIVED = 0


###### FLAG FUNCTION, SAME FOR BOTH PROGRAMS ######


def get_flag(operation):
    if operation == ACK:
        operation = "_ACK"
        return operation
    if operation == RDY:
        operation = "_RDY"
        return operation
    if operation == END:
        operation = "_END"
        return operation
    if operation == WRT:
        operation = "_WRT"
        return operation
    if operation == PFL:
        operation = "_PFL"
        return operation
    if operation == NCK:
        operation = "_NCK"
        return operation
    if operation == KAR:
        operation = "_KAR"
        return operation
    if operation == SWR:
        operation = "_SWR"
        return operation
    if operation == FIN:
        operation = "_FIN"
        return operation


###### FLAG FUNCTION, SAME FOR BOTH PROGRAMS ######

####################################### SENDER CODE ############################################
def decode_WRT(msg):
    global PACKET_ORDER
    order = PACKET_ORDER
    PACKET_ORDER += PACKET_ORDER
    operation = WRT
    total_packets = 0
    order = order.to_bytes(4, "big")
    operation = operation.to_bytes(1, "big")
    total_packets = total_packets.to_bytes(4, "big")
    msg = msg.encode()
    crc = libscrc.buypass(order + operation + total_packets + msg)
    crc = crc.to_bytes(4, "big")
    packet = order + operation + total_packets + msg + crc
    return packet

def decode_ACK(data):
    order = int.from_bytes(data[:4], "big")
    operation = int.from_bytes(data[4:5], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    msg = msg.decode()
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg.encode())
    opcode = get_flag(operation)
    if checksum == crc:
        packet = [order, opcode, total_packets, msg,  crc]
        return packet


def encode_multiple_packets(msg):
    global PACKET_ORDER, PACKET_BUFFER, FRAGMENT_HEAD_SIZE
    PACKET_BUFFER.clear()
    packet_cut = FRAGMENT_SIZE - FRAGMENT_HEAD_SIZE
    cut_string = [msg[i:i + packet_cut] for i in range(0, len(msg), packet_cut)]

    for i in range(len(cut_string)):
        order = PACKET_ORDER
        PACKET_ORDER += 1
        order = order.to_bytes(4, "big")
        operation = OPERATION
        operation = operation.to_bytes(1, "big")
        total_packets = len(cut_string)
        total_packets = total_packets.to_bytes(4, "big")
        cut_msg = cut_string[i].encode()
        crc = libscrc.buypass(order + operation + total_packets + cut_msg)
        crc = crc.to_bytes(4, "big")
        fragment_msg = order + operation + total_packets + cut_msg + crc
        PACKET_BUFFER.append(copy(fragment_msg))

    # create_END_packet()
    #print(PACKET_BUFFER)

def encode_file_packets(fileContent):
    global PACKET_ORDER, PACKET_BUFFER
    PACKET_BUFFER.clear()
    packet_cut = FRAGMENT_SIZE - FRAGMENT_HEAD_SIZE
    cut_string = [fileContent[i:i + packet_cut] for i in range(0, len(fileContent), packet_cut)]

    for i in range(len(cut_string)):
        order = PACKET_ORDER
        PACKET_ORDER += 1
        order = order.to_bytes(4, "big")
        operation = OPERATION
        operation = operation.to_bytes(1, "big")
        total_packets = len(cut_string)
        total_packets = total_packets.to_bytes(4, "big")
        cut_data = cut_string[i]
        crc = libscrc.buypass(order + operation + total_packets + cut_data)
        crc = crc.to_bytes(4, "big")
        fragment_msg = order + operation + total_packets + cut_data + crc
        PACKET_BUFFER.append(copy(fragment_msg))

    #print(PACKET_BUFFER)


def encode_KAR():
    order = 0
    operation = KAR
    total_packets = 1
    msg = "Keep alive request"
    order = order.to_bytes(4, "big")
    operation = operation.to_bytes(1, "big")
    total_packets = total_packets.to_bytes(4, "big")
    msg = msg.encode()
    crc = libscrc.buypass(order + operation + total_packets + msg)
    crc = crc.to_bytes(4, "big")
    packet = order + operation + total_packets + msg + crc
    return packet


def send_keep_alive_request(c, addr):
    while True:
        KAR_packet = encode_KAR()
        time.sleep(10)
        # print("Sending Keep alive request")
        c.sendto(KAR_packet, addr)

def encode_SWR():
    order = 0
    operation = SWR
    total_packets = 1
    msg = "Switch Roles"
    order = order.to_bytes(4, "big")
    operation = operation.to_bytes(1, "big")
    total_packets = total_packets.to_bytes(4, "big")
    msg = msg.encode()
    crc = libscrc.buypass(order + operation + total_packets + msg)
    crc = crc.to_bytes(4, "big")
    packet = order + operation + total_packets + msg + crc
    return packet

####################################### SENDER CODE ############################################

####################################### RECEIVER CODE ############################################

def decode_WRT(data, operation, opcode):
    global SIMULATE_ERROR
    order = int.from_bytes(data[:4], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg)
    if SIMULATE_ERROR:
        if random.randint(1, 2) == 1:
            checksum = checksum + checksum
            print("Wrong packet, requesting resending...")
    msg = msg.decode()
    if checksum == crc:
        packet = [order, opcode, total_packets, msg, crc]
        return packet
    else:
        packet = [0, "_NCK", 0, 0, 0]
        return packet


def decode_END(data, operation, opcode):
    order = int.from_bytes(data[:4], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg)
    msg = msg.decode()
    if checksum == crc:
        packet = [order, opcode, total_packets, msg, crc]
        return packet
    else:
        packet = [0, "_NCK", 0, 0, 0]
        return packet


def decode_PFL(data, operation, opcode):
    order = int.from_bytes(data[:4], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg)
    if SIMULATE_ERROR:
        if random.randint(1, 25) == 1:
            checksum = checksum + checksum
            print("Wrong packet")
    if checksum == crc:
        packet = [order, opcode, total_packets, msg, crc]
        return packet
    else:
        packet = [0, "_NCK", 0, 0, 0]
        return packet


def decode_KAR(data, operation, opcode):
    order = int.from_bytes(data[:4], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg)

    if checksum == crc:
        packet = [order, opcode, total_packets, msg, crc]
        return packet


def decode_SWR(data, operation, opcode):
    order = int.from_bytes(data[:4], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg)

    if checksum == crc:
        packet = [order, opcode, total_packets, msg, crc]
        return packet


def decode_FIN(data, operation, opcode):
    order = int.from_bytes(data[:4], "big")
    total_packets = int.from_bytes(data[5:9], "big")
    msg = data[9:-4]
    crc = int.from_bytes(data[-4:], "big")
    checksum = libscrc.buypass(order.to_bytes(4, "big") + operation.to_bytes(1, "big") +
                               total_packets.to_bytes(4, "big") + msg)

    if checksum == crc:
        packet = [order, opcode, total_packets, msg, crc]
        return packet


def decode_data(data):
    global OPERATION
    operation = int.from_bytes(data[4:5], "big")
    opcode = get_flag(operation)
    if opcode == "_WRT":
        OPERATION = "_WRT"
        packet = decode_WRT(data, operation, opcode)
        return packet
    if opcode == "_END":
        OPERATION = "_END"
        packet = decode_END(data, operation, opcode)
        return packet
    if opcode == "_PFL":
        OPERATION = "_PFL"
        packet = decode_PFL(data, operation, opcode)
        return packet
    if opcode == "_KAR":
        OPERATION = "_KAR"
        packet = decode_KAR(data, operation, opcode)
        return packet
    if opcode == "_SWR":
        OPERATION = "_SWR"
        packet = decode_SWR(data, operation, opcode)
        return packet
    if opcode == "_FIN":
        OPERATION = "_FIN"
        packet = decode_FIN(data, operation, opcode)
        return packet


def encode_ACK():
    order = 0
    opcode = 0
    msg = "Acknowledgement"
    total_packets = 1
    order = order.to_bytes(4, "big")
    opcode = opcode.to_bytes(1, "big")
    total_packets = total_packets.to_bytes(4, "big")
    msg = msg.encode()
    crc = libscrc.buypass(order + opcode + total_packets + msg)
    crc = crc.to_bytes(4, "big")
    packet = order + opcode + total_packets + msg + crc
    return packet


def encode_NCK():
    order = 0
    opcode = 6
    msg = "Not acknowledged"
    total_packets = 1
    order = order.to_bytes(4, "big")
    opcode = opcode.to_bytes(1, "big")
    total_packets = total_packets.to_bytes(4, "big")
    msg = msg.encode()
    crc = libscrc.buypass(order + opcode + total_packets + msg)
    crc = crc.to_bytes(4, "big")
    packet = order + opcode + total_packets + msg + crc
    return packet


def get_keep_alive_timer(s):
    while True:
        time.sleep(20)
        if HAS_KAR_ARRIVED:
            print(f"Received Keep alive request")
        else:
            sys.exit()


def list_to_string(list):
    str = ""
    for i in list:
        str += i
    return str


def bytes_array_to_file(data):
    bytes_array = bytearray()
    for i in data:
        bytes_array += i
    filePath = input("Enter download path: ")
    fileName = input("Enter name of the file: ")
    if os.path.exists(filePath):
        filePath = filePath + "\\" + fileName
        with open(filePath, "wb+") as bin_file:
            bin_file.write(bytes_array)
    print(f"File successfully downloaded on {filePath}")
    return

####################################### RECEIVER CODE ############################################

####################################### CLIENT CODE ############################################
def client():
    global INITIAL_ACK, HOST, PORT, OPERATION, PACKET_ORDER, TOTAL_SENT, TOTAL_RECEIVED
    INITIAL_ACK = False
    HOST = "192.168.56.1"
    PORT = 5555
    HOST = input(f"Current host IP is {HOST}, please select your server IP: ")
    PORT = int(input(f"Current port is {PORT}, please select your port: "))
    serverAddressPort = (HOST, PORT)
    c = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    keep_alive_thread = threading.Thread(target=send_keep_alive_request, args=(c, serverAddressPort))
    keep_alive_thread.start()
    while True:
        if not INITIAL_ACK:
            c.sendto(bytesToSend, serverAddressPort)
            TOTAL_SENT = TOTAL_SENT + 13
            msgFromServer = c.recvfrom(FRAGMENT_SIZE)
            TOTAL_RECEIVED = TOTAL_RECEIVED + 13
            msg = "Message from Server {}".format(msgFromServer[0])
            print(msg)
            INITIAL_ACK = True

        packetType = input("Are you sending a message or a file, switching roles or ending communication"
                           "?\n (msg/file/switch/end)\n")

        if packetType == "msg":
            msg = input("type your message: ")

            OPERATION = WRT
            encode_multiple_packets(msg)
            for i in range(len(PACKET_BUFFER)):
                c.sendto(PACKET_BUFFER[i], serverAddressPort)
                TOTAL_SENT = TOTAL_SENT + 13

                ACK_packet = c.recvfrom(FRAGMENT_SIZE)
                TOTAL_RECEIVED = TOTAL_RECEIVED + 13
                ACK_packet = ACK_packet[0]
                ACK_packet = decode_ACK(ACK_packet)
                print(ACK_packet)
                while ACK_packet[1] == "_NCK":
                    print(f"Failed to send packet number {i+1}, resending packet...\n")
                    c.sendto(PACKET_BUFFER[i], serverAddressPort)
                    TOTAL_SENT = TOTAL_SENT + 13
                    ACK_packet = c.recvfrom(FRAGMENT_SIZE)
                    TOTAL_RECEIVED = TOTAL_RECEIVED + 13
                    ACK_packet = ACK_packet[0]
                    ACK_packet = decode_ACK(ACK_packet)

                print(f"Packet number {i+1} was sent successfully. Yay :D\n")



        ### FILE ################################################

        elif packetType == "file":
            OPERATION = PFL
            filePath = input("Enter filepath to your file you wish to send: ")
            fileName = input("Enter filename of the file you wish to send: ")
            if os.path.exists(filePath):
                filePath = filePath + "\\" + fileName
                if os.path.exists(filePath):
                    with open(filePath, "rb") as bin_file:
                        fileContent = bin_file.read()
                    encode_file_packets(fileContent)
                    for i in range(len(PACKET_BUFFER)):
                        c.sendto(PACKET_BUFFER[i], serverAddressPort)
                        TOTAL_SENT = TOTAL_SENT + 13

                        ACK_packet = c.recvfrom(FRAGMENT_SIZE)
                        ACK_packet = ACK_packet[0]
                        ACK_packet = decode_ACK(ACK_packet)

                        while ACK_packet[1] == "_NCK":
                            print(f"Failed to send packet number {i+1}, resending packet...\n")
                            c.sendto(PACKET_BUFFER[i], serverAddressPort)
                            TOTAL_SENT = TOTAL_SENT + 13
                            ACK_packet = c.recvfrom(FRAGMENT_SIZE)
                            TOTAL_RECEIVED = TOTAL_RECEIVED + 13
                            ACK_packet = ACK_packet[0]
                            ACK_packet = decode_ACK(ACK_packet)

                        print(f"Packet number {i+1} was sent successfully. Yay :D\n")

                else:
                    print("File does not exist")
            else:
                print("Directory or patch to it does not exist")

        ### FILE ################################################

        elif packetType == "switch":
            SWR_packet = encode_SWR()
            c.sendto(SWR_packet, serverAddressPort)
            TOTAL_SENT = TOTAL_SENT + 13
            server()

        PACKET_ORDER = 1
        OPERATION = 0
####################################### CLIENT CODE ############################################

####################################### SERVER CODE ############################################


def server():
    global INITIAL_ACK, HOST, PORT, TOTAL_SENT, TOTAL_RECEIVED
    INITIAL_ACK = False
    HOST = "192.168.56.1"
    PORT = 5555
    HOST = input(f"Current host IP is {HOST}, please select your server IP: ")
    PORT = int(input(f"Current port is {PORT}, please select your port: "))
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.bind((HOST, PORT))
    print("UDP server up and listening")

    # keep_alive_thread_server = threading.Thread(target=get_keep_alive_timer, args=(s,))
    # keep_alive_thread_server.start()
    full_msg = []
    while True:
        if not INITIAL_ACK:
            bytesAddressPair = s.recvfrom(FRAGMENT_SIZE)
            message = bytesAddressPair[0]
            address = bytesAddressPair[1]
            clientMsg = "Message from Client:{}".format(message)
            clientIP = "Client IP Address:{}".format(address)
            print(clientMsg)
            print(clientIP)
            # Sending a reply to client
            s.sendto(bytesToSend, address)
            INITIAL_ACK = True

        msg = s.recvfrom(FRAGMENT_SIZE)
        msg = msg[0]
        packet = decode_data(msg)
        if packet[1] != "_KAR":
            TOTAL_RECEIVED = TOTAL_RECEIVED + 13
        print(f"Length of fragment: {len(msg)}\n"
              f"Order: {packet[0]}\n"
              f"Operation: {packet[1]}\n"
              f"Total_packets: {packet[2]}\n"
              f"Message: {packet[3]}\n"
              f"Checksum: {packet[4]}\n")
        if packet[1] == "_SWR":
            print(f"Poslana rezai: {TOTAL_SENT}\n"
                  f"Prijdena rezia: {TOTAL_RECEIVED}")
            break

        if packet[1] == "_FIN":
            print(f"Connection with {clientIP} ended.\n")
            ACK_packet = encode_ACK()
            s.sendto(ACK_packet, address)
            TOTAL_SENT = TOTAL_SENT + 13
            print(f"Poslana rezai: {TOTAL_SENT}\n"
                  f"Prijdena rezia: {TOTAL_RECEIVED}")
            sys.exit()

        if packet[1] != "_NCK" and packet[1] != "_KAR":
            full_msg.append(copy(packet[3]))
            ACK_packet = encode_ACK()
            s.sendto(ACK_packet, address)
            TOTAL_SENT = TOTAL_SENT + 13
        if packet[1] == "_NCK":
            NCK_packet = encode_NCK()
            s.sendto(NCK_packet, address)
            TOTAL_SENT = TOTAL_SENT + 13

        if packet[0] == packet[2] and OPERATION == "_WRT" and packet[1] != "_NCK":
            str = list_to_string(full_msg)
            print(str)
            print("\n")
            del str
            full_msg.clear()

        if packet[0] == packet[2] and OPERATION == "_PFL" and packet[1] != "_NCK":
            bytes_array_to_file(full_msg)
            full_msg.clear()
        print(f"Poslana rezai: {TOTAL_SENT}\n"
              f"Prijdena rezia: {TOTAL_RECEIVED}")

    client()

####################################### SERVER CODE ############################################


if __name__ == "__main__":
    server()
