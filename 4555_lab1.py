from random import *
import socket
import sys
import struct 
import sys
import os
import enum


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.

    Failing to comply with those requirements will invalidate
    your submission.

    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2

    def __init__(self,file_name):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """

        self.packet_buffer = []
        self.file_name=file_name
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data) # pack inside another pack 
        out_packet = self._do_some_logic(in_packet) # send to port 

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine 
        the type of the packet and extract other available
        information.
        """
        f = open(self.file_name,"r") 
        my_File=f.read()
        temp_Arr=[]
        count=0
        while count<=len(my_File) : 
            temp_Arr.append(my_File[count:count+512])
            count=count+512
        count=0
        print("here"+str(len(temp_Arr)))
        while count<len(temp_Arr):
            my_String=temp_Arr.pop(count)
            my_String_in_ASCII=bytes(my_String,"ascii") 
            my_packet=struct.pack(str(len(my_String_in_ASCII)) + 's',my_String_in_ASCII)
            print(my_packet)
            self.packet_buffer.append(my_packet)
            count=count+1
        
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        
        pass

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        opcode=bytes([1]) 
        fileName_in_ASCII=bytes(file_path_on_server,"ascii")  
        mode_in_ASCII=bytes("octet","ascii") 
        RRQ=struct.pack('IsIsI',opcode,fileName_in_ASCII,0 , mode_in_ASCII,0)
        return RRQ
        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        
        """
        opcode=bytes([2]) 
        fileName_in_ASCII=bytes(file_path_on_server,"ascii")                
        mode_in_ASCII=bytes("octet","ascii") 
        WRQ=struct.pack('Ishsh',opcode,fileName_in_ASCII,bytes([0]) , mode_in_ASCII,bytes([0]))   # lengths 
        return WRQ
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    # Create a UDP socket
    sck= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the port
    server_address = (address, 69)
    print('starting up on {} port {}'.format(*server_address))
    return sck,server_address
    pass


def do_socket_logic(command_type,file_name,my_Socket,my_Server_adr):
    tftp_obj= TftpProcessor(file_name)

    if command_type=="push":
        WRQ=tftp_obj.upload_file(file_name)
        my_Socket.sendto(WRQ,my_Server_adr) # mtnsash t7t recieve from 
        ack, block_num = my_Socket.recvfrom(4)
        if b'04'==ack:
            while tftp_obj.has_pending_packets_to_be_sent():
                my_packet=tftp_obj.get_next_output_packet()
                my_Socket.sendto(my_packet,my_Server_adr)
                ack, block_num = my_Socket.recvfrom(4)
                if b'04'!=ack:
                    print("error packet is not acknowledged")
                    break
                
        

    elif command_type=="pull":
        RRQ=tftp_obj.request_file(file_name)
        my_Socket.sendto(RRQ,my_Server_adr)
        data , block_num , data = my_Socket.recvfrom(512)

    pass


def parse_user_input(address, operation, file_name):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    my_Socket,my_Server_adr=setup_sockets(address)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        do_socket_logic("push",file_name,my_Socket,my_Server_adr)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic("pull",file_name,my_Socket,my_Server_adr)
        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():

    my_input=  input("Enter your value: ") 
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()

    print("*" * 50)
    
    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.

    ip_address = get_arg(1, my_input.split(' ')[0])
    operation = get_arg(2, my_input.split(' ')[1])
    file_name = get_arg(3, my_input.split(' ')[2])

    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()