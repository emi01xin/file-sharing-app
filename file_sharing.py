# Xin Ran Wang
# 400264245

import argparse
from ctypes.wintypes import MSG
import socket
import sys
import threading
import os

# Server Commands
SERVER_LIST_CMD     = "list"
SERVER_PUT_CMD      = "put"
SERVER_GET_CMD      = "get"  

SERVER_CMDS = {
    SERVER_LIST_CMD : 2,
    SERVER_PUT_CMD  : 3,
    SERVER_GET_CMD  : 4
}

# Client Commands
CLIENT_SCAN_CMD         = "scan"
CLIENT_CONNECT_CMD      = "Connect"
CLIENT_LOCAL_LIST_CMD   = "llist"
CLIENT_REMOTE_LIST_CMD  = "rlist"
CLIENT_PUT_CMD          = "put"
CLIENT_GET_CMD          = "get"
CLIENT_BYE_CMD          = "bye"

# Defaults
DEFAULT_SHARING_DIR     = "./"
SERVICE_DISCOVERY_PORT  = 30000
FILE_SHARING_PORT       = 30001

# File Sharing Params
CMD_FIELD_LEN            = 1 # Length of command field in bytes
FILENAME_SIZE_FIELD_LEN  = 1 # Length of file name size field in bytes
FILESIZE_FIELD_LEN       = 8 # Length of file size field in bytes
MSG_ENCODING = "utf-8"  # Encoding to use for message strings
SOCKET_TIMEOUT = 4  # Socket timeout in seconds

SERVER_DIR = "./server_dir/"
CLIENT_DIR = "./client_dir/"

# Read a specified number of bytes from a socket using recv. Return a tuple of status (True or False) and received bytes (in the former case)
def recv_bytes(sock, bytecount_target):
    try:
        byte_recv_count = 0 # Total number of received bytes
        recv_bytes = b''    # All received bytes
        while byte_recv_count < bytecount_target:
            # Request the remaining bytes from the socket
            new_bytes = sock.recv(bytecount_target-byte_recv_count)
            # If the other end closes before all bytes are received, return False status and zero bytes
            if not new_bytes:   
                return(False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off socket timeout if all bytes are received        
        return (True, recv_bytes)
    # If socket times out, return False status
    except socket.timeout:  
        sock.settimeout(None)        
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')

# Sends bytes over socket connection
def send_bytes(sock, msg_send):
    try:
        # Convert string to bytes and send it over the connection
        sock.sendall(msg_send.encode(MSG_ENCODING))
    except Exception as msg:
        # Print error message and exit program
        print(msg)
        sys.exit(1)

class Server:
    # Server constants
    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_DISCOVERY_ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_DISCOVERY_PORT)
    FILE_SHARING_ADDRESS_PORT = (ALL_IF_ADDRESS, FILE_SHARING_PORT) 
    
    SCAN_MSG = "SERVICE DISCOVERY"

    SCAN_RESP_MSG = "Emily's File Sharing Service"
    SCAN_RESP_MSG_ENCODED = SCAN_RESP_MSG.encode(MSG_ENCODING)

    RECV_SIZE = 1024
    BACKLOG = 5

    def __init__(self):
        self.create_sockets()
        dir_list = str(os.listdir(SERVER_DIR)) # Prints server directory 
        
        print("Current Directory List: ", dir_list)

        service_disc_thread = threading.Thread(target=self.receive_broadcast_forever, args=())
        file_share_thread   = threading.Thread(target=self.receive_file_share_forever, args=())

        service_disc_thread.start()
        file_share_thread.start()

    # Create sockets for the server
    def create_sockets(self):
        try:
            # Create IPv4 UDP and TCP sockets
            self.disc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Enable socket option to reuse address
            self.disc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.file_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind sockets to IP address and port
            self.disc_socket.bind( Server.SERVICE_DISCOVERY_ADDRESS_PORT )
            self.file_socket.bind( Server.FILE_SHARING_ADDRESS_PORT )

        except Exception as msg:
            # Print error message and exit program
            print(msg)
            sys.exit(1)

    # Listen for file sharing connections forever
    def receive_file_share_forever(self):
        # Listen on file sharing socket
        self.file_socket.listen(Server.BACKLOG)
        print("FILE SHARING SERVICE: Listening on port {} ...".format(FILE_SHARING_PORT))
        try:
            # Accept incoming connections and handle them
            while True:
                conn, addr = self.file_socket.accept()
                self.connection_handler(conn, addr)
        except Exception as msg:
            # Print error message
            print(msg)
        except KeyboardInterrupt:
            # Print newline character on keyboard interrupt
            print()
        finally:
            # Close file sharing socket and exit program
            self.file_socket.close()
            sys.exit(1)

    # Handle a connection from a client
    def connection_handler(self, client):
        # Get the connection and client address
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))

        while (True):   
            # Read the command and see if it is a GET command
            status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)

            # If the read fails, close the connection and return
            if not status:
                print("Connection closed!")
                connection.close()
                return

            # Convert the command to an integer
            cmd = int.from_bytes(cmd_field, byteorder='big')
            print(cmd)

            # Take action based on the command
            if cmd == SERVER_CMDS[SERVER_GET_CMD]:
                if (self.send_file(connection) == False):
                    return
            elif cmd == SERVER_CMDS[SERVER_LIST_CMD]:
                self.send_dir_list(connection)
            elif cmd == SERVER_CMDS[SERVER_PUT_CMD]:
                self.recieve_file(connection)
            else:
                print("INVALID command received. Connection closed!")
                connection.close()
                return 

    def send_dir_list(self, connection):
        # Get the list of files in the server directory and convert it to a string
        dir_list = str(os.listdir(SERVER_DIR))

        # Encode the directory list string using the specified encoding
        dir_list_bytes = dir_list.encode(MSG_ENCODING)

        # Get the size of the encoded directory list in bytes
        dir_list_size_bytes = len(dir_list_bytes)

        # Convert the directory list size to a byte string of a fixed length
        dir_list_size_field = dir_list_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Combine the directory list size field and the encoded directory list to form a packet to be sent
        pkt = dir_list_size_field + dir_list_bytes
        
        try:
            # Send the packet to the connected client
            connection.sendall(pkt)
            
            print("Sending directory list: ", dir_list)
            print("Directory list size field: ", dir_list_size_field.hex(), "\n")
        except socket.error:
            # If the client has closed the connection, close the socket on this end
            print("Connection closed!")
            connection.close()
            return  

    def send_file(self, connection):
            # Receive the size of the filename field in bytes
            status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
            if not status:
                print("Connection closed!")            
                connection.close()
                return False

            # Convert the size field to an integer
            filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')

            # Check if the filename size is zero, which indicates a closed connection
            if not filename_size_bytes:
                print("Connection closed!")
                connection.close()
                return False
            
            print('Filename size (bytes): ', filename_size_bytes)

            # Receive the filename bytes and decode them to get the filename
            status, filename_bytes = recv_bytes(connection, filename_size_bytes)
            if not status:
                print("Connection closed!")            
                connection.close()
                return False

            # Check if the filename is empty, which indicates a closed connection
            if not filename_bytes:
                print("Connection closed!")
                connection.close()
                return False
            
            filename = filename_bytes.decode(MSG_ENCODING)
            print('Requested filename: ', filename)

            # Try to open the requested file and read its contents
            # If the file cannot be found, close the connection and return False 
            try:
                file = open(os.path.join(SERVER_DIR, filename), 'rb').read() 
            except FileNotFoundError:
                print("Error: Requested file is not available!")
                connection.close()                   
                return False

            # Encode the file contents and get the size of the encoded bytes
            file_bytes = file
            file_size_bytes = len(file_bytes)

            # Convert the file size to a byte string of a fixed length
            file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

            # Combine the file size field and the encoded file contents to form a packet to be sent
            pkt = file_size_field + file_bytes
            
            try:
                # Send the packet to the connected client
                connection.sendall(pkt)
                print("Sending file: ", filename)
                print("file size field: ", file_size_field.hex(), "\n")
            except socket.error:
                # If the client has closed the connection, close the socket on this end
                print("Connection closed!")
                connection.close()
                return False

    def recieve_file(self, connection):
        # Receive the filename size field
        status, filename_size_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
        if not status:
            print("Connection closed!")            
            connection.close()
            return

        print("Filename size bytes: ", filename_size_bytes.hex())
        if len(filename_size_bytes) == 0:
            connection.close()
            return

        # Interpret the filename size in host byte order
        filename_size = int.from_bytes(filename_size_bytes, byteorder='big')
        print("Filename size: ", filename_size)

        # Receive the file data                   
        status, filename = recv_bytes(connection, filename_size)
        if not status:
            print("Connection closed!")            
            connection.close()
            return
        
        # Receive the file size field
        status, file_size_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
        if not status:
            print("Connection closed!")            
            connection.close()
            return

        print("File size bytes: ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            connection.close()
            return

        # Interpret the file size in host byte order
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size: ", file_size)

        # Receive the file data               
        status, recvd_bytes_total = recv_bytes(connection, file_size)
        if not status:
            print("Connection closed!")            
            connection.close()
            return
        
        print("File writing begins...")
        try:
            # Create a file using the received filename and store the data
            filename = filename_bytes.decode(MSG_ENCODING)
            print("Received ", len(recvd_bytes_total), " bytes. Creating file: ", filename)
            
            with open(os.path.join(SERVER_DIR, filename), 'wb') as f: 
                recvd_file = recvd_bytes_total
                f.write(recvd_file)
            
        except:
            print("Error writing file!")
            exit(1)

    # Define a method to receive broadcast messages forever
    def receive_broadcast_forever(self):
        # Print a message indicating that the service is listening on a specific port
        print("SERVICE DISCOVERY: Listening on port {} ...".format(FILE_SHARING_PORT))

        # Enter an infinite loop to keep receiving broadcast messages
        while True:
            try:
                # Receive a message and the address of the sender
                recvd_bytes, address = self.disc_socket.recvfrom(Server.RECV_SIZE)

                # Print the received message and its sender's address
                print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
            
                # Decode the received bytes into a string
                recvd_str = recvd_bytes.decode(MSG_ENCODING)

                # If the received message is a service scan command, send a response back to the sender
                if recvd_str == Server.SCAN_MSG.strip():
                    self.disc_socket.sendto(Server.SCAN_RESP_MSG_ENCODED, address)
            except KeyboardInterrupt:
                # If the user interrupts the program, print a newline and exit
                print()
                sys.exit(1)

class Client:
    RECV_SIZE = 1024
    BROADCAST_ADDRESS = "255.255.255.255"    
    BROADCAST_ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_DISCOVERY_PORT)
    SCAN_TIMEOUT = 2
    SCAN_MSG = "SERVICE DISCOVERY"
    SCAN_MSG_ENCODED = SCAN_MSG.encode(MSG_ENCODING)

    def __init__(self):
        # Set up the server's sockets and handle console input forever
        self.socket_setup()
        self.handle_console_input_forever()

    # Define a method to connect to a server given its address and port
    def connect_to_server(self, address_port):
        # Print a message indicating that the server is connecting to the specified address and port
        print("Connecting to:", address_port)
        try:
            # Attempt to connect to the server using its socket address tuple
            self.file_socket.connect( address_port )
        except Exception as msg:
            # If an error occurs, print the error message and exit the program
            print(msg)
            sys.exit(1)

    # Define a method to set up the client's sockets
    def socket_setup(self):
        try:
            # Create a UDP socket for service discovery
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Allow reuse of the socket address
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Enable broadcasting of the socket
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Set the socket timeout for service scanning
            self.broadcast_socket.settimeout(Client.SCAN_TIMEOUT)
            
            # Create a TCP socket for later use
            self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       
        except Exception as msg:
            # If an error occurs, print the error message and exit the program
            print(msg)
            sys.exit(1)

    # Define a method to scan for services on the network
    def scan_for_service(self):
        # Initialize a variable to hold the results of the scan
        scan_results = None

        # Send a broadcast message to search for services
        print("Sending broadcast scan: '{}'".format(Client.SCAN_MSG))            
        self.broadcast_socket.sendto(Client.SCAN_MSG_ENCODED, Client.BROADCAST_ADDRESS_PORT)
    
        try:
            # Receive a response from a server and store the received message and address
            recvd_bytes, address_port = self.broadcast_socket.recvfrom(Client.RECV_SIZE) # socket configured to use timeout
            recvd_msg = recvd_bytes.decode(MSG_ENCODING)
            scan_results = (recvd_msg, address_port)
        except socket.timeout:
            # If a timeout occurs, we are finished scanning
            pass

        # Output the results of the scan
        if scan_results:
            for result in scan_results:
                print(result)
        else:
            print("No services found.")

        return scan_results

    # Define a method to retrieve a remote file list from the server
    def get_remote_list(self):
        # Build the packet containing the list command
        cmd_field = SERVER_CMDS[SERVER_LIST_CMD].to_bytes(CMD_FIELD_LEN, byteorder='big')
        pkt = cmd_field

        # Send the list command packet to the server
        self.file_socket.sendall(pkt)

        # Receive the size of the file list from the server
        status, file_size_bytes = recv_bytes(self.file_socket, FILESIZE_FIELD_LEN)
        if not status:
            print("Connection closed!")            
            self.file_socket.close()
            return

        if len(file_size_bytes) == 0:
            self.file_socket.close()
            return

        # Interpret the received file size in host byte order
        resp_bytes_length = int.from_bytes(file_size_bytes, byteorder='big')

        # Receive the entire file list from the server                  
        status, recvd_bytes_total = recv_bytes(self.file_socket, resp_bytes_length)
        if not status:
            print("Connection closed!")            
            self.file_socket.close()
            return

        # Evaluate the received byte stream as a Python object
        remote_dir = eval(recvd_bytes_total.decode(MSG_ENCODING))

        # Print the size and contents of the remote directory
        print("Directory size: ", len(remote_dir))
        print(remote_dir)


    def handle_console_input_forever(self):
        while True:
            try:
                self.input_text = input("Enter Command: ")
                if self.input_text != "":
                    print("Command Entered: ", self.input_text)
                    if self.input_text == CLIENT_LOCAL_LIST_CMD:
                        print_str = "local list"    # List files in client directory
                        print(os.listdir(CLIENT_DIR))
                    elif self.input_text == CLIENT_REMOTE_LIST_CMD:
                        print_str = "remote list"   # List files in server directory
                        self.get_remote_list()
                    elif self.input_text == CLIENT_SCAN_CMD:
                        print_str = "scan"  # Scans network for available file-sharing servers
                        _, (self.server_addr, _) = self.scan_for_service()
                    elif self.input_text.split()[0] == CLIENT_CONNECT_CMD:
                        print_str = "connect"   # Connects to the specified file-sharing server
                        self.connect_to_server((self.server_addr, FILE_SHARING_PORT))
                    elif self.input_text.split()[0] == CLIENT_PUT_CMD:
                        print_str = "PUT"   # Uploads a file to the connected server
                        self.send_file(self.input_text.split()[1])
                    elif self.input_text.split()[0] == CLIENT_GET_CMD:
                        print_str = "GET"   # Downloads a file from the connected server
                        self.download_filename = self.input_text.split()[1]
                        self.get_file(self.download_filename)
                    elif self.input_text == CLIENT_BYE_CMD:
                        print_str = "BYE"   # Closes the connection with the server and exits the client
                        print("Closing Connection")
                        self.file_socket.close()
                    else:
                        print_str = "Unrecognized cmd.."
                        print(print_str)
                        continue

            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.file_socket.close()
                sys.exit(1)

    def send_file(self, filename):
        try:
            # Open the requested file and read its contents as bytes
            file_bytes = open(os.path.join(CLIENT_DIR, filename), 'rb').read() 
        except FileNotFoundError:
            # If the file is not found, print an error message and close the socket
            print("Error: Requested file was not found!")
            self.file_socket.close()                   
            return

        # Create the header fields for the packet
        cmd_field = SERVER_CMDS[SERVER_PUT_CMD].to_bytes(CMD_FIELD_LEN, byteorder='big') # command field
        filename_bytes = filename.encode(MSG_ENCODING) # filename field
        filename_size_field = len(filename_bytes).to_bytes(FILESIZE_FIELD_LEN, byteorder='big') # filename size field
        file_size_bytes = len(file_bytes) # file size field
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big') # file size field

        # Combine the header fields and file contents into a single packet
        pkt = cmd_field + filename_size_field + filename_bytes + file_size_field + file_bytes
        
        try:
            # Send the packet to the connected client
            self.file_socket.sendall(pkt)
            print("Sending file: ", filename)
            print("File size field: ", file_size_field.hex(), "\n")
            
        except socket.error:
            # If there's an error sending the packet, print an error message and close the socket
            print("Closing client connection ...")
            self.file_socket.close()
            return    

    def get_file(self, filename): 
        
        # Create a file transfer request to the server
        cmd_field = SERVER_CMDS[SERVER_GET_CMD].to_bytes(CMD_FIELD_LEN, byteorder='big')    

        # Create the packet fields for filename size and content
        filename_field_bytes = filename.encode(MSG_ENCODING)
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet by concatenating the command, filename size, and filename fields
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())
        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server
        self.file_socket.sendall(pkt)

        # Receive the file transfer response from the server
        status, file_size_bytes = recv_bytes(self.file_socket, FILESIZE_FIELD_LEN)  
        if not status:
            print("Connection closed!")            
            self.file_socket.close()
            return

        # Retrieve the file size from the received bytes
        print("File size bytes: ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            self.file_socket.close()
            return
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size: ", file_size)

        # Receive the file itself             
        status, recvd_bytes_total = recv_bytes(self.file_socket, file_size)
        if not status:
            print("Connection closed!")            
            self.file_socket.close()
            return

        # Write the received file to disk
        try:
            print("Received {} bytes. Creating file: {}".format(len(recvd_bytes_total), self.download_filename))
            with open(os.path.join(CLIENT_DIR, self.download_filename), 'wb') as f:
                recvd_file = recvd_bytes_total 
                f.write(recvd_file)
            
        except:
            print("Error writing file!")
            exit(1)

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, 
                        type=str, 
                        default='client')

    args = parser.parse_args()
    roles[args.role]()
