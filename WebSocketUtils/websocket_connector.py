import asyncio
import websockets
import time
import json
import random
import zlib  #for compression
from .websocket_utils import delete_element_from_nested_list_dict



class ConnectionHandler:
    """a class to handle all connections, both for the server and the client side.
    As a server, execute ConnectionHandler.accept_connections() after instantiating the object.
    All active connections are saved in the dictionary self.connections, possibly with subgroupings
    to create hierarchical groups
    """
    def __init__(self, authenticator, message_manager):
        self.connections = {}
        self.loop = asyncio.get_event_loop()
        self.authenticator = authenticator
        self.message_manager = message_manager

    # --------------------------------------------------

    def accept_connections(self, port, ip_filter = '0.0.0.0'):
        try:
            asyncio.get_event_loop().run_until_complete(websockets.serve(self.websocket_handler, ip_filter, port))
            print(f' ********* accepting connections on port {port} from {ip_filter} ************** ')
            #loop.run_forever()   #don't call this here in case multiple accept_connections are called from a higher level. Only call this once all coroutines have been added to the event loop
        except Exception as exc:
            print(f'problem occurred in ConnectionHandler.accept_connections({ip_filter}, {port}): {exc}')

    # --------------------------------------------------

    async def connect_to_host(self, host_ip, host_port, attempt_reconnect_if_dropped = False):
        print(f'connect_to_host called with {host_ip}  and {host_port}')
        try:
            async with websockets.connect(f'ws://{host_ip}:{host_port}') as websocket:
                this_connection = None   # allocate that this exists for cleanup
                auth_results = {}
                if await self.authenticator.auth_me_to_host(this_websocket=websocket, auth_results=auth_results, connections=self.connections):
                    print('successfully connected and authenticated to host.')
                else:
                    print('authenticated to host not successful. Quitting connection attempt.')
                    return False

                try:
                    this_connection = auth_results['this_connection']
                    while True:  # keep this loop running for this connection as long as it is open
                        try:
                            received_data = await this_connection.recv()
                            asyncio.get_event_loop().create_task(self.message_manager.process_message(received_data))  # just launch it to return to receiving, don't gather anywhere.
                        except:
                            print(f'problem in the receive loop for connection {str(auth_results)}')
                            break

                except Exception as exc:
                    print(f'problem in receive loop for connection {str(auth_results)}. Exception: {exc}')
                finally:  #clean up this connection: remove from all occurences in the dictionary
                    print('------------- connection closed ------------- ')
                    delete_element_from_nested_list_dict(self.connections, this_connection)  #cleans up as long as this is a structure of nested dicts and lists
        except Exception as exc2:
            print(f'problem in outer connection loop for connection. Exception: {exc2}')
        finally:
            if attempt_reconnect_if_dropped:
                await asyncio.sleep(3)
                print(f'attempting reconnecting to {host_ip}:{host_port}')
                asyncio.get_event_loop().create_task(self.connect_to_host(host_ip, host_port, attempt_reconnect_if_dropped))  # python 3.7 supports asyncio.create_task(...)


    # --------------------------------------------------


    class connection():
        """a class wrapping a connection individually. Different encryption and compression methods
        may be used on a connection-specific basis."""
        def __init__(self, this_socket, use_compression = False, AES_encryptor = None):
            self.id = None
            self.this_socket = this_socket
            self.AES_encryptor = AES_encryptor
            self.use_compression = use_compression
            self.zlib_compression_level = 6  #ranges between [0, 9]  (0 = no compression), see https://stackabuse.com/python-zlib-library-tutorial/
            self.time_established = None

        async def send(self, msg):
            if type(msg) is dict:
                msg = json.dumps(msg)


            if self.use_compression:
                msg = zlib.compress(msg.encode('utf-8'), self.zlib_compression_level)
            if self.AES_encryptor:
                msg = self.AES_encryptor.encrypt(msg)
            #print('actually sending: ' + str(msg) )
            try:
                await self.this_socket.send(msg)
            except:
                import traceback
                traceback.print_exc()
                print(f"problem in ConnectionHandler.connection.send with msg = {msg}")


        async def recv(self):

            msg = await self.this_socket.recv()
            #print('actually received: ' + str(msg))
            if self.AES_encryptor:   #if this is defined, use encryption
                msg = self.AES_encryptor.decrypt(msg)
            if self.use_compression:
                msg = zlib.decompress(msg).decode('utf-8')
            return msg

    # --------------------------------------------------

    async def websocket_handler(self, this_websocket, path):
        """this function is executed by the server each time a new client attempts to connect.
        this_websocket is passed by the websocket routine in start_server.
        1) identify the category of the connection
        2) verify that this is legitimate
        3) save the connection object created from this_websocket into the respective connection group
        4) this function keeps running listening on the port for incoming data.
        5) cleanup: remove the connection object from all groups if the connection is closed."""
        print("Entered Handler")
        print('---- connection accepted by handler ----------- ')
        this_connection = None  #allocate that this exists for cleanup
        auth_results = {}   #the authentication routine will write its results in here
        try:
            if await self.authenticator.auth_incoming(this_websocket=this_websocket, auth_results=auth_results, connections=self.connections):
                print('authentication successful')
            else:
                print('authentication failed. Exiting websocket handler')
                return
        except Exception as ex:
            print(f'error occurred in authentication: {str(ex)}')

        try:
            this_connection = auth_results['this_connection']  #get the connection object from the dictionary passed back from the authenticator, where the connector was created
            while True:    #keep this loop running for this connection as long as it is open
                try:
                    received_msg_str = await this_connection.recv()
                    connection_and_msg_str = {'connection': this_connection, 'receivedMsgStr': received_msg_str}    #the connection needs to be passed along to know exactly which lambda fct ws connection to return the state to
                    asyncio.get_event_loop().create_task(self.message_manager.process_message(connection_and_msg_str))    #just launch it to return to receiving, don't gather anywhere.

                except:
                    #print(f'problem in the receive loop for connection {auth_results}')
                    break
        except Exception as exc:
            print(f'problem in connection {str(auth_results)}. Exception: {exc}')

        finally:
            # remove this websocket from all places it was saved in the dictionary
            #print('------------- connection closed ------------- ')
            delete_element_from_nested_list_dict(self.connections, this_connection)




