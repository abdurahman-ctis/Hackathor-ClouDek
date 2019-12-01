import asyncio
import json
import time
from .sangoma_utils import AES_encrypt
from .sangoma_connector import ConnectionHandler

def setG(global_G):
    global G
    G = global_G

# Added
class MonitoringServiceAuthenticator():

    def __init__(self):
        self.connection_id_counter = 0

    async def auth_incoming(self, this_websocket, auth_results, connections):
        """
        this_websocket: the current websocket connection object
        auth_results:
        connections: the connection pool to which the websocket is added if authentication is sucessful
        """
        global G
        try:
            first_message = await this_websocket.recv()   # the very first message from the other server needs to have a specific format
            print(first_message)
            # TODO: Make Authorization check here, Currently accepts any connection
            this_connection = ConnectionHandler.connection(this_websocket, use_compression=False, AES_encryptor=None)  # wrap this as a connection object
            this_connection.id = self.connection_id_counter
            this_connection.time_established = time.time()
            connections[self.connection_id_counter] = this_connection
            auth_results['this_connection'] = this_connection
            self.connection_id_counter += 1
            return True
        except:
            print("Failed Here")
            return False




