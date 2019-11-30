import asyncio
import json
import time
from .sangoma_utils import AES_encrypt
from .sangoma_connector import ConnectionHandler

def setG(global_G):
    global G
    G = global_G



class MainSystemServerLambdaAuthenticator():
    """
    For requests coming in from AWS lambda functions.
    Performs basic key authentication on the first message.
    """

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
            first_message = await this_websocket.recv()   #the very first message from the other server needs to have a specific format
            #G['logger'].log(f"first_message in MainSystemServerLambdaAuthenticator = |{first_message}|")
            D = json.loads(first_message)
            if D['authorization_key_used_by_incoming_aws_lambda_fcts'] == G['settings']['apis']['authorization_key_used_by_incoming_aws_lambda_fcts']:
                this_connection = ConnectionHandler.connection(this_websocket, use_compression=False, AES_encryptor=None)  # wrap this as a connection object
                this_connection.id = self.connection_id_counter
                this_connection.time_established = time.time()
                connections[self.connection_id_counter] = this_connection
                auth_results['this_connection'] = this_connection
                self.connection_id_counter += 1
                return True
            else:
                return False
        except:
            G['logger'].log('Error decoding first authentication message: {first_message}')
            return False


class WebClientAuthenticator:
    """
    an object of this type is instantiated, configured and passed to the ConnectionHandler object
    for server role:
    -   handles the authentication of any incoming connections,
        identifies and saves the connection object to the respective group
    for client role:
    -   Handles the authentication for connecting to the server
    """
    def __init__(self):
        self.connection_counter = 0  #help to create unique ids

    async def auth_incoming(self, this_websocket, auth_results, connections):


        #print('waiting for incoming message...')
        #msg = await this_websocket.recv()
        #print(f'msg = {msg}')

        this_connection = ConnectionHandler.connection(this_websocket, use_compression=False, AES_encryptor=None)  # wrap this as a connection object
        this_connection_id = 'conn_' + str(self.connection_counter)   #create a unique id. This can be extended to contain the client user name
        self.connection_counter += 1
        connections[this_connection_id] = this_connection
        auth_results['this_connection'] = this_connection
        print('incoming connection in WebClientAuthenticator accepted. No authentication performed.')
        return True

# --------------------------------------------------


class MainSystemServerAuthenticator:
    """
    used to handle the standardized authentication of one of the main system servers.
    """
    def __init__(self, use_compression=False, use_encryption=False):
        self.authentication_time_threshold = 60
        self.use_compression = use_compression
        self.use_encryption=use_encryption
        try:
            self.AES_encryptor = AES_encrypt(key_hex=G['settings']['communication_encryption_key_hex'])
        except:
            print('problem creating encryptor with hex key from settings file')

    async def auth_incoming(self, this_websocket, auth_results, connections):
        """returns True if client is authenticated, False if not.
        Other properties from the authentication are saved in auth_results.
        The connections dictionary is passed that the authentication routine can assign the connection object to the appropriate groups.
        The connection object is also returned in the auth_results (implicitly by reference)
        For authentication, the beginning of the message after encrypting needs to exactly match and the time difference
        between the send time and local system time needs to be lower than a threshold
        """

        raw = await this_websocket.recv()   #the very first message from the other server needs to have a specific format
        auth_msg = self.AES_encryptor.decrypt(raw)
        try:
            auth_dict = json.loads(auth_msg[33:])
            self.use_compression = auth_dict['use_compression']   #use the settings specified by the client
            self.use_encryption = auth_dict['use_encryption']
            t_diff = abs(auth_dict['time']-time.time())   #the time difference between the time marked in the authentication message and the current system time
            if auth_msg[:34] != 'ThisPreSnippetIsForAuthentication{' or t_diff>self.authentication_time_threshold:
                return False  #not properly authenticated

            #now assign the connection to a specific group
            this_connection = ConnectionHandler.connection(this_websocket, use_compression=self.use_compression, AES_encryptor=None)  #wrap this as a connection object
            if self.use_encryption:
                this_connection.AES_encryptor = AES_encrypt(key_hex=G['settings']['communication_encryption_key_hex'])

            #pass some parameters associated with this connection to the outside
            auth_results['service_id'] = auth_dict['service_id']
            auth_results['time_connected'] = round(time.time())
            auth_results['this_connection'] = this_connection


            #send confirmation message to client that connection is accepted
            await this_connection.send(json.dumps({
                "authentication_success" : True,
                "this_host_role": G["settings"]["this_host_role"]
            }))

            #assign this connection into connections[this_host_role][service_id]
            try:
                if auth_dict['this_host_role'] not in connections:
                    connections[auth_dict['this_host_role']] = {}

                if auth_dict['service_id'] in connections[auth_dict['this_host_role']]:
                    print(f'connection with name {auth_dict["service_id"]} already present in connections[{auth_dict["this_host_role"]}]. Rejecting new connection attempt')
                    return False

                connections[auth_dict['this_host_role']][auth_dict['service_id']] = this_connection   #e.g. connections['main_system_server']['Interoffshore']

            except Exception as exc:
                print(f'problem assigning connection from name transmitted by client. Exception: {exc} and auth_dict={str(auth_dict)}')
                return False

            return True   #authetication successful and connection assigned

        except Exception as exc:
            print(f'Error occurred in authentication: {exc}')
            return False

    async def auth_me_to_host(self, this_websocket, auth_results, connections):
        """returns True if the authentication was successful. Sets up the connection into the passed 'connections'
        dictionary with the key specified by the role of the server (given in its repsonse)."""
        try:
            first_auth_message = f'ThisPreSnippetIsForAuthentication' + json.dumps({
                "time": round(time.time(), 2),
                "this_host_role" : G["settings"]["this_host_role"],
                "service_id": G["settings"]["service_id"],
                "use_compression" : self.use_compression,   #for this channel
                "use_encryption" : self.use_encryption
            })
            enc = self.AES_encryptor.encrypt(first_auth_message)
            await this_websocket.send(enc)  # send the authentication message. Now wait for confirmation
        except:
            print(f'problem constructing or sending auth message in MainSystemServerAuthenticator.auth_me_to_host')


        #create the connection object
        this_connection = ConnectionHandler.connection(this_websocket, use_compression=self.use_compression, AES_encryptor=None)  # wrap this as a connection object
        if self.use_encryption:
            this_connection.AES_encryptor = AES_encrypt(key_hex=G['settings']['communication_encryption_key_hex'])

        #now get a response from the server that the authentication went well
        try:
            auth_response = json.loads(await this_connection.recv())
            if auth_response['authentication_success'] != True:
                return False   #not properly authenticated

            # now assign the connection to a specific group
            connections[auth_response['this_host_role']] = this_connection

            auth_results['partner_host_role'] = auth_response["this_host_role"]
            auth_results['time_connected'] = round(time.time())
            auth_results['this_connection'] = this_connection

            return True
        except Exception as exc:
            print(f'problem in receiving or decoding authorization response message from server {exc}')
            return False

# --------------------------------------------------
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
            # D = json.loads(first_message)
            # TODO: Make Authorization check here, Currently accepts any connection
            this_connection = ConnectionHandler.connection(this_websocket, use_compression=False, AES_encryptor=None)  # wrap this as a connection object
            this_connection.id = self.connection_id_counter
            this_connection.time_established = time.time()
            connections[self.connection_id_counter] = this_connection
            auth_results['this_connection'] = this_connection
            self.connection_id_counter += 1
            return True
        except:
            G['logger'].log('Error decoding first authentication message: {first_message}')
            return False




