import json
from time import time
from urllib.parse import urlparse

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from flask import Flask, request
from flask_cors import CORS
from flask_restful import Resource, Api
from flask_socketio import SocketIO

cred = credentials.Certificate('ids-hackathor-636a3e9f4e4c.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ids-hackathor.firebaseio.com/'
})
ref = db.reference('')

with open('payloads.json', encoding="utf8") as f:
    loaded = json.load(f)
    XSS = loaded['XSS']
    TRAVERS = loaded['TRAVERS']

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'secret!'
cors = CORS(app)
socketio = SocketIO(app)
DOMAIN = "bilkent.com"

#Zeyad Additions
#------------------------------------
from SangomaUtils.sangoma_authenticators import *
import asyncio
WEBSOCKETS_PORT = 6666

G = {}  # Global Dictionary

def start_websocket_server(port):
        global G
        import SangomaUtils.sangoma_authenticators
        SangomaUtils.sangoma_authenticators.setG(G)
        """accepts connections from incoming lambda function requests"""
        services_authenticator = MonitoringServiceAuthenticator()
        services_message_manager = MessageManagerWebsocketFromServices()
        G['lambda_connection_handler'] = ConnectionHandler(authenticator=services_authenticator,
                                                           message_manager=services_message_manager)
        G['lambda_connection_handler'].accept_connections(port=port)

class MessageManagerWebsocketFromServices:

    async def process_message(self, connection_and_msg):
        '''look at the incoming event (message/command), determine its priority and add it to the eventQ saved
        in the global obejct G.'''


    @staticmethod
    def report_to_connections(event):
        for connection in G['lambda_connection_handler'].connections:
            asyncio.ensure_future(G['lambda_connection_handler'].connections[connection].send(event))

#MessageManagerWebsocketFromServices.report_to_connections(event)  # Reporting to WSS subscribers

# -----------------------------------------------------------------


def send_ref(ip, param, val, type):
    ref.push({
        "ip": ip,
        "type": type,
        "query_key": param,
        "query_val": val,
        "timestamp": time()
    })


def not_same_domain(url):
    url = urlparse(url).netloc
    index = url.find("@")
    if index != -1:
        url = url[index + 1:]
    return url != DOMAIN


class AnalyzeQuery(Resource):
    def get(self):
        return db.reference('').get()

    def post(self):
        params = request.get_json(force=True)
        ip = request.remote_addr
        for param, val in params.items():
            # XSS
            for pload in XSS:
                if pload in val:
                    send_ref(ip, param, val, 'XSS')
                    break
            # SQLi
            if "'" in val and ('and' in val.lower() or 'or' in val.lower()) or '--' in val:
                send_ref(ip, param, val, 'SQLi')
            # CRLF
            if '%0d' in val.lower() or '%0a' in val.lower():
                send_ref(ip, param, val, 'CRLF')
            # OPEN Redirect
            if len([i for i in ['url', 'redirect', 'next'] if i in param.lower()]) > 0 \
                    and not_same_domain(val):
                send_ref(ip, param, val, 'Open Redirect')
            # Path Traversal
            for pload in TRAVERS:
                if pload in val:
                    send_ref(ip, param, val, 'Path Traversal')
                    break

        return params


api.add_resource(AnalyzeQuery, '/api/query')

if __name__ == '__main__':
    
    start_websocket_server(WEBSOCKETS_PORT)
    app.run(host='0.0.0.0')
