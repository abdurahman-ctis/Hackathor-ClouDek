import asyncio
from api_endpoints import *
from tornado.ioloop import IOLoop
from tornado.platform.asyncio import AsyncIOMainLoop
from tornado.web import Application
from tornado.httpclient import AsyncHTTPClient
from SangomaUtils.sangoma_authenticators import *
import json
from time import time
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from requests import post
from SangomaUtils.sangoma_authenticators import *
import asyncio

WEBSOCKETS_PORT = 6666
TORNADO_PORT = 5555
TORNADO_DEBUG = True

G = {}  # Global Dictionary

class IDSService:
    def __init__(self):
        global G
        import SangomaUtils.sangoma_authenticators
        SangomaUtils.sangoma_authenticators.setG(G)
        self.start_websocket_server(WEBSOCKETS_PORT)
        self.application = self.start_tornado()


    def start_websocket_server(self,port):
        global G
        import SangomaUtils.sangoma_authenticators
        SangomaUtils.sangoma_authenticators.setG(G)
        """accepts connections from incoming lambda function requests"""
        services_authenticator = MonitoringServiceAuthenticator()
        services_message_manager = MessageManagerWebsocketFromServices()
        G['lambda_connection_handler'] = ConnectionHandler(authenticator=services_authenticator,
                                                        message_manager=services_message_manager)
        G['lambda_connection_handler'].accept_connections(port=port)


    def start_tornado(self):
            """
            Starts a Tornado server with specific endpoints specified in the dictionary endpoints.
            Each endpoint should have a respective Handler Class implemented in tge tornado_endpoints module.
            To initialize the members of the Handler Classes you pass a dictionary after the Class Argument.

            :return: Tornado application that was created
            """


            urls = [
                ("/api/query", AnalyzeQuery),
                ("/api/csrf" , CSRF, dict(
                    handlers={"report": MessageManagerWebsocketFromServices.report_to_connections})),
                ('/api/viralurls', ViralUrls)
            ]

            print("Started Tornado")
            AsyncIOMainLoop().install()  # Allows to use Asyncio main event loop ; https://www.tornadoweb.org/en/branch4.5/asyncio.html
            app = Application(urls, debug=TORNADO_DEBUG)
            app.listen(TORNADO_PORT)
            IOLoop.current().start()
            return app


class MessageManagerWebsocketFromServices:

    async def process_message(self, connection_and_msg):
        '''look at the incoming event (message/command), determine its priority and add it to the eventQ saved
        in the global obejct G.'''

    @staticmethod
    def report_to_connections(event):
        global G
        print(G['lambda_connection_handler'].connections)
        for connection in G['lambda_connection_handler'].connections:
            asyncio.ensure_future(G['lambda_connection_handler'].connections[connection].send(event))
