import json
from time import time
from urllib.parse import urlparse

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from flask import Flask, request
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
socketio = SocketIO(app)
DOMAIN = "bilkent.com"


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
                    send_ref(ip, param, val, 'xss')
                    break
            # SQLi
            if "'" in val and ('and' in val.lower() or 'or' in val.lower()) or '--' in val:
                send_ref(ip, param, val, 'sqli')
            # CRLF
            if '%0d' in val.lower() or '%0a' in val.lower():
                send_ref(ip, param, val, 'csrf')
            # OPEN Redirect
            if len([i for i in ['url', 'redirect', 'next'] if i in param.lower()]) > 0 \
                    and not_same_domain(val):
                send_ref(ip, param, val, 'open_redirect')
            # Path Traversal
            for pload in TRAVERS:
                if pload in val:
                    send_ref(ip, param, val, 'path_traversal')
                    break

        return params


api.add_resource(AnalyzeQuery, '/api/query')

if __name__ == '__main__':
    socketio.run(app)
