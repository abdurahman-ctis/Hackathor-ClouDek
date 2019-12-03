import datetime
import json
from time import time
from urllib.parse import urlparse
from requests import post
import firebase_admin
from dateutil.parser import parse
from firebase_admin import credentials
from firebase_admin import db
from requests import post
from tornado.web import RequestHandler

cred = credentials.Certificate('CERTIFICATE_FILE')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ids-hackathor.firebaseio.com/'
})
ref = db.reference('')
intrusion_ref = db.reference('intrusions')

with open('payloads.json', encoding="utf8") as f:
    loaded = json.load(f)
    XSS = loaded['XSS']
    TRAVERS = loaded['TRAVERS']

VIRUSTOTAL = 'API_KEY'
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


class BaseHandler(RequestHandler):

    def set_default_headers(self):
        print("setting headers!!!")
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_header('Access-Control-Allow-Methods', '*')

    def options(self):
        # no body
        self.set_status(204)
        self.finish()


class AnalyzeQuery(BaseHandler):
    def initialize(self, handlers):
        self.report = handlers["report"]

    async def get(self):
        result = db.reference('').get()
        self.write(result)

    async def post(self):
        print("Entered post")
        ip = self.request.remote_ip
        params = json.loads(self.request.body)
        response = post("http://localhost:5000/hello/hikmet", json=params)
        response_val = json.loads(response.text)
        for i in response_val:
            print(i)
            send_ref(ip, i['param'], i['val'], i['type'])
            self.report({i['type']: {"ip": ip, "param": i['param'], "val": i['val'],
                                     "uid": 99, "confidence": i['confidence']}})

        for param, val in params.items():

            # CRLF
            if '%0d' in val.lower() or '%0a' in val.lower():
                send_ref(ip, param, val, 'CRLF')
                self.report({"CRLF": {"ip": ip, "param": param, "val": val, "uid": 99}})

            # OPEN Redirect
            if len([i for i in ['url', 'redirect', 'next'] if i in param.lower()]) > 0 \
                    and not_same_domain(val):
                send_ref(ip, param, val, 'Open Redirect')
                self.report({"Redirect": {"ip": ip, "param": param, "val": val, "uid": 99}})

        self.write({"Result": "200 Success"})


class ViralUrls(BaseHandler):
    def initialize(self, handlers):
        self.report = handlers["report"]

    async def post(self):
        params = json.loads(self.request.body)
        malicious = []
        for url in params:
            post("https://www.virustotal.com/vtapi/v2/url/scan", data={'apikey': VIRUSTOTAL, 'url': url})
            res = post("https://www.virustotal.com/vtapi/v2/url/report", data={'apikey': VIRUSTOTAL, 'resource': url})
            for i in res.json()['scans'].values():
                if i['detected']:
                    malicious.append(url)
                break

        self.report({"Viral": malicious})
        self.write({"Result": "200 Success"})


class CSRF(BaseHandler):

    def initialize(self, handlers):
        self.report = handlers["report"]

    async def post(self):
        params = json.loads(self.request.body)
        params['uid'] = '99'
        self.report({"CSRF": params})
        self.write({"Result": "200 Success"})


class IntrusionDetection(BaseHandler):

    def initialize(self, handlers):
        self.report = handlers["report"]

    async def post(self):
        params = json.loads(self.request.body)
        print(params)
        inter = intrusion_ref.get()
        prev = [i for i in inter if inter[i]['path'] == params['path']]
        if len(prev) == 0:
            prev = None
            key = None
        else:
            key = prev[0]
            prev = inter[prev[0]]
        print(prev)

        if not prev:
            cnt = 1
            intrusion_ref.push({
                "ip": self.request.remote_ip,
                "path": params['path'],
                "time": datetime.datetime.now().isoformat(),
                "cnt": cnt
            })
        else:
            cnt = prev['cnt']
            earlier_time = parse(prev['time'])
            now = datetime.datetime.now()
            print((now - earlier_time).seconds)
            if (now - earlier_time).seconds > 5 and cnt > 10:
                print("printed")
                self.report({"Intrusion": params})
                cnt = 1
            cnt += 1

            intrusion_ref.child(key).update({'cnt': cnt})
        self.write({"Result": "200 Success"})
