from tornado.web import RequestHandler
import json
from time import time
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from urllib.parse import urlparse
from requests import post


cred = credentials.Certificate('ids-hackathor-636a3e9f4e4c.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ids-hackathor.firebaseio.com/'
})
ref = db.reference('')

with open('payloads.json', encoding="utf8") as f:
    loaded = json.load(f)
    XSS = loaded['XSS']
    TRAVERS = loaded['TRAVERS']

VIRUSTOTAL = '66a5fb757b258c33502762d5b0f494111d7cc70032cfcf115336ad837a13b9ea'
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
    def initialize(self,handlers):
        self.report = handlers["report"]

    async def get(self):
        result = db.reference('').get()
        self.write(result)

    async def post(self):
        print("Entered post")
        params = json.loads(self.request.body)
        ip = self.request.remote_ip
        for param, val in params.items():
            # XSS
            for pload in XSS:
                if pload in val:
                    send_ref(ip, param, val, 'XSS')
                    break
            # SQLi
            if "'" in val and ('and' in val.lower() or 'or' in val.lower()) or '--' in val:
                send_ref(ip, param, val, 'SQLi')
                self.report({"SQLi" : {"ip":ip , "param" : param , "val" : val, "uid" : 99}})

            # CRLF
            if '%0d' in val.lower() or '%0a' in val.lower():
                send_ref(ip, param, val, 'CRLF')
                self.report({"CRLF" : {"ip":ip , "param" : param , "val" : val, "uid" : 99}})

            # OPEN Redirect
            if len([i for i in ['url', 'redirect', 'next'] if i in param.lower()]) > 0 \
                    and not_same_domain(val):
                send_ref(ip, param, val, 'Open Redirect')
                self.report({"Redirect" : {"ip":ip , "param" : param , "val" : val, "uid" : 99}})

            # Path Traversal
            for pload in TRAVERS:
                if pload in val:
                    send_ref(ip, param, val, 'Path Traversal')
                    self.report({"Traversal" : {"ip":ip , "param" : param , "val" : val, "uid" : 99}})

                    break
        return params


class ViralUrls(BaseHandler):
    def initialize(self):
        pass

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
    
        return self.write(malicious)


class CSRF(BaseHandler):

    def initialize(self,handlers):
        self.report = handlers["report"]

    async def post(self):
        params = json.loads(self.request.body)
        params['uid'] = '99'
        self.report({"CSRF" : params})

class IntrusionDetection(RequestHandler):


    def initialize(self):
        pass

    async def get(self):
        params = json.loads(self.request.body)
        # TODO
        #Get endpoint  from params
        #increment visit times 
        #check query params for fuzzy search or intrusion
        #send alert in case found 

