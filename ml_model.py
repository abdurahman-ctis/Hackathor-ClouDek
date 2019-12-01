from bottle import route, run, template,post,request
import matplotlib.pyplot as plt
import nltk
import pandas as pd
import scipy
from nltk.util import ngrams
from scipy.sparse import coo_matrix, hstack, vstack
from sklearn.datasets import load_iris
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
import os
import pickle
import random
import json
import string

def get1Grams(payload_obj):
    '''Divides a string into 1-grams
    
    Example: input - payload: "<script>"
             output- ["<","s","c","r","i","p","t",">"]
    '''
    payload = str(payload_obj)
    ngrams = []
    for i in range(0,len(payload)-1):
        ngrams.append(payload[i:i+1])
    return ngrams

def get2Grams(payload_obj):
    '''Divides a string into 2-grams
    
    Example: input - payload: "<script>"
             output- ["<s","sc","cr","ri","ip","pt","t>"]
    '''
    payload = str(payload_obj)
    ngrams = []
    for i in range(0,len(payload)-2):
        ngrams.append(payload[i:i+2])
    return ngrams

def get3Grams(payload_obj):
    '''Divides a string into 3-grams
    
    Example: input - payload: "<script>"
             output- ["<sc","scr","cri","rip","ipt","pt>"]
    '''
    payload = str(payload_obj)
    ngrams = []
    for i in range(0,len(payload)-3):
        ngrams.append(payload[i:i+3])
    return ngrams



@post('/hello/<name>')
def index(name):
    data_params = request.json
    print(data_params)
    #postdata =  name = request.forms.get("query_val")
    return_value = run_model(data_params)
    print("return value ",return_value)
    return str(return_value)
    
    return "1"
def run_model(param):
    list_of_results = []
    check = 0
    for key in param:
        content = param[key]
        q_val = content
        type_attack = None
        q_key = key
        df = pd.DataFrame([[content]],columns=['content'])
        df['content'] = df['content'].str.strip('\n')
        df['content'] = df['content'].str.lower()
        X1C = count_vectorizer_1grams.transform(df["content"])
        X2C = count_vectorizer_2grams.transform(df["content"])
        X3C = count_vectorizer_3grams.transform(df["content"])
        X1T = tfidf_vectorizer_1grams.transform(df["content"])
        X2T = tfidf_vectorizer_2grams.transform(df["content"])
        X3T = tfidf_vectorizer_3grams.transform(df["content"])
        X = hstack([X1C,X2C,X3C,X1T,X2T,X3T])
        predicted = logistic_model.predict(X)
        predicted_sql = sql_model.predict_proba(X)[0][1]
        predicted_traverse = traverse_model.predict_proba(X)[0][1]
        predicted_xss = xss_model.predict_proba(X)[0][1]
        max_value = max(predicted_sql,predicted_traverse,predicted_xss)
        if max_value >= 0.5:
            if max_value == predicted_sql:
                type_attack = "SQLi"
            elif max_value == predicted_traverse:
                type_attack = "Path Traversal"
            elif max_value == predicted_xss:
                type_attack = "XSS"
            dicc = {
                    "type":type_attack,
                    "param": q_key,
                    "val": q_val,
                    "confidence": max_value
            }
            list_of_results.append(dicc)
    return json.dumps(list_of_results)

if __name__ == '__main__':
    count_vectorizer_1grams = pickle.load(open("c1g.vec","rb"))
    count_vectorizer_2grams = pickle.load(open("c2g.vec","rb"))
    count_vectorizer_3grams = pickle.load(open("c3g.vec","rb"))
    tfidf_vectorizer_1grams = pickle.load(open("t1g.vec","rb"))
    tfidf_vectorizer_2grams = pickle.load(open("t2g.vec","rb"))
    tfidf_vectorizer_3grams = pickle.load(open("t3g.vec","rb"))
    logistic_model = pickle.load(open("logistic.model","rb"))
    sql_model = pickle.load(open("sql.model","rb"))
    traverse_model = pickle.load(open("traverse.model","rb"))
    xss_model = pickle.load(open("xss.model","rb"))

    print("valalal")
    run(host = 'localhost', port=5000,reloader=True)