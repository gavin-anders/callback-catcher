'''
Created on 13 Dec 2017

@author: gavin
'''
import requests

class Communicator(object):
    '''
    Used for sending back data to main server
    Starts as a new thread so we arnt hanging around too long wathcing for another callback
    '''
    AUTHURI = '/auth/'

    def __init__(self, url, username=None, password=None):
        '''
        Constructor
        '''
        self.url = url
        self.authtoken = {}
        self.username = username
        self.password = password
        if username and password:
            self.authenticate(username, password)
        
    def _send_authenticated(self, path, data):
        #NEED TO SET IGNORE SSL WARNING
        url = "%s%s" % (self.url, path)
        r = requests.post(url,
                          headers=self.authtoken,
                          json=data,)
                          #proxies={'http': 'http://127.0.0.1:8080',})
        if r.status_code == 401:
            #if invalid token, try again after getting a new token
            self.authenticate(self.username, self.password)
            r = requests.post(url,
                          headers=self.authtoken,
                          json=data)
        print r
    
    def authenticate(self, username, password):
        url = "%s%s" % (self.url, Communicator.AUTHURI)
        r = requests.post(url, json={"username": username, "password": password})
        try:
            if r.status_code == 200:
                resp = r.json()
                self.authtoken['Authorization'] = "Token %s" % str(resp['token'])
                print self.authtoken
        except Exception, e:
            print e
        
    def send_callback(self, data):
        self._send_authenticated('/api/callback/', data)
        
    def send_log(self, data):
        self._send_authenticated('/api/log/', data)
        
