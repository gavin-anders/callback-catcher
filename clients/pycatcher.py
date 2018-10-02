'''
Created on 28 Aug 2017

@author: gavin

'''
import threading
import time
import requests
import os
import base64
import logging

class CatcherLogException(Exception):
    pass

class CatcherClientConnectionError(Exception):
    pass

class CatcherClient(object):
    '''
    Used for communicating with the callbackcatcher server
    '''
    BASE_REST_PATH = 'api/'
    PORT_PATH = 'api/port/'
    CALLBACK_PATH = 'api/callback/'
    STATUS_PATH = 'api/status/'
    HANDLER_PATH = 'api/handler/'

    def __init__(self, host, port=12443, user='admin', password='password', ssl=False):
        """
        Constructor
        """
        self.host = host
        self.port = port
        self.username = user
        self.password = password
        self.url = "http://{0}:{1}/".format(self.host, self.port)
        if ssl is True:
            self.url = "https://{0}:{1}/".format(self.host, self.port)
        
    def _send_post(self, path, data):
        """
        Sends a simple post request to the rest endpoint
        
        :param      path: location of endpoint
        :param      data: dict of data
        :return:    return response or None
        """
        resp = None
        url = "{}{}".format(self.url, path)
        headers = {'Accept': 'application/json'}
        resp = requests.post(url,
                          verify=False,
                          auth=(self.username, self.password),
                          headers=headers,
                          json=data)
        return resp
        
    def _send_get(self, path):
        """
        Sends a simple get request to the rest endpoint
        
        :param      path: location of endpoint
        :return:    return response or None
        """
        resp = None
        url = "{}{}".format(self.url, path)
        headers = {'Accept': 'application/json'}
        resp = requests.get(url,
                          verify=False,
                          headers=headers,
                          auth=(self.username, self.password))
        if resp.status_code != 200:
            raise ValueError("Error")
        return resp
    
    def get_handlers(self):
        resp = self._send_get(self.HANDLER_PATH)
        return resp.json()
            
    def check_connection(self):
        """
        Connect to catcher endpoint
        
        :return:    True if endpoint is alive
        """
        try:
            resp = self._send_get(self.STATUS_PATH)
            if resp.status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            return False
        except:
            raise
        else:
            return False
    
    def get_status(self):
        """
        Connect to catcher endpoint, login and get status
        
        :return:    True if endpoint is alive
        """
        response = self._send_get(self.STATUS_PATH)
        return response.json()
    
    def get_callbacks(self):
        """
        Get all callbacks
        
        :return:    dict object
        """
        response = self._send_get(self.CALLBACK_PATH)
        return response.json()
    
    def get_ports(self):
        """
        Get all ports
        
        :return:    dict object
        """
        response = self._send_get(self.PORT_PATH)
        return response.json()['results']
    
    def get_handlers(self):
        """
        Get all handlers
        
        :return:    dict object
        """
        response = self._send_get(self.HANDLER_PATH)
        return response.json()
        
    def start_port(self, number, protocol='tcp', handler='', ssl=False):
        """
        Tell callbackcatcher server to start a port
        
        :param      port number to start
        :return:    single dictionary item of give id
        """
        if ssl is False:
            ssl = 0
        else:
            ssl = 1
        
        data = {"number":number, "protocol":protocol, "handler":handler, "ssl":ssl}
        resp = self._send_post(self.PORT_PATH, data)
        if resp.status_code == 201:
            if resp.json()['id'] > 0:
                return resp.json()['id']
        return 0
        
    def stop_port(self, id):
        """
        Tell callbackcatcher server to stop a port
        
        :param      port number to stop
        :return:    true/false if port started or not
        """
        resp = None
        url = "{}{}".format(self.url, path)
        headers = {'Accept': 'application/json'}
        resp = requests.delete(url,
                               verify=False,
                               headers=headers,
                               auth=(self.username, self.password))
        if resp.status_code != 204:
            return True
        return False
        
if __name__ == '__main__':
    import sys
    
    print("[+] Start")
    client = CatcherClient('catcher.pentestlabs.co.uk', 12443, 'admin', 'password')
    try:
        if client.check_connection() is False:
            print("[-] CallbackCatcher server is not online :(")
            sys.exit()
        
        status = client.get_status()
        print("########### STATUS ###########")
        print("Domain:\t\t{}".format(status["domain"]))
        print("Client IP:\t{}".format(status["clientip"]))
        print("Finger count:\t{}".format(status["callback_count"]))
        print("Callback count:\t{}".format(status["fingerprint_count"]))
        print("Port count:\t{}".format(status["port_count"]))
        print("Handler count:\t{}".format(status["handler_count"]))
        print("Secret count:\t{}".format(status["secret_count"]))
        print("##############################")

        ports = client.get_ports()
        print("########### PORTS ###########")
        for p in ports:
            print("{}/{} - {}".format(p['number'], p['protocol'].upper(), p['handler']))
        print("##############################")
        
        print("####### TESTING PORTS ########")
        print("Starting port 1234/tcp with handler ftp.py")
        id = client.start_port(1234, 'tcp', handler='ftp.py', ssl=False)
        if id > 0:
            print("Stopping port 1234/tcp with handler ftp.py")
            client.stop_port(id)
        print("##############################")

    except CatcherClientConnectionError:
        print("[-] Failed to connect to server")
    
    print("[+] Finished")