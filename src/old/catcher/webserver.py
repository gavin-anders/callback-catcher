'''
Created on 27 Aug 2017

@author: gavin
'''
from flask import request, jsonify, abort, send_from_directory
from flask import Flask, Response
from functools import wraps
from OpenSSL import SSL

from config import config as CONFIG
from service import Service
from version import catcher_banner

import json
import os
import logging
import signal

logger = logging.getLogger('catcher')
USERNAME = 'admin'
PASSWORD = 'password'
JOBS = []

class localFlask(Flask):
    def process_response(self, response):
        #Every response will be processed here first
        response.headers['Server'] = catcher_banner
        super(localFlask, self).process_response(response)
        return(response)
    
app = localFlask(__name__)

def check_auth(username, password):
    """
    This function is called to check if a username /
    password combination is valid.
    """
    if username == USERNAME and password == PASSWORD:
        return True
    return False

def authenticate():
    """
    Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})
    
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or check_auth(auth.username, auth.password) == False:
            return authenticate()
        return f(*args, **kwargs)
    return decorated
        
@app.route('/api/ports', methods=['POST', 'GET'])
@requires_auth
def ports():
    '''
    Accepts json array with list of services to start
    '''
    logger.debug('Request for /api/ports')
    global JOBS
    #Stop ports here
    while len(JOBS) > 0:
        job = JOBS.pop()
        try:
            logger.info("Terminating %i (%s)" % (job.pid, job))
            job.terminate()
            job.join()
            if job.is_alive():
                logger.debug("Process %i is still running. Trying to hard terminate..." % job.pid)
                os.kill(job.pid, signal.SIGTERM)
        except Exception, e:
            logger.exception(e)
    
    #Start ports here
    try:
        if request.method == 'POST':
            #process list of services
            portdata = json.loads(request.data)
            
            for item in portdata:
                ip = CONFIG.listenip
                #pass logger so we can log inside the subprocess
                process = Service(ip, item['number'], item['protocol'], item['ssl'], logger)
                logger.info("Starting service on %s:%s:%i" % (item['protocol'], ip, item['number']))
                #Enable ssl
                if process.ssl_enabled():
                    process.set_ssl_context(CONFIG.sslcert, CONFIG.sslkey)
                #Enable handler
                if len(str(item['handler'])) > 0:
                    logger.info("Using custom handler %s" % item['handler'])
                    print "Using custom handler %s" % item['handler']
                    process.set_handler(item['handler'], CONFIG.handlerdir)
                process.start()
                if process.is_alive():
                    JOBS.append(process)
            return jsonify({'ports': 'ok'})
        elif request.method == 'GET':
            #Get the current running services
            return jsonify({'ports': 'ok'})
        else:
            abort(400)
    except:
        #abort(400)
        raise
        
@app.route('/api/status', methods=['GET'])
@requires_auth
def status():
    logger.debug('Request for /api/status')
    resp = {}
    
    #Processes
    pids = []
    for job in JOBS:
        d = {}
        d['pid'] = job.pid
        d['service'] = str(job)
        pids.append(d)
    resp['processes'] = pids
    
    return jsonify(resp)

@app.route('/api/logs', methods=['GET'])
@requires_auth
def logs():
    logger.debug('Request for /api/logs')
    return jsonify({'logs': 'ok'})

@app.route('/', methods=['GET'])
def get_index():
    return 'Ok'

def run(host, port, sslcert, sslkey, username, password):
    global USERNAME, PASSWORD
    USERNAME = username
    PASSWORD = password
    context = (sslcert, sslkey)
    app.run(host=host, port=port, debug=False, ssl_context=context, threaded=True)

    
if __name__ == '__main__':
    app.run('127.0.0.1', CONFIG.apiport, debug=True)
    