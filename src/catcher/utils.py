import signal
import os
import logging 

logger = logging.getLogger(__name__)

def kill_process(pid):
    #Check if process exists
    #Sending signal 0 to a pid will raise an OSError exception if the pid is not running
    if pid is None:
        logger.warning("Pid is None, nothing to do...")
        return
    
    try:
        os.kill(pid, 0)
    except OSError:
        logger.error("No process found for pid %i" % pid)
        return
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("Killed process {}".format(pid))
        except:
            logger.error("Failed to kill process")
            
def is_process_running(pid):
    '''
    Check if the provided pid is running
    '''
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True
            
def safe_load_path(basedir, path, follow_symlinks=True):
    if follow_symlinks:
        return os.path.realpath(path).startswith(basedir)

    return os.path.abspath(path).startswith(basedir)

