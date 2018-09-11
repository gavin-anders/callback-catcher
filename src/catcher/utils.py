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