import signal
import os

def kill_process(pid):
    #Check if process exists
    #Sending signal 0 to a pid will raise an OSError exception if the pid is not running
    if pid is None:
        print("Pid is None, return early")
        return
    try:
        os.kill(pid, 0)
    except OSError:
        print("No process found for pid %i" % pid)
        return
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            print("Killed pid %i" % pid)
        except:
            print("Failed to kill process")
            raise