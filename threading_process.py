import time 
import subprocess
import threading


ipaddresses = ['8.8.8.8','1.1.1.1']
results = []
def ping_test(ipaddess):
    """
    This block of code will send ping commands to cmd 
    by taking one single IP address as argument 
    and appends the result as bytetype into a list, 
    which includes stdout,stderr,returncode etc.
    They can be called by typing result.stdout
    """
    result = subprocess.run(f"ping {ipaddess} -n 2",capture_output=True,  text=True)
    print(result.stdout)
    results.append(result)  # used when to append the results to a list
    #return results         # used when to return the result   

    """
    Following block of code will create multiple threads 
    for calling the function parallelly. 
    function name and the arguments are passed to each thread
    .start() will start all funcs at same time.
    .join() will wait for all funcs to stop before moving on to next line of code
    """
threads = []
for ipaddress in ipaddresses:
    t = threading.Thread(target = ping_test, args=[ipaddress])
    # here the function is passed onto thread using target keyword, 
    # and function name is written without paranthesis
    # arguments to function can be passed onto using keyword args
    t.start()
    threads.append(t)
    # another loop is created to join the results of all threads. 
    # so that all the functions will start at the same time 
    # and results will be out only when all threads have finished execution
for thread in threads:
    thread.join()


# for ipadd in ipaddresses:
#     ping_test(ipadd)

for result in results:
    print(result.stdout)