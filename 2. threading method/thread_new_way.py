import time 
import subprocess
import concurrent.futures


ipaddresses = ['8.8.8.8','1.1.1.1']
results = []
def ping_test(ipaddress):
    """
    following code block shows the new way of threading
    here a container named executor is created and 
    threads are created using for loop.
    if there is a return value for the function, 
    it can be obtained from f.result()
    """
    result = subprocess.run(f"ping {ipaddress} -n 2",capture_output=True,  text=True)
    # print(result.stdout)
    # results.append(result)  # used when to append the results to a list
    return result         # used when to return the result   
# End of Fuction

fouts = []
with concurrent.futures.ThreadPoolExecutor() as executor:
    for ipaddress in ipaddresses:
        f = executor.submit(ping_test,ipaddress)    
        fouts.append(f)
    # following line with coverge list creation and for loop in single line    
    # fouts = [executor.submit(ping_test,ipaddress) for ipaddress in ipaddresses]

    # following code will print the results in the oder in which they are executed 
    # for f in concurrent.futures.as_completed(fouts):
    #      print(f.result())
for fout in fouts:
    print(fout.result().stdout)