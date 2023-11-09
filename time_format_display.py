from datetime import datetime
import time 
import os

start = time.perf_counter()
time.sleep(3)
stop = time.perf_counter()
print(datetime.fromtimestamp(start))
print(datetime.fromtimestamp(stop))

"""
following line of code with get the current working 
directory and joins it with the file name 
"""
print(os.path.join(os.getcwd(),'test.txt'))