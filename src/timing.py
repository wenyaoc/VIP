from datetime import date, datetime
from email.errors import StartBoundaryNotFoundDefect
from time import sleep

start_time = datetime.now()
print(start_time)
sleep(2)
time_2 = datetime.now()
print(time_2)
time_diff = time_2 - start_time


print(time_diff.seconds)
