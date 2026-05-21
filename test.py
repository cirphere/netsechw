#!/usr/bin/python3

import os, time

while True:
	os.system("arp -d 10.0.0.3")
	time.sleep(1)
