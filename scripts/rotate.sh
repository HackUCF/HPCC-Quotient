#!/usr/bin/env python3

from subprocess import run
from os import listdir
import random

ip = '172.16.0.0/16'
gateway = '28.0.0.1'
safe_nics = ['lo', 'eth0']
nic_contains = 'eth' # we don't want to select the docker nic, or anything like that

# list routes
routes_cmd = run('ip route list', shell=True, capture_output=True)
routes = routes_cmd.stdout.decode().splitlines()

# convert lines into lists
for i in range(len(routes)):
  routes[i] = routes[i].split(' ')
  #print(len(routes[i]))

# find my route and delete it
for route in routes:
  if route[0] == ip:
    cmd = f'ip route del {ip}'
    run(cmd, shell=True)
    print(f'ran "{cmd}"')

# get next nic
nics = listdir('/sys/class/net')
random_nics = [nic for nic in nics if (nic not in safe_nics and nic_contains in nic)]
random_nic = random.choice(random_nics)

# create new route
cmd = f'ip route add {ip} via {gateway} dev {random_nic}'
run(cmd, shell=True)
print(f'ran "{cmd}"')
