#! /usr/bin/python
# coding=utf8
import os, sys
from urlparse import *

filename = sys.argv[1]

fd = open(filename, 'r')

#1673249732346108	270866	[ERROR]	[system]	/root/CLionProjects/local_git/hammer/hammer/tcp_server.cc:144	onAcceptConnection...

logs = {}
l = 1
tmp = 0
for line in fd.readlines():
    global line
    fields = line.strip().split("\t")
    time = int(fields[0])
    if l % 2 == 0:
        diff = time - tmp
        if diff != 0:
            print time, tmp, diff
        tmp = 0;
    else:
        tmp = time
    l = l + 1
