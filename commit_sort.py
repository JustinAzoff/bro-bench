#!/usr/bin/env python
import sys
cs = {}

def key(line):
    c = line.split(",")[0]
    return cs.get(c)

for idx, line in enumerate(open("commits.txt")):
    c = line.strip()
    cs[c] = idx

data = list(sys.stdin)

data.sort(key=key, reverse=True)

for x in data:
    print x.rstrip()
