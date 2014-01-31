#!/usr/bin/env python
from optparse import OptionParser
import subprocess
import time
import os
import csv
import sys


def get_stats(cmd):
    args = ["perf", "stat", "-o", ".timing", "-x", " ", "-e", "instructions"] + cmd
    if os.path.exists(".timing"):
        os.unlink(".timing")
    start = time.time()
    subprocess.check_call(args)
    end = time.time()
    elapsed = end - start

    with open(".timing") as f:
        instructions = int(f.read().split()[0])

    return {
        "elapsed": elapsed,
        "instructions": instructions,
    }


class Bencher:
    def __init__(self, data, srcdir, tmpdir, pcap):
        self.data = data
        self.srcdir = srcdir
        self.tmpdir = tmpdir
        self.pcap = pcap
        self.cwd = os.getcwd()

        self.benched_revisions = self.read_data()

    def read_data(self):
        revs = set()
        if not os.path.exists(self.data):
            return revs
        with open(self.data) as f:
            for rec in csv.reader(f):
                rev = rec[0]
                revs.add(rev)
        return revs

    def log_data_point(self, data):
        with open(self.data, 'a') as f:
            w = csv.DictWriter(f, ["rev", "date", "elapsed", "instructions"])
            w.writerow(data)

    def run_bro(self):
        os.chdir(self.tmpdir)
        cmd = ["bin/bro", "-r", self.pcap]
        return get_stats(cmd)

    def checkout(self, rev):
        os.chdir(self.srcdir)
        subprocess.check_call(["git", "checkout", rev])

    def build(self):
        os.chdir(self.srcdir)
        subprocess.check_call(["./configure", "--prefix", self.tmpdir])
        subprocess.check_call(["make -j8"])
        subprocess.check_call(["make install"])

    def test(self, rev):
        self.checkout(rev)
        self.build()
        stats = self.run_bro()

    def get_git_info(self):
        os.chdir(self.srcdir)
        ver = subprocess.check_output("git rev-parse HEAD".split()).strip()
        out = subprocess.check_output(["git", "rev-list", "--format=format:%ci", "--max-count=1", ver])
        date = out.splitlines()[-1]
        return {
            "version": ver,
            "date": date,
        }

    def get_git_revisions(self):
        os.chdir(self.srcdir)
        cmd = ["git", "rev-list", "--format=format:%ci", "HEAD"]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout
        lines = iter(out.read().splitlines())
        for rev, date in zip(lines, lines):
            rev = rev.split()[1]
            yield rev, date

    def run(self):
        for rev, date in self.get_git_revisions():
            self.test(rev)

def main():
    parser = OptionParser()
    parser.add_option("-d", "--data", dest="data", help="data file", action="store")
    parser.add_option("-s", "--src", dest="src", help="src dir", action="store")
    parser.add_option("-t", "--tmp", dest="tmp", help="tmp dir", action="store")
    parser.add_option("-p", "--pcap", dest="pcap", help="pcap", action="store")
    (options, args) = parser.parse_args()

    if not (options.data and options.src and options.tmp and options.pcap):
        parser.print_help()
        sys.exit(1)

    b = Bencher(options.data, options.src, options.tmp, options.pcap)
    b.run()

    b.get_git_revisions()

if __name__ == "__main__":
    main()
