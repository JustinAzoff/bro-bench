#!/usr/bin/env python
from optparse import OptionParser
import subprocess
import time
import os
import csv
import sys
import shutil

#python 2.6 compat
def check_output(*popenargs, **kwargs):
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise subprocess.CalledProcessError(retcode, cmd, output=output)
    return output

def get_stats(cmd):
    args = ["perf", "stat", "-o", ".timing", "-x", " ", "-e", "instructions"] + cmd
    if os.path.exists(".timing"):
        os.unlink(".timing")
    start = time.time()
    subprocess.check_call(args)
    end = time.time()
    elapsed = end - start

    with open(".timing") as f:
        for line in f:
            if 'instructions' in line:
                instructions = int(line.split()[0])

    return {
        "elapsed": elapsed,
        "instructions": instructions,
    }


class Bencher:
    def __init__(self, data, srcdir, tmpdir, pcap):
        self.cwd = os.getcwd()
        self.data = self.full(data)
        self.srcdir = self.full(srcdir)
        self.tmpdir = self.full(tmpdir)
        self.pcap = self.full(pcap)

        self.benched_revisions = self.read_data()

    def full(self, d):
        if d.startswith("/"):
            return d
        else:
            return os.path.join(self.cwd, d)
            

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
        try :
            check_output(["git", "submodule", "update"], stderr=subprocess.PIPE)
        except:
            #Nothing to do here?
            pass

    def build(self):
        os.chdir(self.srcdir)
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        print "Building..."
        check_output(["./configure", "--prefix=" + self.tmpdir], stderr=subprocess.PIPE)
        check_output(["make", "-j8"])
        check_output(["make", "install"])

    def test(self, rev):
        self.checkout(rev)
        self.build()
        stats = self.run_bro()
        return stats

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
            if rev in self.benched_revisions: continue

            print "Revision:", rev, date
            self.checkout(rev)
            try :
                self.build()
            except:
                continue
            for x in range(5):
                try :
                    stats = self.run_bro()
                except:
                    stats = dict(elapsed="", instructions="")
                print "%(elapsed).2f %(instructions)d" % stats
                stats.update(dict(rev=rev, date=date))
                self.log_data_point(stats)

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
