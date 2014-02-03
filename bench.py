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
    def __init__(self, data, srcdir, tmpdir, pcaps):
        self.cwd = os.getcwd()
        self.data = self.full(data)
        self.srcdir = self.full(srcdir)
        self.tmpdir = self.full(tmpdir)
        self.pcaps = [self.full(pcap) for pcap in pcaps]

        self.benched_revisions = self.read_data()

    def full(self, d):
        if d.startswith("/"):
            return d
        else:
            return os.path.join(self.cwd, d)
            
    def log(self, s):
        sys.stdout.write("%s\n" % s)
        sys.stdout.flush()

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
            w = csv.DictWriter(f, ["rev", "date", "subject", "elapsed", "instructions"])
            w.writerow(data)

    def run_bro(self):
        os.chdir(self.tmpdir)
        bro_bin = os.path.join(self.tmpdir, "bin/bro")
        cmd = [bro_bin, "-C"]
        for pcap in self.pcaps:
            cmd.extend(["-r", pcap])
        return get_stats(cmd)

    def checkout(self, rev):
        os.chdir(self.srcdir)
        subprocess.check_call(["git", "checkout", rev])
        commands = [
            "git submodule update --recursive --init",
            "git reset --hard",
            "git submodule foreach --recursive git reset --hard",
        ]
        for c in commands:
            try :
                subprocess.check_call(c.split())
            except Exception, e:
                #Nothing to do here?
                self.log("error running " + c)

    def build(self):
        os.chdir(self.srcdir)
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        self.log("Building...")
        s = time.time()
        subprocess.call(["make", "clean"], stdout=subprocess.PIPE)
        subprocess.call(["rm", "-rf", "build"])
        check_output(["./configure", "--prefix=" + self.tmpdir], stderr=subprocess.PIPE)
        check_output(["make", "-j12", "install"])
        e = time.time()
        self.log("Build took %d seconds" % (e-s))

    def test(self, rev):
        self.checkout(rev)
        self.build()
        stats = self.run_bro()
        return stats

    def get_git_revisions(self):
        os.chdir(self.srcdir)
        cmd = ["git", "rev-list", "--format=format:%ci|%s", "HEAD"]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout
        lines = iter(out.read().splitlines())
        for rev, info in zip(lines, lines):
            date, subject = info.split("|", 1)
            rev = rev.split()[1]
            yield rev, date, subject

    def run(self):
        for rev, date, subject in self.get_git_revisions():
            if rev in self.benched_revisions: continue

            self.log("Revision: %s %s" %( rev, date))
            self.checkout(rev)
            try :
                self.build()
            except:
                continue
            self.log("Testing...")
            for x in range(5):
                try :
                    stats = self.run_bro()
                except:
                    stats = dict(elapsed=0, instructions=0)
                self.log("result: %(elapsed).2f %(instructions)d" % stats)
                stats.update(dict(rev=rev, date=date, subject=subject))
                self.log_data_point(stats)

def main():
    parser = OptionParser()
    parser.add_option("-d", "--data", dest="data", help="data file", action="store")
    parser.add_option("-s", "--src", dest="src", help="src dir", action="store")
    parser.add_option("-t", "--tmp", dest="tmp", help="tmp dir", action="store")
    parser.add_option("-p", "--pcap", dest="pcaps", help="pcap", action="append")
    (options, args) = parser.parse_args()

    if not (options.data and options.src and options.tmp and options.pcaps):
        parser.print_help()
        sys.exit(1)

    b = Bencher(options.data, options.src, options.tmp, options.pcaps)
    b.run()

if __name__ == "__main__":
    main()
