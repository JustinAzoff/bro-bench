#!/usr/bin/env python
from optparse import OptionParser
import subprocess
import time
import os
import csv
import sys
import shutil

class ProcError(Exception):
    def __init__(self, retcode, out, err):
        self.code = retcode
        self.stdout = out
        self.stderr = err

    def __str__(self):
        return self.stderr

def get_output(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = process.communicate()
    retcode = process.poll()
    if retcode:
        raise ProcError(retcode, output, err)
    return output, err

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
    def __init__(self, data, srcdir, tmpdir, pcaps, scripts):
        self.cwd = os.getcwd()
        self.data = self.full(data)
        self.srcdir = self.full(srcdir)
        self.tmpdir = self.full(tmpdir)
        self.pcaps = [self.full(pcap) for pcap in pcaps]
        self.scripts = [self.full(script) for script in scripts]

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
        cmd.extend(self.scripts)
        return get_stats(cmd)

    def checkout(self, rev=None):
        os.chdir(self.srcdir)
        self.cleanup()
        if rev:
            subprocess.check_call(["git", "checkout", rev])
        commands = [
            "git submodule update --recursive --init",
            "git reset --hard",
            "git submodule foreach --recursive git reset --hard",
        ]
        for c in commands:
            try :
                get_output(c.split())
            except Exception, e:
                #Nothing to do here?
                self.log("error running " + c)
                self.log(e.stderr)

    def build(self):
        os.chdir(self.srcdir)
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        self.log("Building...")
        s = time.time()
        subprocess.call(["make", "clean"], stdout=subprocess.PIPE)
        subprocess.call(["rm", "-rf", "build"])
        get_output(["./configure", "--prefix=" + self.tmpdir])
        #eh?
        if os.path.exists("magic/README"):
            os.unlink("magic/README")
        get_output(["make", "-j12", "install"])
        e = time.time()
        self.log("Build took %d seconds" % (e-s))

    def get_git_revisions(self):
        os.chdir(self.srcdir)
        cmd = ["git", "rev-list", "--format=format:%ci|%s", "HEAD"]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout
        lines = iter(out.read().splitlines())
        for rev, info in zip(lines, lines):
            date, subject = info.split("|", 1)
            subject = subject.replace(",",".")
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
                self.log("Build failed")
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

    def cleanup(self):
        """Prevent merge conflicts"""
        os.chdir(self.srcdir)
        subprocess.call(["git", "clean", "-f"])
        if os.path.exists("magic"):
            shutil.rmtree("magic")
        for f in 'src/3rdparty/sqlite3.c', 'src/3rdparty/sqlite3.h':
            if os.path.exists(f):
                os.unlink(f)

    def bisect(self, seconds_threshold):
        self.checkout(None)
        try :
            self.build()
            self.cleanup()
            stats = self.run_bro()
        except:
            self.cleanup() #FIXME: refactor this
            self.log("BISECT: SKIPPING")
            return 125

        #success
        if stats["elapsed"] < seconds_threshold:
            self.log("BISECT: OK")
            return 0

        self.log("BISECT: BAD")
        return 1


    def get_seconds_from_data(self):
        ver = get_output("git rev-parse HEAD".split())[0].strip()
        for rec in csv.reader(open(self.data)):
            if rec[0] == ver:
                return float(rec[3])

    def fast_bisect(self, seconds_threshold):
        seconds = self.get_seconds_from_data()
        if not seconds:
            self.log("BISECT: SKIPPING")
            return 125

        if seconds < seconds_threshold:
            self.log("BISECT: OK")
            return 0

        self.log("BISECT: BAD")
        return 1
                

def main():
    parser = OptionParser()
    parser.add_option("-d", "--data", dest="data", help="data file", action="store")
    parser.add_option("-s", "--src", dest="src", help="src dir", action="store")
    parser.add_option("-t", "--tmp", dest="tmp", help="tmp dir", action="store")
    parser.add_option("-p", "--pcap", dest="pcaps", help="pcaps", action="append")
    parser.add_option("-l", "--load", dest="scripts", help="scripts", action="append")
    parser.add_option("-b", "--bisect", dest="bisect", help="bisect mode, set to seconds threshold", action="store", default=0)
    parser.add_option("-f", "--fastbisect", dest="fastbisect", help="uses data file for bisecting", action="store_true", default=False)
    (options, args) = parser.parse_args()

    if not (options.data and options.src and options.tmp and options.pcaps):
        parser.print_help()
        sys.exit(1)

    b = Bencher(options.data, options.src, options.tmp, options.pcaps, options.scripts)
    if options.fastbisect and options.bisect:
        sys.exit(b.fast_bisect(options.bisect))

    if options.bisect:
        sys.exit(b.bisect(options.bisect))

    b.run()

if __name__ == "__main__":
    main()
