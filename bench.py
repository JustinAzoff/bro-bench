#!/usr/bin/env python
from optparse import OptionParser
import subprocess
import time
import os
import csv
import sys
import shutil
import glob
import queue
import threading
import tempfile

BAD_COMMITS = ["595e2f3c8a6829d44673a368ab13dd28bd4aab85"]
FIELDS = ["rev", "date", "subject", "version", "elapsed", "instructions"]

os.environ['PATH']='/usr/lib/ccache/:' + os.environ['PATH']
os.environ['PATH']='/usr/lib64/ccache/:' + os.environ['PATH']
os.environ['CCACHE_DIR'] = '/dev/shm/ccache'
#echo max_size = 15.0G  >> /tmp/ccache/ccache.conf

LOGGING_MUTEX = threading.Lock()

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
    return output.decode(), err.decode()

def get_stats(cmd):
    #Not great, but should work ok
    timing_file = tempfile.mktemp("timing")
    args = ["perf", "stat", "-o", timing_file, "-x", " ", "-e", "instructions"] + cmd
    start = time.time()
    subprocess.check_call(args)
    end = time.time()
    elapsed = end - start

    with open(timing_file) as f:
        for line in f:
            if 'instructions' in line:
                instructions = int(line.split()[0])
    os.unlink(timing_file)

    return {
        "elapsed": elapsed,
        "instructions": instructions,
    }

DESIRED_CONFIGURE_OPTIONS=[
    # One of these will work
    "--disable-zeekctl",
    "--disable-broctl",

    "--ccache",
    "--disable-python",
    "--disable-broker-tests",
    "--disable-archiver",
    "--disable-btest",
    "--disable-btest-pcaps",
]

def filter_configure_options(desired_options=DESIRED_CONFIGURE_OPTIONS):
    with open("configure") as f:
        configure_contents = set(f.read().split())

    return [o for o in desired_options if o in configure_contents]

class Bencher:
    def __init__(self, data, srcdir, tmpdir, instdir, pcaps, scripts):
        self.cwd = os.getcwd()
        self.data = self.full(data)
        self.srcdir = self.full(srcdir)
        self.tmpdir = self.full(tmpdir)
        self.instdir = self.full(instdir)
        self.pcaps = [self.full(pcap) for pcap in pcaps]
        self.scripts = [self.full(script) for script in scripts]

        self.benched_revisions = self.read_data()
        self.benched_revisions.update(BAD_COMMITS)

        self.is_zeek =  os.path.exists(os.path.join(self.srcdir, 'zeek-config.in'))
        self.ext = "zeek" if self.is_zeek else "bro"

    def full(self, d):
        if d.startswith("/"):
            return d
        else:
            return os.path.join(self.cwd, d)
            
    def log(self, s):
        with LOGGING_MUTEX:
            sys.stdout.write("%s\n" % s)
            sys.stdout.flush()

    def read_data(self):
        revs = set()
        if not os.path.exists(self.data):
            return revs
        with open(self.data) as f:
            for rec in csv.DictReader(f, FIELDS):
                rev = rec['rev']
                revs.add(rev)
        return revs

    def log_data_point(self, data):
        with LOGGING_MUTEX:
            with open(self.data, 'a') as f:
                w = csv.DictWriter(f, FIELDS)
                w.writerow(data)

    def get_binary(self, rev):
        dst_dir = "{}/zeek-{}".format(self.instdir, rev)
        for prog in "zeek", "bro":
            path = os.path.join(dst_dir, "bin", prog)
            if os.path.exists(path):
                return path
        return None

    def get_version(self, rev):
        bro_bin = self.get_binary(rev)
        out, err =  get_output([bro_bin, "--version"])
        return out.split()[-1]

    def run_bro(self, rev, core=None):
        os.chdir(self.tmpdir)
        bro_bin = self.get_binary(rev)
        cmd = []
        if core:
            cmd.extend(["taskset", "-c", str(core)])
        cmd.append(bro_bin)
        for pcap in self.pcaps:
            cmd.extend(["-r", pcap])
        cmd.extend(self.scripts)
        return get_stats(cmd)

    def checkout(self, rev=None):
        os.chdir(self.srcdir)
        self.cleanup()
        if rev:
            subprocess.check_call(["git", "checkout", "-f", rev])
        commands = [
            "git submodule update --recursive --init",
            "git reset --hard",
            "git submodule foreach --recursive git reset --hard",
            "git checkout .",
            "git submodule foreach --recursive git checkout .",
        ]
        for c in commands:
            try :
                get_output(c.split())
            except Exception as e:
                #Nothing to do here?
                self.log("error running " + c)
                self.log(e.stderr)

    def fix_trivial_issues(self, dst_dir):
        ssl_fn = os.path.join(dst_dir, "share/{0}/base/protocols/ssl/main.{0}".format(self.ext))
        subprocess.call(["perl", "-pi", "-e", 's/timeout (SSL::)*max_log_delay/timeout 15secs/', ssl_fn])

        local_fn_glob = os.path.join(dst_dir, "share/*/site/local.*")
        for local_fn in glob.glob(local_fn_glob):
            subprocess.call(["perl", "-pi", "-e", 's!.load protocols/ssl/notary!#nope!', local_fn])
            subprocess.call(["perl", "-pi", "-e", 's!.load.*detect.MHR!#nope!', local_fn])

        #mhr_fn = os.path.join(dst_dir, "share/{0}/policy/protocols/http/detect-MHR.{0}".format(self.ext))
        #if os.path.exists(mhr_fn):
        #    subprocess.call(["perl", "-pi", "-e", 's/if/return;if/', mhr_fn])

    def build(self, rev):
        if self.get_binary(rev):
            self.log("Already built: {}".format(rev))
            self.link_version(rev)
            return
        os.chdir(self.srcdir)
        dst_dir = "{}/zeek-{}".format(self.instdir, rev)
        self.log("Building {}".format(rev))
        self.checkout(rev)
        self.is_zeek =  os.path.exists('zeek-config.in')
        self.ext = "zeek" if self.is_zeek else "bro"

        s = time.time()
        #get_output(["make", "clean"])
        subprocess.call(["rm", "-rf", "build"])
        configure_cmd = ["./configure", "--prefix=" + dst_dir, "--build-type=Release"]
        configure_cmd.append("--generator=Ninja")
        configure_cmd.extend(filter_configure_options())
        get_output(configure_cmd)
        #eh?
        if os.path.exists("magic/README"):
            os.unlink("magic/README")
        get_output(["ninja", "-C", "build", "install"])
        self.fix_trivial_issues(dst_dir)
        e = time.time()
        self.log("Build took %d seconds" % (e-s))
        version = self.get_version(rev)

        self.link_version(rev)

    def link_version(self, rev):
        version = self.get_version(rev)
        dst_dir = "{}/zeek-{}".format(self.instdir, rev)
        version_base_dir = os.path.join(self.instdir, "by-version")
        version_dir = os.path.join(version_base_dir, version)

        if not os.path.isdir(version_base_dir):
            os.makedirs(version_base_dir)
        
        if not os.path.islink(version_dir):
            os.symlink(dst_dir, version_dir)

    def get_git_revisions(self):
        os.chdir(self.srcdir)
        cmd = ["git", "rev-list", "HEAD"]
        out, err = get_output(cmd)
        revs = [r.strip() for r in out.splitlines()]
        return revs

    def get_git_info(self, rev="HEAD"):
        os.chdir(self.srcdir)
        if rev == "HEAD":
            rev = get_output("git rev-parse HEAD".split())[0].strip()
        out = get_output(["git", "rev-list", "--format=format:%ci|%s", "--max-count=1", rev])[0]
        date, subject = out.strip().splitlines()[-1].split("|", 1)
        return {
            "rev": rev,
            "date": date,
            "subject": subject,
        }

    def bench_revision(self, rev="HEAD"):
        info = self.get_git_info(rev)
        rev = info['rev']
        self.log("Revision: %(rev)s %(date)s" % info)
        try :
            self.build(rev)
        except ProcError as e:
            self.log("Build failed")
            self.log(e.stderr)
            return None
        info["version"] = self.get_version(rev)
        self.log("Testing...")
        #FIXME: make this an option
        for x in range(1):
            try :
                stats = self.run_bro(rev)
            except:
                stats = dict(elapsed=0, instructions=0)
            self.log("result: %(elapsed).2f %(instructions)d" % stats)
            stats.update(info)
            self.log_data_point(stats)
        return stats


    def run(self):
        for rev in self.get_git_revisions():
            if rev in self.benched_revisions:
                self.link_version(rev)
                continue

            info = self.get_git_info(rev)
            if 'Merge remote-tracking branch' not in info['subject'] and 'Merge branch' not in info['subject']:
                self.log("Skipping non merge commit: %s" % rev)
                continue

            stats = self.bench_revision(rev)

    def cleanup(self):
        """Prevent merge conflicts"""
        os.chdir(self.srcdir)
        subprocess.call(["git", "clean", "-f"])
        if os.path.exists("magic"):
            shutil.rmtree("magic")
        for f in 'src/3rdparty/sqlite3.c', 'src/3rdparty/sqlite3.h':
            if os.path.exists(f):
                os.unlink(f)

    def bisect_result(self, value, value_threshold):
        if value < 5:
            self.log("BISECT: SKIP: value=%d" % (value))
            return 125

        #success
        if value < value_threshold:
            self.log("BISECT: OK: %d < %d" % (value, value_threshold))
            return 0

        self.log("BISECT: BAD: %d > %d" % (value, value_threshold))
        return 1

    def bisect(self, value_threshold):
        key = value_threshold < 10000 and "elapsed" or "instructions"

        self.checkout(None)
        try :
            value = self.bench_revision()[key]
            self.cleanup()
        except Exception as e:
            self.log("Exception {}".format(e))
            self.cleanup() #FIXME: refactor this
            self.log("BISECT: SKIPPING")
            return 125
        return self.bisect_result(value, value_threshold)


    def get_value_from_data(self, key):
        os.chdir(self.srcdir)
        rev = get_output("git rev-parse HEAD".split())[0].strip()
        for rec in csv.DictReader(open(self.data), FIELDS):
            if rec['rev'] == rev:
                return float(rec[key])

    def fast_bisect(self, value_threshold):
        key = value_threshold < 10000 and "elapsed" or "instructions"
        value = self.get_value_from_data(key)
        if value:
            return self.bisect_result(value, value_threshold)

        self.log("Need to build this revision..")
        return self.bisect(value_threshold)


    def multi_worker(self, queue, core):
        while True:
            rev = queue.get()
            if rev is None:
                break
            info = self.get_git_info(rev)
            info["version"] = ver = self.get_version(rev)
            self.log(f"Testing... {rev} - {ver} on core {core}")
            try :
                stats = self.run_bro(rev, core=core)
            except subprocess.CalledProcessError:
                stats = dict(elapsed=0, instructions=0)
            self.log("result: %(elapsed).2f %(instructions)d" % stats)
            stats.update(info)
            self.log_data_point(stats)

    def multi(self, cores):
        versions = [d.replace("zeek-","") for d in os.listdir(self.instdir)]
        self.log(f"Testing {len(versions)} versions using {cores} cores")

        q = queue.Queue()
        threads = []
        for cpu in range(1, cores+1):
            t = threading.Thread(name=f"core-{cpu}", target=self.multi_worker, args=(q, cpu))
            t.start()
            threads.append(t)

        for rev in versions:
            try:
                ver = self.get_version(rev)
                q.put(rev)
            except Exception as e:
                self.log(f"Skipping {rev} because --version failed: {e!r}")
        for _ in range(cores):
            q.put(None)
        for t in threads:
            t.join()

def main():
    parser = OptionParser()
    parser.add_option("-d", "--data", dest="data", help="data file", action="store")
    parser.add_option("-s", "--src", dest="src", help="src dir", action="store")
    parser.add_option("-i", "--inst", dest="inst", help="install dir", action="store", default="/usr/local/zeeks")
    parser.add_option("-t", "--tmp", dest="tmp", help="tmp dir", action="store")
    parser.add_option("-p", "--pcap", dest="pcaps", help="pcaps", action="append", default=[])
    parser.add_option("-l", "--load", dest="scripts", help="scripts", action="append")
    parser.add_option("-b", "--bisect", dest="bisect", help="bisect mode, set to seconds or instructions threshold", action="store", type="int", default=0)
    parser.add_option("-f", "--fastbisect", dest="fastbisect", help="uses data file for bisecting", action="store_true", default=False)
    parser.add_option("-m", "--multi", dest="multi", help="multi mode, run on this many cpu cores", action="store", type="int", default=0)
    (options, args) = parser.parse_args()

    if options.multi:
        b = Bencher(options.data, options.src, options.tmp, options.inst, options.pcaps, options.scripts)
        sys.exit(b.multi(options.multi))

    if not (options.data and options.src and options.tmp and (options.pcaps or options.scripts)):
        parser.print_help()
        sys.exit(1)

    b = Bencher(options.data, options.src, options.tmp, options.inst, options.pcaps, options.scripts)
    if options.fastbisect and options.bisect:
        sys.exit(b.fast_bisect(options.bisect))

    if options.bisect:
        sys.exit(b.bisect(options.bisect))


    b.run()

if __name__ == "__main__":
    main()
