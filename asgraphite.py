#!/usr/bin/env python

# Copyright 2013-2019 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Description: Graphite connector for Aerospike
from __future__ import print_function


__author__ = "Aerospike"
__copyright__ = "Copyright 2019 Aerospike"
__version__ = "1.6.6"

# Modules
import aerospike
import argparse
import getpass
import re
import signal
import socket


DEFAULT_TIMEOUT = 5

# Custom module to Daemonize this script.
###########################################
##           begin daemon.py
###########################################

import sys, os, time, atexit
from signal import SIGTERM
import fcntl
import subprocess


class Pidfile(object):
    def __init__(self, pidfile, procname):
        try:
            self.fd = os.open(pidfile, os.O_CREAT | os.O_RDWR)
        except IOError as e:
            sys.exit("Failed to open pidfile: %s" % str(e))
        self.pidfile = pidfile
        self.procname = procname
        assert not fcntl.flock(self.fd, fcntl.LOCK_EX)

    def unlock(self):
        assert not fcntl.flock(self.fd, fcntl.LOCK_UN)

    def write(self, pid):
        os.ftruncate(self.fd, 0)
        os.write(self.fd, "%d" % int(pid))
        os.fsync(self.fd)

    def kill(self):
        pid = int(os.read(self.fd, 4096))
        os.lseek(self.fd, 0, os.SEEK_SET)

        try:
            os.kill(pid, SIGTERM)
            time.sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                    os.remove(self.pidfile)
            else:
                return str(err)

        if self.is_running():
            return "Failed to kill %d" % pid

    def is_running(self):
        contents = os.read(self.fd, 4096)
        os.lseek(self.fd, 0, os.SEEK_SET)

        if not contents:
            return False

        p = subprocess.Popen(["ps", "-o", "comm", "-p", str(int(contents))],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if stdout == "COMM\n":
            return False

        if self.procname in stdout[stdout.find("\n") + 1:]:
            return True

        return False


# =============================================================================
#
# Daemon
#
# -----------------------------------------------------------------------------


class Daemon:
    """
    A generic daemon class.
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, logfile , stdin='/dev/null'):
        self.stdin = stdin
        self.stdout = logfile
        self.stderr = logfile
        self.pidfile = Pidfile(pidfile, "python")
        self.pidfileloc = pidfile
        self.client = None

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        self.pidfile.write(pid)

    def delpid(self):
        os.remove(self.pidfileloc)

    def sigterm_handler(self, signal, frame):
        if self.client:
            self.client.close()
            self.client = None
        sys.exit(0)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        if self.pidfile.is_running():
            self.pidfile.unlock()
            sys.exit("Daemon already running.")

        # Start the daemon
        self.daemonize()
        self.pidfile.unlock()
        signal.signal(signal.SIGTERM, self.sigterm_handler)
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        if not self.pidfile.is_running():
            self.pidfile.unlock()
            print("Daemon not running.", file=sys.stderr)
            return

        # Try killing the daemon process
        error = self.pidfile.kill()
        if error:
            self.pidfile.unlock()
            sys.exit(error)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()
    
    def once(self):
        """
        Run the process once
        """
        # Start the daemon
        self.run()
        if self.client:
            self.client.close()
            self.client = None

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """

###########################################
##           end daemon.py
###########################################

# =============================================================================
#
# Client
#
# -----------------------------------------------------------------------------


class Enumeration(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

    def __getitem__(self, name):
        if name in self:
            return name
        raise AttributeError

AuthMode = Enumeration([
    # Use internal authentication only.  Hashed password is stored on the server.
	# Do not send clear password. This is the default.

	"INTERNAL",

    # Use external authentication (like LDAP).  Specific external authentication is
	# configured on server.  If TLS defined, send clear password on node login via TLS.
	# Throw exception if TLS is not defined.

	"EXTERNAL",

    # Use external authentication (like LDAP).  Specific external authentication is
	# configured on server.  Send clear password on node login whether or not TLS is defined.
	# This mode should only be used for testing purposes because it is not secure authentication.

	"EXTERNAL_INSECURE",
])

class ClientError(Exception):
    pass


class Client(object):

    def __init__(self, addr, port, tls_enable=False, tls_name=None, tls_keyfile=None, tls_keyfile_pw=None, tls_certfile=None,
                 tls_cafile=None, tls_capath=None, tls_cipher=None, tls_protocols=None, tls_cert_blacklist=None,
                 tls_crl_check=False, tls_crl_check_all=False, auth_mode=aerospike.AUTH_INTERNAL, timeout=DEFAULT_TIMEOUT):
        self.addr = addr
        self.port = port
        self.tls_name = tls_name
        self.timeout = timeout
        self.host = (self.addr, self.port)
        if self.tls_name:
            self.host = (self.addr, self.port, self.tls_name)

        tls_config = {
            'enable': tls_enable
        }

        if tls_enable:
            tls_config = {
                'enable': tls_enable,
                'keyfile': tls_keyfile,
                'keyfile_pw': tls_keyfile_pw,
                'certfile': tls_certfile,
                'cafile': tls_cafile,
                'capath': tls_capath,
                'cipher_suite': tls_cipher,
                'protocols': tls_protocols,
                'cert_blacklist': tls_cert_blacklist,
                'crl_check': tls_crl_check,
                'crl_check_all': tls_crl_check_all
            }

        config = {
            'hosts': [
                self.host
            ],

            'policies': {
                'timeout': self.timeout*1000,
                'auth_mode': auth_mode
            },

            'tls': tls_config
        }

        self.asClient = aerospike.client(config)


    def connect(self, username=None, password=None):
        try:
            self.asClient.connect(username, password)
        except Exception as e:
            raise ClientError("Could not connect to server at %s %s: %s" % (self.addr, self.port, str(e)))

    def close(self):
        if self.asClient is not None:
            self.asClient.close()

    def info(self, request):
        read_policies = {'total_timeout': self.timeout}

        res = self.asClient.info_node(request, self.host, policy=read_policies)
        out = re.split("\s+", res, maxsplit=1)

        if len(out) == 2:
            return out[1]
        else:
            raise ClientError("Failed to parse response: %s" % (res))


####
# Usage :
# ## To send just the latency information to Graphite
# python asgraphite.py -l 'latency:back=70;duration=60' --start -g s1 -p 2023
# ## To send just 1 namespace stats to Graphite, for multiple namespaces, start accordingly
# python asgraphite.py -n --start -g s1 -p 2023
# ## To send just the statistics information to Graphite
# python asgraphite.py --start -g s1 -p 2023
# ## To send sets info to Graphite
# python asgraphite.py -s --start -g s1 -p 2023
# ## To send XDR DC statistics to Graphite
# python asgraphite.py -x --start -g s1 -p 2023
# ## To Stop the Daemon
#  python asgraphite.py --stop
####

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

parser.add_argument("-U"
                    , "--user"
                    , help="user name")
parser.add_argument("-P"
                    , "--password"
                    , nargs="?"
                    , const="prompt"
                    , help="password")
parser.add_argument("-c"
                    , "--credentials-file"
                    , dest="credentials"
                    , help="Path to the credentials file. Use this in place of --user and --password.")
parser.add_argument("--auth-mode"
                    , dest="auth_mode"
                    , default=str(AuthMode.INTERNAL)
                    , help="Authentication mode. Values: " + str(list(AuthMode)) + " (default: %(default)s)")
group.add_argument("--stop"
                    , action="store_true"
                    , dest="stop"
                    , help="Stop the Daemon")
group.add_argument("--start"
                    , action="store_true"
                    , dest="start"
                    , help="Start the Daemon")
group.add_argument("--once"
                    , action="store_true"
                    , dest="once"
                    , help="Run the script once")
group.add_argument("--restart"
                    , action="store_true"
                    , dest="restart"
                    , help="Restart the Daemon")
parser.add_argument("--stdout"
                    , action="store_true"
                    , dest="stdout"
                    , help="Print metrics output to stdout. Only useful with --once")
parser.add_argument("-v"
                    , "--verbose"
                    , action="store_true"
                    , dest="verbose"
                    , help="Enable verbose logging")
parser.add_argument("-n"
                    , "--namespace"
                    , action="store_true"
                    , dest="namespace"
                    , help="Get all namespace statistics")
parser.add_argument("-s"
                    , "--sets"
                    , action="store_true"
                    , dest="sets"
                    , help="Gather set based statistics")
parser.add_argument("-l"
                    , "--latency"
                    , dest="latency"
                    , help="Enable latency statistics and specify query (ie. latency:back=70;duration=60)")
parser.add_argument("-x"
                    , "--xdr"
                    , nargs='+'
                    , action='append'
                    , dest="dc"
                    , help="Gather XDR datacenter statistics")
parser.add_argument("-g"
                    , "--graphite"
                    , dest="graphite_server"
                    , action="append"
                    , help="REQUIRED: IP:PORT for Graphite server. This argument can be specified multiple times to send to multiple servers")
parser.add_argument("--interval"
                    , dest="graphite_interval"
                    , default=30
                    , help="How often metrics are sent to graphite (seconds)")
parser.add_argument("--prefix"
                    , dest="graphite_prefix"
                    , default='instances.aerospike.'
                    , help="Prefix used when sending metrics to Graphite server (default: %(default)s)")
parser.add_argument("--hostname"
                    , dest="hostname"
                    , default=socket.gethostname()
                    , help="Hostname used when sending metrics to Graphite server (default: %(default)s)")
parser.add_argument("-i"
                    , "--info-port"
                    , dest="info_port"
                    , default=3000
                    , type=int
                    , help="PORT for Aerospike server (default: %(default)s)")
parser.add_argument("-b"
                    , "--base-node"
                    , dest="base_node"
                    , default="127.0.0.1"
                    , help="Base host for collecting stats (default: %(default)s)")
parser.add_argument("-f"
                    , "--log-file"
                    , dest="log_file"
                    , default='/var/log/aerospike/asgraphite.log'
                    , help="Logfile for asgraphite (default: %(default)s)")
parser.add_argument("-si"
                    , "--sindex"
                    , action="store_true"
                    , dest="sindex"
                    , help="Gather sindex based statistics")
parser.add_argument("-hi"
                    , "--hist-dump"
                    , nargs='+'
                    , action='append'
                    , dest="hist_dump"
                    , help="Gather histogram data.  Valid args are ttl and objsz")
parser.add_argument("--timeout"
                    , dest="timeout"
                    , default=DEFAULT_TIMEOUT
                    , help="Set timeout value in seconds to node level operations. (default: %(default)s)")
parser.add_argument("--tls-enable"
                    , action="store_true"
                    , dest="tls_enable"
                    , help="Enable TLS")
parser.add_argument("--tls-name"
                    , dest="tls_name"
                    , help="The expected name on the server side certificate")
parser.add_argument("--tls-keyfile"
                    , dest="tls_keyfile"
                    , help="The private keyfile for your client TLS Cert")
parser.add_argument("--tls-keyfile-pw"
                    , dest="tls_keyfile_pw"
                    , help="Password to load protected tls_keyfile")
parser.add_argument("--tls-certfile"
                    , dest="tls_certfile"
                    , help="The client TLS cert")
parser.add_argument("--tls-cafile"
                    , dest="tls_cafile"
                    , help="The CA for the server's certificate")
parser.add_argument("--tls-capath"
                    , dest="tls_capath"
                    , help="The path to a directory containing CA certs and/or CRLs")
parser.add_argument("--tls-ciphers"
                    , dest="tls_ciphers"
                    , help="Ciphers to include. See https://www.openssl.org/docs/man1.0.1/apps/ciphers.html for cipher list format")
parser.add_argument("--tls-protocols"
                    , dest="tls_protocols"
                    , help="The TLS protocol to use. Available choices: TLSv1, TLSv1.1, TLSv1.2, all. An optional + or - can be appended before the protocol to indicate specific inclusion or exclusion.")
parser.add_argument("--tls-cert-blacklist"
                    , dest="tls_cert_blacklist"
                    , help="Blacklist including serial number of certs to revoke")
parser.add_argument("--tls-crl-check"
                    , dest="tls_crl_check"
                    , action="store_true"
                    , help="Checks SSL/TLS certs against vendor's Certificate Revocation Lists for revoked certificates. CRLs are found in path specified by --tls_capath. Checks the leaf certificates only")
parser.add_argument("--tls-crl-check-all"
                    , dest="tls_crl_check_all"
                    , action="store_true"
                    , help="Check on all entries within the CRL chain")


args = parser.parse_args()

user = None
password = None
auth_mode = aerospike.AUTH_INTERNAL

if args.user != None:
    user = args.user
    if args.password == "prompt":
        args.password = getpass.getpass("Enter Password:")
    password = args.password

if args.credentials:
    try:
        cred_file = open(args.credentials,'r')
        user = cred_file.readline().strip()
        password = cred_file.readline().strip()
    except IOError:
        print("Unable to read credentials file: %s"%args.credentials)

if user:
    if args.auth_mode == AuthMode.EXTERNAL:
        auth_mode = aerospike.AUTH_EXTERNAL
    elif args.auth_mode == AuthMode.EXTERNAL_INSECURE:
        auth_mode = aerospike.AUTH_EXTERNAL_INSECURE

# Configurable parameters
LOGFILE = args.log_file

if not args.stop and not args.stdout:
    if args.graphite_server and len(args.graphite_server) > 0:
        GRAPHITE_SERVERS = args.graphite_server
        for gs in GRAPHITE_SERVERS:
            gsgp = gs.split(":")
            if len(gsgp) != 2:
                parser.print_help()
                sys.exit(200)
            try:
                int(gsgp[1])
            except:
                parser.print_help()
                sys.exit(200)
    else:
        parser.print_help()
        sys.exit(200)

AEROSPIKE_SERVER = args.base_node
AEROSPIKE_PORT = args.info_port
AEROSPIKE_SERVER_ID = args.hostname
AEROSPIKE_XDR_DCS = args.dc
GRAPHITE_PATH_PREFIX = args.graphite_prefix + AEROSPIKE_SERVER_ID
INTERVAL = int(args.graphite_interval)

class clGraphiteDaemon(Daemon):
    def connect(self, gs, gp):
        GRAPHITE_RUNNING = False
        while GRAPHITE_RUNNING is not True:
            try:
                s = socket.socket()
                s.connect((gs, gp))
                GRAPHITE_RUNNING = True
            except:
                print("Unable to connect to Graphite server on %s:%d" % (gs, gp))
                s.close()
                sys.stdout.flush()
                time.sleep(INTERVAL)
        return s

    def run(self):
        if not args.stdout:
            print("Starting asgraphite daemon" , time.asctime(time.localtime()))
            s = []
            for gs in GRAPHITE_SERVERS:
                gsa = gs.split(":")
                s.append({"ip":gsa[0],"port":int(gsa[1]),"s":self.connect(gsa[0],int(gsa[1]))})
            print("Aerospike-Graphite connector started: ", time.asctime(time.localtime()))
            sys.stdout.flush()

        self.client = Client(addr=AEROSPIKE_SERVER, port=AEROSPIKE_PORT, tls_enable=args.tls_enable, tls_name=args.tls_name,
                        tls_keyfile=args.tls_keyfile, tls_keyfile_pw=args.tls_keyfile_pw, tls_certfile=args.tls_certfile,
                        tls_cafile=args.tls_cafile, tls_capath=args.tls_capath, tls_cipher=args.tls_ciphers,
                        tls_protocols=args.tls_protocols, tls_cert_blacklist=args.tls_cert_blacklist,
                        tls_crl_check=args.tls_crl_check, tls_crl_check_all=args.tls_crl_check_all,
                        auth_mode=auth_mode, timeout=args.timeout)

        while True:

            try:
                self.client.connect(username=user, password=password)
                break
            except ClientError as e:
                if self.client:
                    self.client.close()
                print("Unable to connect to Aerospike server on %s:%s "% (AEROSPIKE_SERVER, str(AEROSPIKE_PORT)))
                print(e)
                sys.stdout.flush()
                time.sleep(INTERVAL)

        while True:
            msg = []
            now = int(time.time())

            r = -1
            try:
                r = self.client.info('statistics')
                if (-1 != r):
                    lines = []
                    for string in r.split(';'):
                        if string == "":
                            continue
    
                        if string.count('=') > 1:
                            continue
    
                        name, value = string.split('=')
                        value = value.replace('false', "0")
                        value = value.replace('true', "1")
                        lines.append("%s.service.%s %s %s" % (GRAPHITE_PATH_PREFIX, name, value, now))
                    msg.extend(lines)
            except:
                print("Unable to parse general stats:")
                print(r)        # not combined with above line because 'r' could be int (-1) or string
                sys.stdout.flush()

            if args.sets:
                r = -1
                try:
                    r = self.client.info('sets')
                    if (-1 != r):
                        r = r.strip()
                        lines = []
                        for string in r.split(';'):
                            if len(string) == 0:
                                continue
                            setList = string.split(':')
                            namespace = setList[0].split('=')
                            sets = setList[1].split('=')
                            for set_tuple in setList[2:]:
                                key, value = set_tuple.split('=')
                                lines.append("%s.sets.%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, namespace[1], sets[1], key, value, now))
                        msg.extend(lines)
                except Exception as e:
                    print("Unable to parse set stats:")
                    print(r)
                    print(e)
                    sys.stdout.flush()

            if args.latency:
                r = -1
                try:
                    if args.latency.startswith('latency:'):
                        r = self.client.info(args.latency)
                    else:
                        r = self.client.info('latency:')
                    if (-1 != r):
                        r = r.strip()
                        lines = []
                        latency_type = ""
                        header = []
                        for string in r.split(';'):
                            if len(string) == 0 or string.startswith("error"):
                                continue
                            if len(latency_type) == 0:
                                # Base case
                                latency_type, rest = string.split(':', 1)
                                # handle dynamic naming
                                match = re.match('{(.*)}',latency_type)
                                if match:
                                    latency_type = re.sub('{.*}-','',latency_type)
                                    latency_type = match.groups()[0]+'.'+latency_type
                                header = rest.split(',')
                            else:
                                val = string.split(',')
                                for i in range(1, len(header)):
                                    name = latency_type + "." + header[i]
                                    name = name.replace('>', 'over_')
                                    name = name.replace('ops/sec', 'ops_per_sec')
                                    value = val[i]
                                    lines.append("%s.latency.%s %s %s" % (GRAPHITE_PATH_PREFIX , name, value, now))
                                # Reset base case
                                latency_type = ""
                                header = []
                        msg.extend(lines)
                except Exception as e:
                    print("Unable to parse latency stats:")
                    print(r)
                    print(e)
                    sys.stdout.flush()

            if args.namespace:
                r = -1
                try:
                    r = self.client.info('namespaces')
                    if (-1 != r):
                        r = r.strip()
                        namespaces = list(filter(None, r.split(';')))
                        if len(namespaces) > 0:
                            for namespace in namespaces:
                                r = -1
                                r = self.client.info('namespace/' + namespace)
                                if (-1 != r):
                                    r = r.strip()
                                    lines = []
                                    for string in r.split(';'):
                                        name, value = string.split('=')
                                        value = value.replace('false', "0")
                                        value = value.replace('true', "1")
                                        lines.append(GRAPHITE_PATH_PREFIX + "." + namespace + ".%s %s %s" % (name, value, now))
                                    msg.extend(lines)
                                if args.hist_dump:
                                    # Flatten the list
                                    HD = [ item for sublist in args.hist_dump for item in sublist]
                                    for histtype in HD:
                                        try:
                                            r = self.client.info('hist-dump:ns=' + namespace + ';hist=' + histtype)
                                            if (-1 != r):
                                                if 'hist-not-applicable' in r:
                                                    continue    # skip in-memory namespaces that don't have histograms
                                                r = r.strip()
                                                lines = []
                                                string, ignore = r.split(';')
                                                namespace, string = string.split(':')
                                                type, string = string.split('=')
                                                buckets, size, string = string.split(',', 2)
                                                lines.append(GRAPHITE_PATH_PREFIX + ".%s.histogram.%s.%s %s %s" % (namespace, type, "bucketsize", size, now))
                                                bucket = 0
                                                total = 0
                                                for val in string.split(','):
                                                    lines.append(GRAPHITE_PATH_PREFIX + ".%s.histogram.%s.%s %s %s" % (namespace, type, "bucket_"  + str(bucket), val, now))
                                                    bucket+=1
                                                msg.extend(lines)
                                        except:
                                            print("Failure to get histtype " + histtype + ":")
                                            print(r)
                                            sys.stdout.flush()
                except Exception as e:
                    print("Unable to parse namespace list:")
                    print(r)
                    print(e)
                    sys.stdout.flush()
    
            if args.dc:
                r = -1
                # Flatten the list
                DCS = [ item for sublist in AEROSPIKE_XDR_DCS for item in sublist]
                for DC in DCS:
                    try:
                        r = self.client.info('dc/' + DC)
                        if (-1 != r):
                            r = r.strip()
                            lines = []
                            for string in r.split(';'):
                                if string == "":
                                    continue
    
                                if string.count('=') > 1:
                                    continue
    
                                name, value = string.split('=')
                                value = value.replace('false', "0")
                                value = value.replace('true', "1")
                                value = value.replace('INACTIVE',"0")
                                value = value.replace('CLUSTER_DOWN',"1")
                                value = value.replace('CLUSTER_UP',"2")
                                value = value.replace('WINDOW_SHIPPER',"3")
                                lines.append("%s.xdr.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, DC, name, value, now))
                            msg.extend(lines)
                    except Exception as e:
                        print("Unable to parse DC stats:")
                        print(r)
                        print(e)
                        sys.stdout.flush()
    
    ##    Logic to export SIndex Stats to Graphite
    ##    Since Graphite understands numbers we have used substitutes as below
    ##    sync_state --
    ##        synced = 1 & need_sync = 0
    ##    state --
    ##        RW = 1 & WO = 0
    
            if args.sindex:
                r = -1
                try:
                    r = self.client.info('sindex')
                    if (-1 != r):
                        r = r.strip()
                        indexes = str(filter(None, r))
                        if len(indexes) > 0:
                            lines = []
                            for index_line in indexes.split(';'):
                                if len(index_line) > 0:
                                    index = dict(item.split("=") for item in index_line.split(":"))
    
                                    if (index["sync_state"] == "synced"):
                                        index["sync_state"] = 1
                                    elif (index["sync_state"] == "need_sync"):
                                        index["sync_state"] = 0
    
                                    if (index["state"] == "RW"):
                                        index["state"] = 1
                                    elif (index["state"] == "WO"):
                                        index["state"] = 0
    
                                    lines.append("%s.sindexes.%s.%s.sync_state %s %s" % (GRAPHITE_PATH_PREFIX, index["ns"], index["indexname"], index["sync_state"], now))
                                    lines.append("%s.sindexes.%s.%s.state %s %s" % (GRAPHITE_PATH_PREFIX, index["ns"], index["indexname"], index["state"], now))
    
                                    r = -1
                                    try:
                                        r = self.client.info('sindex/' + index["ns"] + '/' + index["indexname"])
                                    except:
                                        pass
                                    if (-1 != r):
                                        r = r.strip()
                                        for string in r.split(';'):
                                            name, value = string.split('=')
                                            value = value.replace('false', "0")
                                            value = value.replace('true', "1")
                                            lines.append("%s.sindexes.%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, index["ns"], index["indexname"], name, value, now))
                            msg.extend(lines)
                except Exception as e:
                    print("Unable to parse sindex stats:")
                    print(r)
                    print(e)
                    sys.stdout.flush()

            nmsg = ''
            #AER-2098 move all non numeric values to numbers
            #check if the val is a float (graphite uses float)
            #if not, break down the non-numeric part of value into numeric
            #this is kind of one way hash but easy to guess
            #leaving the earlier true/false/sync states the way they were done
            #as there is no major gain in moving them to the new format
            for line in msg:
                fields=line.split()

                try:
                    float(fields[1])
                except ValueError:
                    val = fields[1]
                    valstr = ''
                    for x in val:
                        try:
                            int(x)
                            valstr += str(x)
                        except ValueError:
                            # convert [Aa-Zz] into numbers 1-26
                            # doing abs() so that non alphanumerics are taken
                            # care of example: /
                            # ord ('a') + 1 = 96, replacing unnecessary fn call
                            valstr += str(abs(ord(x.lower()) - 96))

                    fields[1] = valstr
                line = ''
                for f in fields:
                    line += f + ' '
                nmsg += line.strip('.') + '\n'

            if not args.stdout:
                if args.verbose:
                    print(nmsg)

                for s_idx,s_sock in enumerate(s):
                    try:
                        s_sock["s"].sendall(nmsg)
                    except:
                        print("ERROR: Unable to send to graphite server %s:%d, retrying connection.." %(s_sock["ip"],s_sock["port"]))
                        sys.stdout.flush()
                        s_sock["s"].close()
                        s[s_idx]["s"] = self.connect(s_sock["ip"],s_sock["port"])
            else:
                print(nmsg)

            if args.once:
                break

            time.sleep(INTERVAL)

if __name__ == "__main__":
    #TODO: move this to config param
    daemon = clGraphiteDaemon('/tmp/asgraphite.pid', LOGFILE)
    if args.start or args.stop or args.restart or args.once:
        if args.start:
            daemon.start()
        elif args.stop:
            daemon.stop()
        elif args.restart:
            daemon.restart()
        elif args.once:
            daemon.once()
        else:
            print("Unknown command")
            sys.exit(20)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(22)
