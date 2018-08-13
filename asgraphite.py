#!/usr/bin/env python

# Copyright 2013-2017 Aerospike, Inc.
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


__author__ = "Aerospike"
__copyright__ = "Copyright 2018 Aerospike"
__version__ = "1.7.0"

# Modules
import argparse
import getpass
import re
import sys
import time
import socket
import struct
from ctypes import create_string_buffer

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
        except IOError, e:
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
        except OSError, err:
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
        except OSError, e:
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
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        self.pidfile.write(pid)

    def delpid(self):
        os.remove(self.pidfile)

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
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        if not self.pidfile.is_running():
            self.pidfile.unlock()
            print >> sys.stderr, "Daemon not running."
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

STRUCT_PROTO = struct.Struct('! Q')
STRUCT_AUTH = struct.Struct('! xxBB12x')
STRUCT_FIELD = struct.Struct('! IB')

MSG_VERSION = 0
MSG_TYPE = 2
AUTHENTICATE = 0
USER = 0
CREDENTIAL = 3
SALT = "$2a$10$7EqJtq98hPqEX7fNZaFWoO"


class ClientError(Exception):
    pass


class Client(object):

    def __init__(self, addr, port, timeout=0.7):
        self.addr = addr
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self, keyfile=None, certfile=None, ca_certs=None, ciphers=None, tls_enable=False, encrypt_only=False,
        capath=None, protocols=None, cert_blacklist=None, crl_check=False, crl_check_all=False, tls_name=None):
        s = None
        for res in socket.getaddrinfo(self.addr, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            ssl_context = None
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error as msg:
                s = None
                continue
            if tls_enable:
                from ssl_context import SSLContext
                from OpenSSL import SSL
                ssl_context = SSLContext(enable_tls=tls_enable, encrypt_only=encrypt_only, cafile=ca_certs, capath=capath,
                       keyfile=keyfile, certfile=certfile, protocols=protocols,
                       cipher_suite=ciphers, cert_blacklist=cert_blacklist,
                       crl_check=crl_check, crl_check_all=crl_check_all).ctx
                s = SSL.Connection(ssl_context,s)
            try:
                s.connect(sa)
                if ssl_context:
                    s.set_app_data(tls_name)
                    s.do_handshake()
            except socket.error as msg:
                s.close()
                s = None
                print "Connect Error %s" % msg
                continue
            break

        if s is None:
            raise ClientError(
                "Could not connect to server at %s %s" % (self.addr, self.port))

        self.sock = s
        return self

    def close(self):
        if self.sock is not None:
            self.sock.settimeout(None)
            self.sock.close()
            self.sock = None

    def auth(self, username, password, timeout=None):

        import bcrypt

        if password == None:
            password = ''
        credential = bcrypt.hashpw(password, SALT)

        if timeout is None:
            timeout = self.timeout

        l = 8 + 16
        l += 4 + 1 + len(username)
        l += 4 + 1 + len(credential)

        buf = create_string_buffer(l)
        offset = 0

        proto = (MSG_VERSION << 56) | (MSG_TYPE << 48) | (l - 8)
        STRUCT_PROTO.pack_into(buf, offset, proto)
        offset += STRUCT_PROTO.size

        STRUCT_AUTH.pack_into(buf, offset, AUTHENTICATE, 2)
        offset += STRUCT_AUTH.size

        STRUCT_FIELD.pack_into(buf, offset, len(username) + 1, USER)
        offset += STRUCT_FIELD.size
        fmt = "! %ds" % len(username)
        struct.pack_into(fmt, buf, offset, username)
        offset += len(username)

        STRUCT_FIELD.pack_into(buf, offset, len(credential) + 1, CREDENTIAL)
        offset += STRUCT_FIELD.size
        fmt = "! %ds" % len(credential)
        struct.pack_into(fmt, buf, offset, credential)
        offset += len(credential)

        self.send(buf)

        buf = self.recv(8, timeout)
        rv = STRUCT_PROTO.unpack(buf)
        proto = rv[0]
        pvers = (proto >> 56) & 0xFF
        ptype = (proto >> 48) & 0xFF
        psize = (proto & 0xFFFFFFFFFFFF)

        buf = self.recv(psize, timeout)
        status = ord(buf[1])

        if status != 0:
            raise ClientError("Autentication Error %d for '%s' " %
                              (status, username))

    def send(self, data):
        if self.sock:
            try:
                r = self.sock.sendall(data)
            except IOError as e:
                raise ClientError(e)
            except socket.error as e:
                raise ClientError(e)
        else:
            raise ClientError('socket not available')

    def send_request(self, request, pvers=2, ptype=1):
        if request:
            request += '\n'
        sz = len(request) + 8
        buf = create_string_buffer(len(request) + 8)
        offset = 0

        proto = (pvers << 56) | (ptype << 48) | len(request)
        STRUCT_PROTO.pack_into(buf, offset, proto)
        offset = STRUCT_PROTO.size

        fmt = "! %ds" % len(request)
        struct.pack_into(fmt, buf, offset, request)
        offset = offset + len(request)

        self.send(buf)

    def recv(self, sz, timeout):
        out = ""
        pos = 0
        start_time = time.time()
        while pos < sz:
            buf = None
            try:
                buf = self.sock.recv(sz)
            except IOError as e:
                raise ClientError(e)
            if pos == 0:
                out = buf
            else:
                out += buf
            pos += len(buf)
            if timeout and time.time() - start_time > timeout:
                raise ClientError(socket.timeout())
        return out

    def recv_response(self, timeout=None):
        buf = self.recv(8, timeout)
        rv = STRUCT_PROTO.unpack(buf)
        proto = rv[0]
        pvers = (proto >> 56) & 0xFF
        ptype = (proto >> 48) & 0xFF
        psize = (proto & 0xFFFFFFFFFFFF)

        if psize > 0:
            return self.recv(psize, timeout)
        return ""

    def info(self, request):
        self.send_request(request)
        res = self.recv_response(timeout=self.timeout)
        if res.lower().startswith("err"):
            raise ClientError(res)
        out = re.split("\s+", res, maxsplit=1)
        if len(out) == 2:
            return out[1]
        else:
            raise ClientError("Failed to parse response: %s" % (res))

#########
# Parsers
#########

def clean(res):
    if res is None:
        return None
    res = res.strip().strip(';').strip(':').replace(';;', ';')
    if len(res) > 0:
        return res
    return None

# simply returns the same value it was given,
def value():
    def parse(input):
        if input == None:
            return None
        return input.strip()
    return parse

# returns a (k,v) tuple, split on first delim
def pair(delim='=', key=value(), value=value()):
    def parse(input):
        if input is None:
            return None
        p = input.strip().strip(delim).split(delim, 1)
        lp = len(p)
        if lp == 2:
            (k, v) = p
            return (key(k), value(v))
        elif lp == 1:
            k = p[0]
            return (key(k), value(None))
        else:
            return (key(None), value(None))
    return parse

# returns a list of all items 
def seq(delim=';', entry=value()):
    def parse(input):
        if input is None:
            return None
        return (entry(e) for e in input.strip().strip(delim).split(delim))
    return parse


# combine pair with seq. A list of (k,v) tuples
def pairs(delim=';'):
    return seq(entry=pair(),delim=delim)

# 1 more level of sequences, for sindex and set discovery
def seqs():
    return seq(entry=pairs(':'))


def parse(input, parser=value()):
    return parser(clean(input)) if input is not None else input


#########
# Readers
#########

def service(client, data, now):
    lines = []
    data = parse(data,parser=pairs())
    for metric, value in data:
        value = value.replace('false','0')
        value = value.replace('true','1')
        lines.append("%s.service.%s %s %s" % (GRAPHITE_PATH_PREFIX, metric, value, now))
    return lines

def sets(client, data, now):
    lines = []
    data = parse(data,parser=seqs())
    for entry in data:
        _, namespace = entry.next()
        _, set_name = entry.next()
        for metric, value in entry:
            lines.append("%s.sets.%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, namespace, set_name, metric, value, now))
    return lines

# Parse each DC stat
def dc(client, data, now):
    # discovery of datacenters, return list of DCs
    dcs = parse(data,parser=seq())
    lines = []
    for dc in dcs:
        r = -1
        r = client.info("dc/"+dc)
        if(-1 != r):
            data = parse(r,parser=pairs())
            for metric, value in data:
                value = value.replace('true', "1")
                value = value.replace('false', "0")
                value = value.replace('INACTIVE',"0")
                value = value.replace('CLUSTER_DOWN',"1")
                value = value.replace('CLUSTER_UP',"2")
                value = value.replace('WINDOW_SHIPPER',"3")
                lines.append("%s.xdr.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, dc, metric, value, now))
    return lines

# namespace metrics
def namespace(client, data, now):
    # namespace discovery
    namespaces = parse(data,parser=seq())
    lines = []
    for namespace in namespaces:
        r = -1
        r = client.info("namespace/"+namespace)
        if( -1 != r):
            data = parse(r,parser=pairs())
            for metric, value in data:
                value = value.replace('false', "0")
                value = value.replace('true', "1")
                lines.append("%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, namespace, metric, value, now))
    return lines

def sindex(client, data, now):
    # sindex discovery
    lines = []
    sindexes = parse(data,parser=seqs())
    for sindex in sindexes:
        index = { k:v for k,v in sindex }
        lines.append("%s.sindexes.%s.%s.sync_state %s %s" % (GRAPHITE_PATH_PREFIX, index["ns"], index["indexname"], index["sync_state"], now))
        lines.append("%s.sindexes.%s.%s.state %s %s" % (GRAPHITE_PATH_PREFIX, index["ns"], index["indexname"], index["state"], now))
        r = -1
        r = client.info("sindex/%s/%s"%(index['ns'],index['indexname']))
        if (-1 != r):
            data = parse(r,parser=pairs())
            for metric, value in data:
                value = value.replace('false', "0")
                value = value.replace('true', "1")
                lines.append("%s.sindexes.%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, index['ns'], index['indexname'], metric, value, now))
    return lines

def latency(client, data, now):
    lines = []
    latencies = parse(data,parser=seq())
    header = []
    latency_type = ""
    for line in latencies:
        if line.startswith("error"):
            continue
        if len(latency_type) == 0:
            # header line
            latency_type, rest = line.split(':',1)
            #dynamic naming
            match = re.match('{(.*)}',latency_type)
            if match:
                latency_type = re.sub('{.*}-','',latency_type)
                latency_type = match.groups()[0]+'.'+latency_type
            header = rest.split(',')
        else:
            val = line.split(',')
            for i in range (1, len(header)):
                name = latency_type + "." + header[i]
                name = name.replace('>', 'over_')
                name = name.replace('ops/sec', 'ops_per_sec')
                value = val[i]
                lines.append("%s.latency.%s %s %s" % (GRAPHITE_PATH_PREFIX , name, value, now))
            # reset nase case
            latency_type=""
            header = []
    return lines

def histogram(client, data, now):
    lines = []
    namespaces=parse(data,parser=seq())
    for namespace in namespaces:
        for hist_type in  ["ttl","object-size-linear"]:
            r = -1
            r = client.info("histogram:namespace=%s;type=%s"%(namespace,hist_type))
            if (-1 != r and 0 != len(r)):
                hist_data = parse(r, parser=seq(delim=':',entry=pair()))
                cdata = {k:v for (k,v) in hist_data}
                if 'bucket-width' not in cdata:
                    continue
                bucket_size = cdata['bucket-width']
                lines.append(GRAPHITE_PATH_PREFIX + ".%s.histogram.%s.%s %s %s" % (namespace, hist_type, "bucketsize", bucket_size, now))
                for index, bucket in enumerate(cdata['buckets'].split(',')):
                    lines.append(GRAPHITE_PATH_PREFIX + ".%s.histogram.%s.%s %s %s" % (namespace, hist_type, "bucket_"  + str(index), bucket, now))
    return lines
    
###
# Usage :
### To send just the latency information to Graphite
# python asgraphite.py -l 'latency:back=70;duration=60' --start -g s1 -p 2023
# ## To send all namespace stats to Graphite
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
                    , action='store_true'
                    , dest="dc"
                    , help="Gather XDR datacenter statistics")
parser.add_argument("-g"
                    , "--graphite"
                    , dest="graphite_server"
                    , help="REQUIRED: IP for Graphite server")
parser.add_argument("-p"
                    , "--graphite-port"
                    , dest="graphite_port"
                    , help="REQUIRED: PORT for Graphite server")
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
                    , action='store_true'
                    , dest="hist_dump"
                    , help="Gather histogram data.  Valid args are ttl and objsz")
parser.add_argument("--tls_enable"
                    , action="store_true"
                    , dest="tls_enable"
                    , help="Enable TLS")
parser.add_argument("--tls_encrypt_only"
                    , action="store_true"
                    , dest="tls_encrypt_only"
                    , help="TLS Encrypt Only")
parser.add_argument("--tls_keyfile"
                    , dest="tls_keyfile"
                    , help="The private keyfile for your client TLS Cert")
parser.add_argument("--tls_certfile"
                    , dest="tls_certfile"
                    , help="The client TLS cert")
parser.add_argument("--tls_cafile"
                    , dest="tls_cafile"
                    , help="The CA for the server's certificate")
parser.add_argument("--tls_capath"
                    , dest="tls_capath"
                    , help="The path to a directory containing CA certs and/or CRLs")
parser.add_argument("--tls_protocols"
                    , dest="tls_protocols"
                    , help="The TLS protocol to use. Available choices: SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2, all. An optional + or - can be appended before the protocol to indicate specific inclusion or exclusion.")
parser.add_argument("--tls_blacklist"
                    , dest="tls_blacklist"
                    , help="Blacklist including serial number of certs to revoke")
parser.add_argument("--tls_ciphers"
                    , dest="tls_ciphers"
                    , help="Ciphers to include. See https://www.openssl.org/docs/man1.0.1/apps/ciphers.html for cipher list format")
parser.add_argument("--tls_crl"
                    , dest="tls_crl"
                    , action="store_true"
                    , help="Checks SSL/TLS certs against vendor's Certificate Revocation Lists for revoked certificates. CRLs are found in path specified by --tls_capath. Checks the leaf certificates only")
parser.add_argument("--tls_crlall"
                    , dest="tls_crlall"
                    , action="store_true"
                    , help="Check on all entries within the CRL chain")
parser.add_argument("--tls_name"
                    , dest="tls_name"
                    , help="The expected name on the server side certificate")



args = parser.parse_args()

user = None
password = None

if args.user != None:
    user = args.user
    if args.password == "prompt":
        args.password = getpass.getpass("Enter Password:")
    password = args.password

# Configurable parameters
LOGFILE = args.log_file

if not args.stop and not args.stdout:
    if args.graphite_server:
        GRAPHITE_SERVER = args.graphite_server
    else:
        parser.print_help()
        sys.exit(200)

    if args.graphite_port:
        GRAPHITE_PORT = int(args.graphite_port)
    else:
        parser.print_help()
        sys.exit(3)

AEROSPIKE_SERVER = args.base_node
AEROSPIKE_PORT = args.info_port
AEROSPIKE_SERVER_ID = args.hostname
AEROSPIKE_XDR_DCS = args.dc
GRAPHITE_PATH_PREFIX = args.graphite_prefix + AEROSPIKE_SERVER_ID
INTERVAL = int(args.graphite_interval)

class clGraphiteDaemon(Daemon):
    def connect(self):
        GRAPHITE_RUNNING = False
        while GRAPHITE_RUNNING is not True:
            try:
                s = socket.socket()
                s.connect((GRAPHITE_SERVER, GRAPHITE_PORT))
                GRAPHITE_RUNNING = True
            except:
                print "unable to connect to Graphite server on %s:%d" % (GRAPHITE_SERVER, GRAPHITE_PORT)
                s.close()
                sys.stdout.flush()
                time.sleep(INTERVAL)
        return s


    def query(self, client,  metric, time ,function):
        data = -1
        try:
            data = client.info(metric)
            return function(client,data,time)
        except Exception as e:
            print "Unable to parse %s:" % metric
            print data
            print e
            sys.stdout.flush()
            exit(25)

    def run(self):
        if not args.stdout:
            print "Starting asgraphite daemon" , time.asctime(time.localtime())
            s = self.connect()
            print "Aerospike-Graphite connector started: ", time.asctime(time.localtime())
            sys.stdout.flush()
        while True:
            msg = []
            now = int(time.time())
            try:
                client = Client(addr=AEROSPIKE_SERVER,port=AEROSPIKE_PORT)
                client.connect(keyfile=args.tls_keyfile, certfile=args.tls_certfile, ca_certs=args.tls_cafile, ciphers=args.tls_ciphers, tls_enable=args.tls_enable,
                    encrypt_only=args.tls_encrypt_only, capath=args.tls_capath, protocols=args.tls_protocols, cert_blacklist=args.tls_blacklist, crl_check=args.tls_crl,
                    crl_check_all=args.tls_crlall, tls_name=args.tls_name)
                global user, password
                if args.credentials:
                    try:
                        cred_file = open(args.credentials,'r')
                        user = cred_file.readline().strip()
                        password = cred_file.readline().strip()
                    except IOError:
                        print "Unable to read credentials file: %s"%args.credentials
                if user:
                    status = client.auth(user,password)
            except Exception as e:
                print "Unable to connect to aerospike"
                print e
                sys.stdout.flush()
                time.sleep(INTERVAL)
                continue
            msg += self.query(client, 'statistics', now, service)
            if args.sets:
                msg += self.query(client, 'sets', now, sets)
            if args.latency:
                if args.latency.startswith('latency:'):
                    msg += self.query(client, args.latency, now, latency)
                else:
                    msg += self.query(client, 'latency:', now, latency)
            if args.namespace:
                msg += self.query(client, 'namespaces', now, namespace)
            if args.hist_dump:
                temp=self.query(client, 'namespaces', now, histogram)
                msg += temp
            if args.dc:
                msg += self.query(client, 'dcs', now, dc)
    ##    Logic to export SIndex Stats to Graphite
    ##    Since Graphite understands numbers we have used substitutes as below
    ##    sync_state --
    ##        synced = 1 & need_sync = 0
    ##    state --
    ##        RW = 1 & WO = 0
            if args.sindex:
                msg += self.query(client, 'sindex', now, sindex)
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
                try:
                    if args.verbose:
                        print nmsg
                    s.sendall(nmsg)
                except:
                    #Once the connection is broken, we need to reconnect
                    print "ERROR: Unable to send to graphite server, retrying connection.."
                    sys.stdout.flush()
                    s.close()
                    s = self.connect()
            else:
                print nmsg
            client.close()
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
            print "Unknown command"
            sys.exit(20)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(22)
