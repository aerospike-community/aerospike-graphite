#!/usr/bin/env python

# Copyright 2013-2014 Aerospike, Inc.
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
__copyright__ = "Copyright 2013 Aerospike"
__version__ = "1.4.2"

# Modules
import argparse
import sys
import time
import socket

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

	def run(self):
		"""
		You should override this method when you subclass Daemon. It will be called after the process has been
		daemonized by start() or restart().
		"""

###########################################
##           end daemon.py
###########################################

####
# Usage :
# ## To send just the latency information to Graphite
# python citrusleaf_graphite.py -l 'latency:back=70;duration=60' --start -g s1 -p 2023
# ## To send just 1 namespace stats to Graphite, for multiple namespaces, start accordingly
# python citrusleaf_graphite.py -n --start -g s1 -p 2023
# ## To send just the statistics information to Graphite
# python citrusleaf_graphite.py --start -g s1 -p 2023
# ## To send sets info to Graphite
# python citrusleaf_graphite.py -s --start -g s1 -p 2023
# ## To send XDR statistics to Graphite
# python citrusleaf_graphite.py -x --start -g s1 -p 2023
# ## To Stop the Daemon
#  python citrusleaf_graphite.py --stop
####

parser = argparse.ArgumentParser()

parser.add_argument("-U"
					, "--user"
					, help="user name")

parser.add_argument("-P"
					, "--password"
					, nargs="?"
					, const="prompt"
					, help="password")

parser.add_argument("--stop"
					, action="store_true"
					, dest="stop"
					, help="Stop the Daemon")

parser.add_argument("--start"
					, action="store_true"
					, dest="start"
					, help="Start the Daemon")

parser.add_argument("--restart"
					, action="store_true"
					, dest="restart"
					, help="Restart the Daemon")

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
					, action="store_true"
					, dest="xdr"
					, help="Gather XDR statistics")

parser.add_argument("-g"
					, "--graphite"
					, dest="graphite_server"
					, required=True
					, help="REQUIRED: IP for Graphite server")

parser.add_argument("-p"
					, "--graphite-port"
					, dest="graphite_port"
					, required=True
					, help="REQUIRED: PORT for Graphite server")

parser.add_argument("--prefix"
					, dest="graphite_prefix"
					, default='instances.citrusleaf.'
                                        , help="Prefix used when sending metrics to Graphite server (default: %(default)s)")

parser.add_argument("-i"
					, "--info-port"
					, dest="info_port"
					, default=3000
					, help="PORT for Aerospike server (default: %(default)s)")

parser.add_argument("-r"
					, "--xdr-port"
					, dest="xdr_port"
					, default=3004
					, help="PORT for XDR server(default: %(default)s)")

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

parser.add_argument("-d"
					, "--sindex"
					, action="store_true"
					, dest="sindex"
					, help="Gather sindex based statistics")

args = parser.parse_args()

try:
	import citrusleaf
except:
	raise Exception, "unable to load Citrusleaf/Aerospike library"
	sys.exit(-1)

user = None
password = None

if args.user != None:
	user = args.User
	if args.password == "prompt":
		args.password = getpass.getpass("Enter Password:")
	password = citrusleaf.hashpassword(args.password)

# Configurable parameters
LOGFILE = args.log_file

if not args.stop:
	if args.graphite_server:
		GRAPHITE_SERVER = args.graphite_server
	else:
		parser.print_help()
		sys.exit(2)

	if args.graphite_port:
		GRAPHITE_PORT = int(args.graphite_port)
	else:
		parser.print_help()
		sys.exit(2)

CITRUSLEAF_SERVER = args.base_node
CITRUSLEAF_PORT = args.info_port
CITRUSLEAF_XDR_PORT = args.xdr_port
CITRUSLEAF_SERVER_ID = socket.gethostname()
GRAPHITE_PATH_PREFIX = args.graphite_prefix + CITRUSLEAF_SERVER_ID
INTERVAL = 30

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

	def run(self):
		s = self.connect()
		print "Aerospike-Graphite connector started: ", time.asctime(time.localtime())

		while True:
			msg = []
			now = int(time.time())
			r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'statistics', user, password)
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

			if args.sets:
				r = -1
				try:
					r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'sets', user, password)
				except:
					pass
				if (-1 != r):
					lines = []
					for string in r.split(';'):
						if len(string) == 0:
							continue
						setList = string.split(':')
						namespace = setList[0]
						sets = setList[1]
						for set_tuple in setList[2:]:
							key, value = set_tuple.split('=')
							lines.append("%s.sets.%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, namespace, sets, key, value, now))
					msg.extend(lines)

			if args.latency:
				r = -1
				if args.latency.startswith('latency:'):
					try:
						r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, args.latency, user, password)
					except:
						pass
				else:
					try:
						r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'latency:', user, password)
					except:
						pass

				if (-1 != r) and not (r.startswith('error')):
					lines = []
					latency_type = ""
					header = []
					for string in r.split(';'):
						if len(string) == 0:
							continue
						if len(latency_type) == 0:
							# Base case
							latency_type, rest = string.split(':', 1)
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

			if args.namespace:
				r = -1
				try:
					r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'namespaces', user, password)
				except:
					pass

				if (-1 != r):
					namespaces = filter(None, r.split(';'))
					if len(namespaces) > 0:
						for namespace in namespaces:
							r = -1
							try:
								r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'namespace/' + namespace, user, password)
							except:
								pass
							if (-1 != r):
								lines = []
								for string in r.split(';'):
									name, value = string.split('=')
									value = value.replace('false', "0")
									value = value.replace('true', "1")
									lines.append(GRAPHITE_PATH_PREFIX + "." + namespace + ".%s %s %s" % (name, value, now))
							msg.extend(lines)

			if args.xdr:
				r = -1
				try:
					r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_XDR_PORT, 'statistics', user, password)
				except:
					pass
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
						lines.append("%s.xdr.%s %s %s" % (GRAPHITE_PATH_PREFIX, name, value, now))
					msg.extend(lines)

##	Logic to export SIndex Stats to Graphite
##	Since Graphite understands numbers we have used substitutes as below
##	sync_state --
##		synced = 1 & need_sync = 0
##	state --
##		RW = 1 & WO = 0

			if args.sindex:
				r = -1
				try:
					r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'sindex', user, password)
				except:
					pass
				if (-1 != r):
					indexes = filter(None, r)
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
									r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER, CITRUSLEAF_PORT, 'sindex/' + index["ns"] + '/' + index["indexname"], user, password)
								except:
									pass
								if (-1 != r):
									for string in r.split(';'):
										name, value = string.split('=')
										value = value.replace('false', "0")
										value = value.replace('true', "1")
										lines.append("%s.sindexes.%s.%s.%s %s %s" % (GRAPHITE_PATH_PREFIX, index["ns"], index["indexname"], name, value, now))
						msg.extend(lines)

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
				nmsg += line + '\n'
			try:
				s.sendall(nmsg)
			except:
				#Once the connection is broken, we need to reconnect
				print "ERROR: Unable to send to graphite server, retrying connection.."
				sys.stdout.flush()
				s.close()
				s = self.connect()

			time.sleep(INTERVAL)

if __name__ == "__main__":
	#TODO: move this to config param
	daemon = clGraphiteDaemon('/tmp/asgraphite.pid', LOGFILE)
	if args.start or args.stop or args.restart:
		if args.start:
			daemon.start()
		elif args.stop:
			daemon.stop()
		elif args.restart:
			daemon.restart()
		else:
			print "Unknown command"
			sys.exit(2)
		sys.exit(0)
	else:
		parser.print_help()
		sys.exit(2)
