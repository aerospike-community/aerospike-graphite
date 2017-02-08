# Aerospike Graphite
## Description
This repositiory provides the asgraphite connector to connect Aerospike with Graphite.

This script is included with the **aerospike-tools** package which is bundled
with the Aerospike server package and is installed into`/opt/aerospike/bin/asgraphite`.

# Install
```bash
sudo pip install -r requirements.txt
```

# Usage
```bash
$ python /opt/aerospike/bin/asgraphite --help
usage: asgraphite.py [-h] [-U USER] [-P [PASSWORD]] [--stop] [--start]
                     [--restart] [-v] [-n] [-s] [-l LATENCY] [-x DC [DC ...]]
                     [-g GRAPHITE_SERVER] [-p GRAPHITE_PORT]
                     [--interval GRAPHITE_INTERVAL] [--prefix GRAPHITE_PREFIX]
                     [-i INFO_PORT] [-b BASE_NODE] [-f LOG_FILE] [-si]
                     [-hi HIST_DUMP [HIST_DUMP ...]] [--tls_enable]
                     [--tls_encrypt_only] [--tls_keyfile TLS_KEYFILE]
                     [--tls_certfile TLS_CERTFILE] [--tls_cafile TLS_CAFILE]
                     [--tls_capath TLS_CAPATH] [--tls_protocols TLS_PROTOCOLS]
                     [--tls_blacklist TLS_BLACKLIST]
                     [--tls_ciphers TLS_CIPHERS] [--tls_crl] [--tls_crlall]
                     [--tls_name TLS_NAME]
Options:
  -h, --help            show this help message and exit
  -U USER, --user USER  user name
  -P [PASSWORD], --password [PASSWORD]
                        password
  --stop                Stop the Daemon
  --start               Start the Daemon
  --restart             Restart the Daemon
  -v, --verbose         Enable verbose logging
  -n, --namespace       Get all namespace statistics
  -s, --sets            Gather set based statistics
  -l LATENCY, --latency LATENCY
                        Enable latency statistics and specify query (ie.
                        latency:back=70;duration=60)
  -x DC [DC ...], --xdr DC [DC ...]
                        Gather XDR datacenter statistics
  -g GRAPHITE_SERVER, --graphite GRAPHITE_SERVER
                        REQUIRED: IP for Graphite server
  -p GRAPHITE_PORT, --graphite-port GRAPHITE_PORT
                        REQUIRED: PORT for Graphite server
  --interval GRAPHITE_INTERVAL
                        How often metrics are sent to graphite (seconds)
  --prefix GRAPHITE_PREFIX
                        Prefix used when sending metrics to Graphite server
                        (default: instances.aerospike.)
  -i INFO_PORT, --info-port INFO_PORT
                        PORT for Aerospike server (default: 3000)
  -b BASE_NODE, --base-node BASE_NODE
                        Base host for collecting stats (default: 127.0.0.1)
  -f LOG_FILE, --log-file LOG_FILE
                        Logfile for asgraphite (default:
                        /var/log/aerospike/asgraphite.log)
  -si, --sindex         Gather sindex based statistics
  -hi HIST_DUMP [HIST_DUMP ...], --hist-dump HIST_DUMP [HIST_DUMP ...]
                        Gather histogram data. Valid args are ttl and objsz
  --tls_enable          Enable TLS
  --tls_encrypt_only    TLS Encrypt Only
  --tls_keyfile TLS_KEYFILE
                        The private keyfile for your client TLS Cert
  --tls_certfile TLS_CERTFILE
                        The client TLS cert
  --tls_cafile TLS_CAFILE
                        The CA for the server's certificate
  --tls_capath TLS_CAPATH
                        The path to a directory containing CA certs and/or
                        CRLs
  --tls_protocols TLS_PROTOCOLS
                        The TLS protocol to use. Available choices: SSLv2,
                        SSLv3, TLSv1, TLSv1.1, TLSv1.2, all. An optional + or
                        - can be appended before the protocol to indicate
                        specific inclusion or exclusion.
  --tls_blacklist TLS_BLACKLIST
                        Blacklist including serial number of certs to revoke
  --tls_ciphers TLS_CIPHERS
                        Ciphers to include. See https://www.openssl.org/docs/m
                        an1.0.1/apps/ciphers.html for cipher list format
  --tls_crl             Checks SSL/TLS certs against vendor's Certificate
                        Revocation Lists for revoked certificates. CRLs are
                        found in path specified by --tls_capath. Checks the
                        leaf certificates only
  --tls_crlall          Check on all entries within the CRL chain
  --tls_name TLS_NAME   The expected name on the server side certificate
```

For example, to start <strong>asgraphite</strong> daemon, you might issue a command like this:

```bash
Usage :

#  To send just the (using defaults) latency information to Graphite
$ python /opt/aerospike/bin/asgraphite -l 'latency:' --start -g <graphite_host> -p <graphite_port>

#  To send namespace stats to Graphite
$ python /opt/aerospike/bin/asgraphite -n --start -g <graphite_host> -p <graphite_port>

#  To send the latency information of custom duration to Graphite.
#  This would go back 70 seconds and send latency, set and namespace data to the Graphite server for 60 seconds worth of data.
$ python /opt/aerospike/bin/asgraphite -n -l 'latency:back=70;duration=60' --start -g <graphite_host> -p <graphite_port>

#  To send just the statistics information to Graphite
$ python /opt/aerospike/bin/asgraphite --start -g <graphite_host> -p <graphite_port>

#  To send sets info to Graphite
$ python /opt/aerospike/bin/asgraphite -s --start -g <graphite_host> -p <graphite_port>

#  To send XDR statistics to Graphite
$ python /opt/aerospike/bin/asgraphite -x datacenter1 [dc2 dc3 ...] --start -g <graphite_host> -p <graphite_port>
or
$ python /opt/aerospike/bin/asgraphite -x datacenter1 [-x datacenter 2 -x datacenter3 ...] --start -g <graphite_host> -p <graphite_port>

#  To send SIndex statistics to Graphite
$ python /opt/aerospike/bin/asgraphite -si --start -g <graphite_host> -p <graphite_port>

# You can use multiple options in a single command
$ python /opt/aerospike/bin/asgraphite -si -l 'latency:' --start -g <graphite_host> -p <graphite_port>

#  To Stop the Daemon
$ python /opt/aerospike/bin/asgraphite --stop

#  To run with SSL/TLS encrypt only
$ python /opt/aerospike/bin/asgraphite -n --tls_enable --tls_encrypt_only true --start -g <graphite_host> -p <graphite_port>

#  To run with SSL/TLS authenticate server
$ python /opt/aerospike/bin/asgraphite -n --tls_enable --tls_cafile /path/to/CA/root.pem --tls_name <server name on cert> --start -g <graphite_host> -p <graphite_port>
```

Add the asgraphite monitoring commands to `/etc/rc.local` to automatically start
monitoring after a server restart.

## Dependencies
- python 2.6+
- python argparse, bcrypt (if using auth), pyOpenSSL (if using SSL/TLS)
