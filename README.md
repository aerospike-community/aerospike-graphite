# Aerospike Graphite
## Description
This repositiory provides the asgraphite connector to connect Aerospike with Graphite.

This script is included with the **aerospike-tools** package with is bundled
with the server package and is installed into`/opt/aerospike/bin/asgraphite`.

# Usage
```bash
$ python /opt/aerospike/bin/asgraphite --help
usage: asgraphite [options]
Options:
  -h, --help            show this help message and exit
  --stop                Stop the Daemon
  --start               Start the Daemon
  --restart             Restart the Daemon
  -n, --namespace       Get all namespace statistics
  -s, --sets            Gather set based statistics
  -l LATENCY, --latency=LATENCY
                        Enable latency statistics and specify query (IE.
                        latency:back=70;duration=60)
  -x DC [DC ...], --xdr DC [DC ...]
                        Gather XDR datacenter statistics (Enterprise 3.7.4+)
  -g GRAPHITE_SERVER, --graphite=GRAPHITE_SERVER
                        REQUIRED: IP for Graphite server
  -p GRAPHITE_PORT, --graphite-port=GRAPHITE_PORT
                        REQUIRED: PORT for Graphite server
  --prefix GRAPHITE_PREFIX
                        Prefix used when sending metrics to Graphite server
                        (default: instances.aerospike.)
  -i INFO_PORT, --info-port=INFO_PORT
                        PORT for Aerospike server [default: 3000]
  -b BASE_NODE, --base-node=BASE_NODE
                        Base host for collecting stats [default: 127.0.0.1]
  -f LOG_FILE, --log-file=LOG_FILE
                        Log file for asgraphite [default:
                        /var/log/aerospike/asgraphite.log]
  -d, --sindex          Gather sindex based statistics, default disabled (version 3.1.6+)
  -v, --verbose			Enable additional output in the logs
```

For example, to start <strong>asgraphite</strong> daemon, you might issue a command like this:

```bash
Usage :

#  To send just the (using defaults) latency information to Graphite
$ python /opt/aerospike/bin/asgraphite -l 'latency:' --start -g <graphite_host> -p <graphite_port>

#  To send the latency information of custom duration to Graphite.
#  This would go back 70 seconds and send latency, set and namespace data to the Graphite server for 60 seconds worth of data.
$ python /opt/aerospike/bin/asgraphite -l 'latency:back=70;duration=60' --start -g <graphite_host> -p <graphite_port>

#  To send namespace stats to Graphite
$ python /opt/aerospike/bin/asgraphite -n --start -g <graphite_host> -p <graphite_port>

#  To send just the statistics information to Graphite
$ python /opt/aerospike/bin/asgraphite --start -g <graphite_host> -p <graphite_port>

#  To send sets info to Graphite
$ python /opt/aerospike/bin/asgraphite -s --start -g <graphite_host> -p <graphite_port>

#  To send XDR statistics to Graphite
$ python /opt/aerospike/bin/asgraphite -x datacenter1 [dc2 dc3 ...] --start -g <graphite_host> -p <graphite_port>
or
$ python /opt/aerospike/bin/asgraphite -x datacenter1 [-x datacenter 2 -x datacenter3 ...] --start -g <graphite_host> -p <graphite_port>

#  To send SIndex statistics to Graphite
$ python /opt/aerospike/bin/asgraphite -d --start -g <graphite_host> -p <graphite_port>

# You can use multiple options in a single command
$ python /opt/aerospike/bin/asgraphite -x -d -l 'latency:' --start -g <graphite_host> -p <graphite_port>

#  To Stop the Daemon
$ python /opt/aerospike/bin/asgraphite --stop
```

Add the asgraphite monitoring commands to `/etc/rc.local` to automatically start
monitoring after a server restart.

## Dependencies
- python 2.6+
- argparse
- aerospike
