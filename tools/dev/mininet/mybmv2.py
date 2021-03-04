# coding=utf-8
"""
Copyright 2019-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import multiprocessing
import os
import argparse

import json
import random
import re
import socket
import sys
import threading
import time
import urllib2
from contextlib import closing
from mininet.log import info, warn, debug
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import Switch, Host

SIMPLE_SWITCH_GRPC = 'simple_switch_grpc'
PKT_BYTES_TO_DUMP = 80
VALGRIND_PREFIX = 'valgrind --leak-check=yes'
SWITCH_START_TIMEOUT = 10  # seconds
BMV2_LOG_LINES = 5
BMV2_DEFAULT_DEVICE_ID = 1
DEFAULT_PIPECONF = "org.onosproject.pipelines.p4-tutorial-pipeconf"

# Stratum paths relative to stratum repo root
STRATUM_BMV2 = 'stratum_bmv2'
STRATUM_BINARY = '/bazel-bin/stratum/hal/bin/bmv2/' + STRATUM_BMV2
STRATUM_INIT_PIPELINE = '/stratum/hal/bin/bmv2/dummy.json'


def getEnvOrDefault(env, default):
    try:
        return os.environ[env]
    except KeyError:
        return default


ONOS_WEB_USER = getEnvOrDefault('ONOS_WEB_USER', 'onos')
ONOS_WEB_PASS = getEnvOrDefault('ONOS_WEB_PASS', 'rocks')


def getStratumRoot():
    if 'STRATUM_ROOT' not in os.environ:
        raise Exception("Env variable STRATUM_ROOT not set")
    return os.environ['STRATUM_ROOT']


def parseBoolean(value):
    if value in ['1', 1, 'true', 'True']:
        return True
    else:
        return False


def pickUnusedPort():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    addr, port = s.getsockname()
    s.close()
    return port


def writeToFile(path, value):
    with open(path, "w") as f:
        f.write(str(value))


def watchDog(sw):
    try:
        writeToFile(sw.keepaliveFile,
                    "Remove this file to terminate %s" % sw.name)
        while True:
            if ONOSBmv2Switch.mininet_exception == 1 \
                    or not os.path.isfile(sw.keepaliveFile):
                sw.killBmv2(log=False)
                return
            if sw.stopped:
                return
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                port = sw.grpcPortInternal if sw.grpcPortInternal else sw.grpcPort
                if s.connect_ex(('localhost', port)) == 0:
                    time.sleep(1)
                else:
                    warn("\n*** WARN: switch %s died ☠️ \n" % sw.name)
                    sw.printBmv2Log()
                    print ("-" * 80) + "\n"
                    return
    except Exception as e:
        warn("*** ERROR: " + e.message)
        sw.killBmv2(log=True)


class ONOSHost(Host):
    def __init__(self, name, inNamespace=True, **params):
        Host.__init__(self, name, inNamespace=inNamespace, **params)

    def config(self, **params):
        r = super(Host, self).config(**params)
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" \
                  % (self.defaultIntf(), off)
            self.cmd(cmd)
        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        return r


class ONOSBmv2Switch(Switch):
    """BMv2 software switch with gRPC server"""
    # Shared value used to notify to all instances of this class that a Mininet
    # exception occurred. Mininet exception handling doesn't call the stop()
    # method, so the mn process would hang after clean-up since Bmv2 would still
    # be running.
    mininet_exception = multiprocessing.Value('i', 0)

    def __init__(self, name, json=None, debugger=False, loglevel="warn",
                 elogger=False, grpcport=None, cpuport=255, notifications=False,
                 thriftport=None, netcfg=True, dryrun=False,
                 pipeconf=DEFAULT_PIPECONF, pktdump=False, valgrind=False,
                 gnmi=False, portcfg=True, onosdevid=None, stratum=False,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.grpcPort = grpcport
        self.grpcPortInternal = None  # Needed for Stratum (local_hercules_url)
        self.thriftPort = thriftport
        self.cpuPort = cpuport
        self.json = json
        self.useStratum = parseBoolean(stratum)
        self.debugger = parseBoolean(debugger)
        self.notifications = parseBoolean(notifications)
        self.loglevel = loglevel
        # Important: Mininet removes all /tmp/*.log files in case of exceptions.
        # We want to be able to see the bmv2 log if anything goes wrong, hence
        # avoid the .log extension.
        self.logfile = '/tmp/bmv2-%s-log' % self.name
        self.elogger = parseBoolean(elogger)
        self.pktdump = parseBoolean(pktdump)
        self.netcfg = parseBoolean(netcfg)
        self.dryrun = parseBoolean(dryrun)
        self.valgrind = parseBoolean(valgrind)
        self.netcfgfile = '/tmp/bmv2-%s-netcfg.json' % self.name
        self.chassisConfigFile = '/tmp/bmv2-%s-chassis-config.txt' % self.name
        self.pipeconfId = pipeconf
        self.injectPorts = parseBoolean(portcfg)
        self.withGnmi = parseBoolean(gnmi)
        self.longitude = kwargs['longitude'] if 'longitude' in kwargs else None
        self.latitude = kwargs['latitude'] if 'latitude' in kwargs else None
        if onosdevid is not None and len(onosdevid) > 0:
            self.onosDeviceId = onosdevid
        else:
            self.onosDeviceId = "device:bmv2:%s" % self.name
        self.p4DeviceId = BMV2_DEFAULT_DEVICE_ID
        self.logfd = None
        self.bmv2popen = None
        self.stopped = True
        # In case of exceptions, mininet removes *.out files from /tmp. We use
        # this as a signal to terminate the switch instance (if active).
        self.keepaliveFile = '/tmp/bmv2-%s-watchdog.out' % self.name
        self.targetName = STRATUM_BMV2 if self.useStratum else SIMPLE_SWITCH_GRPC

        # Remove files from previous executions
        self.cleanupTmpFiles()

    def getSourceIp(self, dstIP):
        """
        Queries the Linux routing table to get the source IP that can talk with
        dstIP, and vice versa.
        """
        ipRouteOut = self.cmd('ip route get %s' % dstIP)
        r = re.search(r"src (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ipRouteOut)
        return r.group(1) if r else None

    def getDeviceConfig(self, srcIP):

        basicCfg = {
            "managementAddress": "grpc://%s:%d?device_id=%d" % (
                srcIP, self.grpcPort, self.p4DeviceId),
            "driver": "stratum-bmv2" if self.useStratum else "bmv2",
            "pipeconf": self.pipeconfId
        }

        if self.longitude and self.latitude:
            basicCfg["longitude"] = self.longitude
            basicCfg["latitude"] = self.latitude

        cfgData = {
            "basic": basicCfg
        }

        if not self.useStratum and self.injectPorts:
            portData = {}
            portId = 1
            for intfName in self.intfNames():
                if intfName == 'lo':
                    continue
                portData[str(portId)] = {
                    "number": portId,
                    "name": intfName,
                    "enabled": True,
                    "removed": False,
                    "type": "copper",
                    "speed": 10000
                }
                portId += 1

            cfgData['ports'] = portData

        return cfgData

    def chassisConfig(self):
        config = """description: "BMv2 simple_switch {name}"
chassis {{
  platform: PLT_P4_SOFT_SWITCH
  name: "{name}"
}}
nodes {{
  id: {nodeId}
  name: "{name} node {nodeId}"
  slot: 1
  index: 1
}}\n""".format(name=self.name, nodeId=self.p4DeviceId)

        intfNumber = 1
        for intfName in self.intfNames():
            if intfName == 'lo':
                continue
            config = config + """singleton_ports {{
  id: {intfNumber}
  name: "{intfName}"
  slot: 1
  port: {intfNumber}
  channel: 1
  speed_bps: 10000000000
  config_params {{
    admin_state: ADMIN_STATE_ENABLED
  }}
  node: {nodeId}
}}\n""".format(intfName=intfName, intfNumber=intfNumber,
              nodeId=self.p4DeviceId)
            intfNumber += 1

        return config

    def doOnosNetcfg(self, controllerIP):
        """
        Notifies ONOS about the new device via Netcfg.
        """
        srcIP = self.getSourceIp(controllerIP)
        if not srcIP:
            warn("*** WARN: unable to get switch IP address, won't do netcfg\n")
            return

        cfgData = {
            "devices": {
                self.onosDeviceId: self.getDeviceConfig(srcIP)
            }
        }
        with open(self.netcfgfile, 'w') as fp:
            json.dump(cfgData, fp, indent=4)

        if not self.netcfg:
            # Do not push config to ONOS.
            return

        # Build netcfg URL
        url = 'http://%s:8181/onos/v1/network/configuration/' % controllerIP
        # Instantiate password manager for HTTP auth
        pm = urllib2.HTTPPasswordMgrWithDefaultRealm()
        pm.add_password(None, url, ONOS_WEB_USER, ONOS_WEB_PASS)
        urllib2.install_opener(urllib2.build_opener(
            urllib2.HTTPBasicAuthHandler(pm)))
        # Push config data to controller
        req = urllib2.Request(url, json.dumps(cfgData),
                              {'Content-Type': 'application/json'})
        try:
            f = urllib2.urlopen(req)
            print f.read()
            f.close()
        except urllib2.URLError as e:
            warn("*** WARN: unable to push config to ONOS (%s)\n" % e.reason)

    def start(self, controllers):

        if not self.stopped:
            warn("*** %s is already running!\n" % self.name)
            return

        # Remove files from previous executions (if we are restarting)
        self.cleanupTmpFiles()

        if self.grpcPort is None:
            self.grpcPort = pickUnusedPort()
        writeToFile("/tmp/bmv2-%s-grpc-port" % self.name, self.grpcPort)

        if self.useStratum:
            config_dir = "/tmp/bmv2-%s-stratum" % self.name
            os.mkdir(config_dir)
            with open(self.chassisConfigFile, 'w') as fp:
                fp.write(self.chassisConfig())
            if self.grpcPortInternal is None:
                self.grpcPortInternal = pickUnusedPort()
            cmdString = self.getStratumCmdString(config_dir)
        else:
            if self.thriftPort is None:
                self.thriftPort = pickUnusedPort()
            writeToFile("/tmp/bmv2-%s-thrift-port" % self.name, self.thriftPort)
            cmdString = self.getBmv2CmdString()

        if self.dryrun:
            info("\n*** DRY RUN (not executing %s)\n" % self.targetName)

        debug("\n%s\n" % cmdString)

        try:
            if not self.dryrun:
                # Start the switch
                self.stopped = False
                self.logfd = open(self.logfile, "w")
                self.logfd.write(cmdString + "\n\n" + "-" * 80 + "\n\n")
                self.logfd.flush()
                self.bmv2popen = self.popen(cmdString,
                                            stdout=self.logfd,
                                            stderr=self.logfd)
                self.waitBmv2Start()
                # We want to be notified if BMv2/Stratum dies...
                threading.Thread(target=watchDog, args=[self]).start()

            self.doOnosNetcfg(self.controllerIp(controllers))
        except Exception:
            ONOSBmv2Switch.mininet_exception = 1
            self.killBmv2()
            self.printBmv2Log()
            raise

    def getBmv2CmdString(self):
        bmv2Args = [SIMPLE_SWITCH_GRPC] + self.bmv2Args()
        if self.valgrind:
            bmv2Args = VALGRIND_PREFIX.split() + bmv2Args
        return " ".join(bmv2Args)

    def getStratumCmdString(self, config_dir):
        stratumRoot = getStratumRoot()
        args = [
            stratumRoot + STRATUM_BINARY,
            '-device_id=%d' % self.p4DeviceId,
            '-chassis_config_file=%s' % self.chassisConfigFile,
            '-forwarding_pipeline_configs_file=%s/pipeline_config.txt' % config_dir,
            '-persistent_config_dir=' + config_dir,
            '-initial_pipeline=' + stratumRoot + STRATUM_INIT_PIPELINE,
            '-cpu_port=%s' % self.cpuPort,
            '-external_hercules_urls=0.0.0.0:%d' % self.grpcPort,
            '-local_hercules_url=localhost:%d' % self.grpcPortInternal,
            '-max_num_controllers_per_node=10',
            '-logtosyslog=false',
            '-logtostderr=true'
        ]
        return " ".join(args)

    def bmv2Args(self):
        args = ['--device-id %s' % str(self.p4DeviceId)]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.append('-i %d@%s' % (port, intf.name))
        args.append('--thrift-port %s' % self.thriftPort)
        if self.notifications:
            ntfaddr = 'ipc:///tmp/bmv2-%s-notifications.ipc' % self.name
            args.append('--notifications-addr %s' % ntfaddr)
        if self.elogger:
            nanologaddr = 'ipc:///tmp/bmv2-%s-nanolog.ipc' % self.name
            args.append('--nanolog %s' % nanologaddr)
        if self.debugger:
            dbgaddr = 'ipc:///tmp/bmv2-%s-debug.ipc' % self.name
            args.append('--debugger-addr %s' % dbgaddr)
        args.append('--log-console')
        if self.pktdump:
            args.append('--pcap --dump-packet-data %s' % PKT_BYTES_TO_DUMP)
        args.append('-L%s' % self.loglevel)
        if not self.json:
            args.append('--no-p4')
        else:
            args.append(self.json)
        # gRPC target-specific options
        args.append('--')
        args.append('--cpu-port %s' % self.cpuPort)
        args.append('--grpc-server-addr 0.0.0.0:%s' % self.grpcPort)
        return args

    def waitBmv2Start(self):
        # Wait for switch to open gRPC port, before sending ONOS the netcfg.
        # Include time-out just in case something hangs.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        endtime = time.time() + SWITCH_START_TIMEOUT
        while True:
            port = self.grpcPortInternal if self.grpcPortInternal else self.grpcPort
            result = sock.connect_ex(('localhost', port))
            if result == 0:
                # No new line
                sys.stdout.write("⚡️ %s @ %d" % (self.targetName, self.bmv2popen.pid))
                sys.stdout.flush()
                # The port is open. Let's go! (Close socket first)
                sock.close()
                break
            # Port is not open yet. If there is time, we wait a bit.
            if endtime > time.time():
                sys.stdout.write('.')
                sys.stdout.flush()
                time.sleep(0.05)
            else:
                # Time's up.
                raise Exception("Switch did not start before timeout")

    def printBmv2Log(self):
        if os.path.isfile(self.logfile):
            print "-" * 80
            print "%s log (from %s):" % (self.name, self.logfile)
            with open(self.logfile, 'r') as f:
                lines = f.readlines()
                if len(lines) > BMV2_LOG_LINES:
                    print "..."
                for line in lines[-BMV2_LOG_LINES:]:
                    print line.rstrip()

    @staticmethod
    def controllerIp(controllers):
        try:
            # onos.py
            clist = controllers[0].nodes()
        except AttributeError:
            clist = controllers
        assert len(clist) > 0
        return random.choice(clist).IP()

    def killBmv2(self, log=False):
        self.stopped = True
        if self.bmv2popen is not None:
            self.bmv2popen.terminate()
            self.bmv2popen.wait()
            self.bmv2popen = None
        if self.logfd is not None:
            if log:
                self.logfd.write("*** PROCESS TERMINATED BY MININET ***\n")
            self.logfd.close()
            self.logfd = None

    def cleanupTmpFiles(self):
        self.cmd("rm -rf /tmp/bmv2-%s-*" % self.name)

    def stop(self, deleteIntfs=True):
        """Terminate switch."""
        self.killBmv2(log=True)
        Switch.stop(self, deleteIntfs)


class ONOSStratumSwitch(ONOSBmv2Switch):
    def __init__(self, name, **kwargs):
        kwargs["stratum"] = True
        super(ONOSStratumSwitch, self).__init__(name, **kwargs)

CPU_PORT = 255


class IPv6Host(Host):
    """Host that can be configured with an IPv6 gateway (default route).
    """

    def config(self, ipv6, ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr add %s dev %s' % (ipv6, self.defaultIntf()))
        if ipv6_gw:
            self.cmd('ip -6 route add default via %s' % ipv6_gw)
        # Disable offload
        for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (self.defaultIntf(), attr)
            self.cmd(cmd)

        def updateIP():
            return ipv6.split('/')[0]

        self.defaultIntf().updateIP = updateIP

    def terminate(self):
        super(IPv6Host, self).terminate()


class TutorialTopo(Topo):
    """2x2 fabric topology with IPv6 hosts"""

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # Leaves
        # gRPC port 50001
        leaf1 = self.addSwitch('leaf1', cls=ONOSStratumSwitch, cpuport=CPU_PORT)
        # gRPC port 50002
        leaf2 = self.addSwitch('leaf2', cls=ONOSStratumSwitch, cpuport=CPU_PORT)

        # Spines
        # gRPC port 50003
        spine1 = self.addSwitch('spine1', cls=ONOSStratumSwitch, cpuport=CPU_PORT)
        # gRPC port 50004
        spine2 = self.addSwitch('spine2', cls=ONOSStratumSwitch, cpuport=CPU_PORT)

        # Switch Links
        self.addLink(spine1, leaf1)
        self.addLink(spine1, leaf2)
        self.addLink(spine2, leaf1)
        self.addLink(spine2, leaf2)

        # IPv6 hosts attached to leaf 1
        h1a = self.addHost('h1a', cls=IPv6Host, mac="00:00:00:00:00:1A",
                           ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h1b = self.addHost('h1b', cls=IPv6Host, mac="00:00:00:00:00:1B",
                           ipv6='2001:1:1::b/64', ipv6_gw='2001:1:1::ff')
        h1c = self.addHost('h1c', cls=IPv6Host, mac="00:00:00:00:00:1C",
                           ipv6='2001:1:1::c/64', ipv6_gw='2001:1:1::ff')
        h2 = self.addHost('h2', cls=IPv6Host, mac="00:00:00:00:00:20",
                          ipv6='2001:1:2::1/64', ipv6_gw='2001:1:2::ff')
        self.addLink(h1a, leaf1)  # port 3
        self.addLink(h1b, leaf1)  # port 4
        self.addLink(h1c, leaf1)  # port 5
        self.addLink(h2, leaf1)  # port 6

        # IPv6 hosts attached to leaf 2
        h3 = self.addHost('h3', cls=IPv6Host, mac="00:00:00:00:00:30",
                          ipv6='2001:2:3::1/64', ipv6_gw='2001:2:3::ff')
        h4 = self.addHost('h4', cls=IPv6Host, mac="00:00:00:00:00:40",
                          ipv6='2001:2:4::1/64', ipv6_gw='2001:2:4::ff')
        self.addLink(h3, leaf2)  # port 3
        self.addLink(h4, leaf2)  # port 4

# Exports for bin/mn
switches = {
    'onosbmv2': ONOSBmv2Switch,
    'stratum': ONOSStratumSwitch,
}
hosts = {'onoshost': ONOSHost}

def main():
    #net = Mininet(topo=TutorialTopo(), controller=c0)
    net = Mininet(topo=TutorialTopo(),controller=None)
    net.addController(name='c0',controller=RemoteController,ip='127.0.0.1')
    net.start()
    CLI(net)
    net.stop()
    print '#' * 80
    print 'ATTENTION: Mininet was stopped! Perhaps accidentally?'
    print 'No worries, it will restart automatically in a few seconds...'
    print 'To access again the Mininet CLI, use `make mn-cli`'
    print 'To detach from the CLI (without stopping), press Ctrl-D'
    print 'To permanently quit Mininet, use `make stop`'
    print '#' * 80


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
       description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv6 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()
