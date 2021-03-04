#!/usr/bin/python

#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.topo import Topo
from mininet.link import  TCLink,Intf
from stratum import StratumBmv2Switch

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

        # All routers
        # gRPC port 50001
        r1 = self.addSwitch('r1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50002
        r2 = self.addSwitch('r2', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50003
        r3 = self.addSwitch('r3', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50004
        r4 = self.addSwitch('r4', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50005
        r5 = self.addSwitch('r5', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50006
        r6 = self.addSwitch('r6', cls=StratumBmv2Switch, cpuport=CPU_PORT)



        # Switch Links
        self.addLink(r1,r2)
        self.addLink(r1,r3)
        self.addLink(r1,r4)
        self.addLink(r2,r4)
        self.addLink(r3,r4)
        self.addLink(r3,r5)
        self.addLink(r4,r5)
        self.addLink(r4,r6)
        self.addLink(r5,r6)
        

        # IPv6 hosts attached to leaf 1
        h1 = self.addHost('h1', cls=IPv6Host, mac="00:00:00:00:00:1A",
                           ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h2 = self.addHost('h2', cls=IPv6Host, mac="00:00:00:00:00:2B",
                           ipv6='2001:2:1::b/64', ipv6_gw='2001:2:1::ff')
        h3 = self.addHost('h3', cls=IPv6Host, mac="00:00:00:00:00:3C",
                           ipv6='2001:3:1::c/64', ipv6_gw='2001:3:1::ff')
        h4 = self.addHost('h4', cls=IPv6Host, mac="00:00:00:00:00:4D",
                           ipv6='2001:4:1::d/64', ipv6_gw='2001:4:1::ff')
        h5 = self.addHost('h5', cls=IPv6Host, mac="00:00:00:00:00:5E",
                           ipv6='2001:5:1::e/64', ipv6_gw='2001:5:1::ff')
        h6 = self.addHost('h6', cls=IPv6Host, mac="00:00:00:00:00:6F",
                           ipv6='2001:6:1::f/64', ipv6_gw='2001:6:1::ff')                           
        self.addLink(h1, r1)  
        self.addLink(h2, r2)  
        self.addLink(h3, r3)  
        self.addLink(h4, r4)  
        self.addLink(h5, r5)  
        self.addLink(h6, r6)  




def main():
    net = Mininet(topo=TutorialTopo(), controller=None)
    collectorIntf = Intf( 'veth0', node=net.nameToNode["r6"] )
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
