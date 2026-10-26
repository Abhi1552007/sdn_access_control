#!/usr/bin/env python3
"""
Builds the Mininet network, starts the auth server and protected service,
then either opens the Mininet CLI or runs the automatic test scenarios.

  sudo python3 topology.py          # interactive CLI
  sudo python3 topology.py --test   # run all test scenarios, then CLI

Topology (single switch s1, OpenFlow 1.3):
  h1 10.0.0.1  TCP auth server :5000  (also acts as SDN controller via ovs-ofctl)
  h2 10.0.0.2  client (alice, staff)
  h3 10.0.0.3  client (bob / guest / wrong passwords)
  h4 10.0.0.4  protected service :9000
  h5 10.0.0.5  blacklisted host
"""
import os
import sys
import time
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info

HERE = os.path.dirname(os.path.abspath(__file__))


class AuthTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13", failMode="secure")
        for i in range(1, 6):
            self.addLink(self.addHost(f"h{i}", ip=f"10.0.0.{i}/24"), s1)


def run(h, cmd):
    info(f"\n{h.name}$ {cmd}\n")
    out = h.cmd(f"cd {HERE} && {cmd}")
    info(out)
    return out


def scenarios(net):
    h1, h2, h3, h4, h5 = (net.get(f"h{i}") for i in range(1, 6))
    banner = lambda t: info(f"\n{'=' * 60}\n {t}\n{'=' * 60}\n")

    banner("1. Unauthenticated host cannot reach the protected service")
    run(h2, "python3 auth_client.py access")

    banner("2. Wrong password is rejected, access stays blocked")
    run(h3, "python3 auth_client.py login bob wrongpass --hold 0")

    banner("3. Valid login grants access; logout revokes it")
    run(h2, "python3 auth_client.py login alice alice123 --hold 3")

    banner("4. Guest role is authenticated but policy denies the service")
    run(h3, "python3 auth_client.py login guest guest123 --hold 0")

    banner("5. Blacklisted host is denied even with valid credentials")
    run(h5, "python3 auth_client.py login alice alice123 --hold 0")

    banner("6. Concurrent users: alice (h2) and bob (h3) at the same time")
    h2.cmd(f"cd {HERE} && python3 -u auth_client.py login alice alice123 --hold 8 > /tmp/c2.txt 2>&1 &")
    h3.cmd(f"cd {HERE} && python3 -u auth_client.py login bob bob123 --hold 8 > /tmp/c3.txt 2>&1 &")
    time.sleep(3)
    run(h2, "python3 auth_client.py status")
    info("\nFlow table while both are logged in:\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))
    time.sleep(13)
    info("\n--- h2 output ---\n" + h2.cmd("cat /tmp/c2.txt"))
    info("\n--- h3 output ---\n" + h3.cmd("cat /tmp/c3.txt"))

    banner("7. Lockout after repeated failures")
    for _ in range(3):
        run(h3, "python3 auth_client.py login bob nope --hold 0")
    run(h3, "python3 auth_client.py login bob bob123 --hold 0")

    banner("Done. Logs: logs/auth.log and logs/access.log")
    info("Session timeout demo (takes ~70s):\n"
         "  mininet> h2 cd " + HERE + " && python3 auth_client.py login alice alice123 --no-heartbeat --hold 70\n")


def main():
    setLogLevel("info")
    os.system("mn -c > /dev/null 2>&1")
    net = Mininet(topo=AuthTopo(), switch=OVSSwitch, controller=None, autoSetMacs=True)
    net.start()

    h1, h4 = net.get("h1"), net.get("h4")
    h1.cmd(f"cd {HERE} && python3 auth_server.py > logs/auth_server.out 2>&1 &")
    h4.cmd(f"cd {HERE} && python3 protected_service.py > logs/service.out 2>&1 &")
    time.sleep(2)
    info("*** Auth server on h1:5000, protected service on h4:9000\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))

    if "--test" in sys.argv:
        scenarios(net)

    CLI(net)
    h1.cmd("pkill -f auth_server.py")
    h4.cmd("pkill -f protected_service.py")
    net.stop()


if __name__ == "__main__":
    main()
