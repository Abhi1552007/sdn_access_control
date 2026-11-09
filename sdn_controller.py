"""
SDN controller module (D2).

Controls every Open vSwitch switch in the Mininet network with OpenFlow 1.3
rules pushed through ovs-ofctl. The network layout (which host sits on which
switch port, and how switches are linked) is read from run/topology.json,
which topology.py writes when the network starts.

Rule priorities (highest wins):
  400  drop everything from an auto-blocked host (hard_timeout = block time)
  310  let a blacklisted host still reach the auth server (so it can be told "denied")
  300  drop everything from a blacklisted host
  200  per-session grant: client -> service port, on every switch on the path
         - on the client's edge switch the rule also matches in_port + MAC (anti-spoofing)
         - rate-limited roles go through an OpenFlow meter on the edge switch
         - hard_timeout: the rule dies on its own if the auth server stops refreshing it
  100  default deny: drop all IP traffic to protected servers
    0  normal L2 forwarding
"""
import json
import logging
import os
import subprocess
import threading
from collections import deque

log = logging.getLogger("sdn")

AUTH_PORT = 5000
COOKIE_MASK = "/-1"


class SDNController:
    def __init__(self, topo_path, protected_ips, auth_ip):
        with open(topo_path) as f:
            topo = json.load(f)
        self.hosts = topo["hosts"]                      # name -> {ip, mac, switch, port}
        self.switches = topo["switches"]                # list of switch names
        self.adj = {s: {} for s in self.switches}       # switch -> {neighbour switch: local port}
        for link in topo["links"]:
            self.adj[link["a"]][link["b"]] = link["a_port"]
            self.adj[link["b"]][link["a"]] = link["b_port"]
        self.by_ip = {h["ip"]: dict(h, name=n) for n, h in self.hosts.items()}
        self.protected_ips = sorted(protected_ips)
        self.auth_ip = auth_ip
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- helpers
    def _ofctl(self, *args):
        cmd = ["ovs-ofctl", "-O", "OpenFlow13"] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log.error("ovs-ofctl failed: %s | %s", " ".join(cmd), r.stderr.strip())
        return r

    def host(self, ip):
        return self.by_ip.get(ip)

    def path(self, src_ip, dst_ip):
        """Switches a packet crosses from src host to dst host (BFS over the switch graph)."""
        a, b = self.by_ip[src_ip]["switch"], self.by_ip[dst_ip]["switch"]
        prev, q = {a: None}, deque([a])
        while q:
            s = q.popleft()
            if s == b:
                break
            for n in self.adj[s]:
                if n not in prev:
                    prev[n] = s
                    q.append(n)
        out, s = [], b
        while s is not None:
            out.append(s)
            s = prev[s]
        return out[::-1]

    # ----------------------------------------------------------- base policy
    def install_base_policy(self, denied_hosts=()):
        with self.lock:
            for sw in self.switches:
                self._ofctl("del-flows", sw)
                self._ofctl("del-meters", sw)
                self._ofctl("add-flow", sw, "priority=0,actions=normal")
                for ip in self.protected_ips:
                    self._ofctl("add-flow", sw, f"priority=100,ip,nw_dst={ip},actions=drop")
                for h in denied_hosts:
                    self._ofctl("add-flow", sw, f"priority=300,ip,nw_src={h},actions=drop")
                    self._ofctl("add-flow", sw, f"priority=310,tcp,nw_src={h},nw_dst={self.auth_ip},"
                                                f"tp_dst={AUTH_PORT},actions=normal")
        log.info("Base policy on %s (protected=%s, denied=%s)",
                 self.switches, self.protected_ips, list(denied_hosts))

    # --------------------------------------------------------- grant / revoke
    @staticmethod
    def meter_id(cookie):
        return (cookie & 0xFFFF) + 1

    def _grant_flows(self, cookie, src_ip, dst_ip, ports, rate_kbps, hard_timeout):
        h = self.by_ip[src_ip]
        flows = []
        for sw in self.path(src_ip, dst_ip):
            for port in ports:
                match = f"tcp,nw_src={src_ip},nw_dst={dst_ip},tp_dst={port}"
                action = "normal"
                if sw == h["switch"]:
                    # edge switch: bind the grant to the client's physical port and MAC
                    match = f"in_port={h['port']},dl_src={h['mac']}," + match
                    if rate_kbps:
                        action = f"meter:{self.meter_id(cookie)},normal"
                flows.append((sw, f"cookie={cookie:#x},priority=200,hard_timeout={hard_timeout},"
                                  f"{match},actions={action}"))
        return flows

    def grant(self, cookie, src_ip, dst_ip, ports, rate_kbps=0, hard_timeout=70):
        edge = self.by_ip[src_ip]["switch"]
        with self.lock:
            if rate_kbps:
                mid = self.meter_id(cookie)
                self._ofctl("del-meter", edge, f"meter={mid}")
                self._ofctl("add-meter", edge,
                            f"meter={mid},kbps,burst,band=type=drop,rate={rate_kbps},"
                            f"burst_size={max(rate_kbps // 10, 50)}")
            for sw, flow in self._grant_flows(cookie, src_ip, dst_ip, ports, rate_kbps, hard_timeout):
                self._ofctl("add-flow", sw, flow)
        log.info("GRANT   cookie=%#x %s -> %s ports=%s rate=%s path=%s", cookie, src_ip, dst_ip,
                 ports, f"{rate_kbps}kbps" if rate_kbps else "full", self.path(src_ip, dst_ip))

    def refresh(self, cookie, src_ip, dst_ip, ports, rate_kbps=0, hard_timeout=70):
        """Re-add the grant flows so their hard_timeout restarts (called on every heartbeat)."""
        with self.lock:
            for sw, flow in self._grant_flows(cookie, src_ip, dst_ip, ports, rate_kbps, hard_timeout):
                self._ofctl("add-flow", sw, flow)

    def revoke(self, cookie, src_ip=None):
        with self.lock:
            for sw in self.switches:
                self._ofctl("del-flows", sw, f"cookie={cookie:#x}{COOKIE_MASK}")
            if src_ip and src_ip in self.by_ip:
                self._ofctl("del-meter", self.by_ip[src_ip]["switch"], f"meter={self.meter_id(cookie)}")
        log.info("REVOKE  cookie=%#x %s", cookie, src_ip or "")

    # ------------------------------------------------------- dynamic blocking
    def block(self, ip, seconds):
        """Drop every packet from ip, on all switches, until hard_timeout expires."""
        with self.lock:
            for sw in self.switches:
                self._ofctl("add-flow", sw, f"priority=400,hard_timeout={seconds},ip,nw_src={ip},actions=drop")
                self._ofctl("add-flow", sw, f"priority=400,hard_timeout={seconds},arp,arp_spa={ip},actions=drop")
        log.warning("BLOCK   %s for %ss", ip, seconds)

    def unblock(self, ip):
        with self.lock:
            for sw in self.switches:
                # --strict: delete only the priority-400 block rules, not grants or blacklist rules
                self._ofctl("--strict", "del-flows", sw, f"priority=400,ip,nw_src={ip}")
                self._ofctl("--strict", "del-flows", sw, f"priority=400,arp,arp_spa={ip}")
        log.info("UNBLOCK %s", ip)

    def dump(self):
        return {sw: self._ofctl("dump-flows", sw).stdout for sw in self.switches}
