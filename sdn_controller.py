"""
SDN controller module.

Installs and removes OpenFlow rules on the Open vSwitch switch using ovs-ofctl.
Every rule installed for a user is tagged with a cookie unique to that session,
so it can be removed cleanly when the session ends.
"""
import subprocess
import threading
import logging

log = logging.getLogger("sdn")

SWITCH = "s1"
AUTH_SERVER_IP = "10.0.0.1"


class SDNController:
    def __init__(self, switch=SWITCH, protected_ips=None):
        self.switch = switch
        self.protected_ips = protected_ips or []
        self.lock = threading.Lock()

    def _ofctl(self, *args):
        cmd = ["ovs-ofctl", "-O", "OpenFlow13"] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log.error("ovs-ofctl failed: %s | %s", " ".join(cmd), r.stderr.strip())
        return r

    def install_base_policy(self, denied_hosts=()):
        """Default-deny: everyone may reach the auth server, nobody may reach protected services."""
        with self.lock:
            self._ofctl("del-flows", self.switch)
            # priority 0: normal L2 forwarding (ARP, pings between ordinary hosts, auth traffic)
            self._ofctl("add-flow", self.switch, "priority=0,actions=normal")
            # priority 100: block all IP traffic to every protected service
            for ip in self.protected_ips:
                self._ofctl("add-flow", self.switch, f"priority=100,ip,nw_dst={ip},actions=drop")
            # priority 300: blacklisted hosts are blocked everywhere except the auth server
            for h in denied_hosts:
                self._ofctl("add-flow", self.switch, f"priority=300,ip,nw_src={h},actions=drop")
                self._ofctl("add-flow", self.switch,
                            f"priority=310,tcp,nw_src={h},nw_dst={AUTH_SERVER_IP},actions=normal")
        log.info("Base policy installed (protected=%s, denied=%s)", self.protected_ips, list(denied_hosts))

    def grant(self, cookie, src_ip, dst_ip, dst_port):
        """Allow src_ip to open TCP connections to dst_ip:dst_port."""
        rule = (f"cookie={cookie:#x},priority=200,tcp,nw_src={src_ip},"
                f"nw_dst={dst_ip},tp_dst={dst_port},actions=normal")
        with self.lock:
            self._ofctl("add-flow", self.switch, rule)
        log.info("GRANT  cookie=%#x %s -> %s:%s", cookie, src_ip, dst_ip, dst_port)

    def revoke(self, cookie):
        """Remove every rule that belongs to one session."""
        with self.lock:
            self._ofctl("del-flows", self.switch, f"cookie={cookie:#x}/-1")
        log.info("REVOKE cookie=%#x", cookie)

    def dump(self):
        return self._ofctl("dump-flows", self.switch).stdout
