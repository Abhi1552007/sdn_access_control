# SDN Authentication and Network Access Control

Hosts must log in to a TCP authentication server before the network lets them
reach a protected service. On a successful login the SDN controller installs an
OpenFlow rule that opens the path; on logout or session timeout the rule is removed.

## Architecture

```
            +------------------- s1 (Open vSwitch, OpenFlow 1.3) -------------------+
            |                                                                       |
   h1 10.0.0.1          h2 10.0.0.2      h3 10.0.0.3      h4 10.0.0.4         h5 10.0.0.5
   auth_server.py       client           client           protected_service   blacklisted
   + sdn_controller.py  (alice)          (bob/guest)      :9000               host
   :5000
```

1. Client connects to h1:5000 over TCP and sends `login`.
2. Server checks the salted SHA-256 password hash (`users.json`) and the policy (`policy.json`).
3. If allowed, `sdn_controller.py` runs `ovs-ofctl add-flow` with a per-session cookie.
4. Client sends heartbeats; if they stop for `session_timeout_sec`, the session expires.
5. On logout or timeout the controller deletes every flow with that cookie.

### Flow table priorities

| Priority | Match | Action | Purpose |
|---|---|---|---|
| 310 | tcp from blacklisted host to auth server | normal | let it be refused politely |
| 300 | ip from blacklisted host | drop | host deny policy |
| 200 | tcp src=client dst=10.0.0.4:9000 (cookie per session) | normal | granted access |
| 100 | ip dst=10.0.0.4 | drop | default deny for protected service |
| 0 | any | normal | ordinary L2 forwarding |

## Files

| File | Role |
|---|---|
| `auth_server.py` | Multi-threaded TCP auth server, sessions, timeouts, lockout, logging |
| `auth_client.py` | Client: login, heartbeat, logout, try the service |
| `sdn_controller.py` | Installs/removes OpenFlow rules via `ovs-ofctl` |
| `protected_service.py` | TCP service on h4 that logs every access |
| `topology.py` | Builds the Mininet network, starts servers, runs tests |
| `users.json` | Users with salted password hashes and roles |
| `policy.json` | Allow/deny policies, timeout, lockout limit |
| `logs/auth.log`, `logs/access.log` | Authentication and access logs |

Demo users: `alice / alice123` (staff), `bob / bob123` (staff), `guest / guest123` (guest, no access).

## Running

```bash
cd ~/sdn_auth
sudo python3 topology.py --test     # runs all scenarios, then opens the Mininet CLI
sudo python3 topology.py            # just the network + CLI
```

Useful CLI commands:

```
mininet> h2 python3 auth_client.py access
mininet> h2 python3 auth_client.py login alice alice123 --hold 20
mininet> h1 ovs-ofctl -O OpenFlow13 dump-flows s1
mininet> h2 python3 auth_client.py status
mininet> sh tail logs/auth.log
```

Session timeout demo (about 70 seconds):

```
mininet> h2 python3 auth_client.py login alice alice123 --no-heartbeat --hold 70
```

Note: lockouts last until the server restarts. Exit Mininet and run `topology.py` again to reset.

## Test scenarios (`--test`)

1. Unauthenticated access is blocked
2. Wrong password rejected, access stays blocked
3. Valid login grants access, logout revokes it
4. Guest is authenticated but the policy denies the service
5. Blacklisted host denied even with valid credentials
6. Two users logged in concurrently, flow table shown
7. Lockout after 3 failed attempts
