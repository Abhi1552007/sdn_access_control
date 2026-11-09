# SDN Authentication and Network Access Control

Hosts must log in to a TCP authentication server before the network lets them reach
protected services. An SDN controller (OpenFlow 1.3 on Open vSwitch, inside Mininet)
grants, **restricts** (rate-limits) and revokes access dynamically, per user role.

## Network (D2)

```
                         s1 (core)
          h1 auth :5000   h4 fileserver :9000   h6 dbserver :9100
                /                         \
          s2 (dept A)                   s3 (dept B)
    h2 alice  h3 guest  h7 admin     h5 blacklisted  h8 bob
```

| Role | Services | Bandwidth | Hours |
|---|---|---|---|
| admin | fileserver, dbserver + admin commands | full | any |
| staff | fileserver | full | any |
| guest | fileserver | 1 Mbit/s (OpenFlow meter) | any |
| contractor | dbserver | full | 09:00–18:00 |

Users: `alice/alice123`, `bob/bob123` (staff), `guest/guest123`, `admin/admin123`, `carol/carol123` (contractor).

## Run

```bash
sudo apt install -y mininet openvswitch-switch iperf python3-matplotlib
git clone https://github.com/Abhi1552007/sdn_access_control.git
cd sdn_access_control
sudo mn -c
sudo python3 topology.py --test      # 12 scenarios (~4 min), then the mininet> prompt
sudo python3 topology.py --perf      # performance evaluation -> results/perf.json
python3 plot_results.py              # graphs -> results/*.png, results/summary.md
```

If conda is active, run `conda deactivate` first. On a machine without the Open vSwitch
kernel module, add `--userspace`.

## Test scenarios (`--test`)

1. Default deny – no login, no access
2. Staff gets fileserver but not dbserver
3. Admin gets both
4. Guest is rate-limited by an OpenFlow meter (iperf staff vs guest)
5. IP spoofing is blocked (grants bind to switch port + MAC)
6. Blacklisted host denied
7. Time-based rule for contractors
8. Brute force → host blocked on every switch for 20 s
9. Admin kicks a user → access revoked at once
10. Live policy reload changes access without restart
11. Auth server crash → access survives, session restored on restart
12. Four users at once, flow tables of all three switches

## Useful commands at `mininet>` (use the full path of the folder)

```
h2 python3 PATH/auth_client.py login alice alice123 --service both --hold 20
h7 python3 PATH/admin_client.py admin admin123 sessions
h7 python3 PATH/admin_client.py admin admin123 flows
h2 cd PATH && python3 auth_client.py login alice alice123 --no-heartbeat --hold 70   # timeout demo
```

## Files

| File | Purpose |
|---|---|
| `topology.py` | Mininet network, starts servers, test scenarios |
| `sdn_controller.py` | OpenFlow rules on all switches: paths, anti-spoofing, meters, blocks |
| `auth_server.py` | Multi-threaded TCP auth server: sessions, roles, admin, reload, crash recovery |
| `perf_test.py`, `perf_client.py` | Performance measurements |
| `auth_client.py` | Login / heartbeat / logout client |
| `admin_client.py` | Admin commands |
| `protected_service.py` | File and database services |
| `add_user.py` | Add or remove users (salted SHA-256) |
| `policy.json`, `users.json` | Policies and users |
| `plot_results.py` | Graphs from the performance results |

Logs: `logs/auth.log` (authentication and SDN events), `logs/access.log` (service access).
