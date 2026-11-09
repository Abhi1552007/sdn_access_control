"""
Make graphs from results/perf.json (created by: sudo python3 topology.py --perf).

  python3 plot_results.py        -> results/*.png and results/summary.md

Needs matplotlib:  sudo apt install -y python3-matplotlib
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results")
BLUE, GREY, INK, MUTED = "#2a78d6", "#a3a29c", "#0b0b0b", "#52514e"

plt.rcParams.update({
    "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb", "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": "#e6e5e0",
    "grid.linewidth": 0.6, "axes.axisbelow": True, "axes.titleweight": "bold", "axes.titlesize": 11,
})


def bar_labels(ax, bars, fmt):
    for b in bars:
        ax.annotate(fmt(b.get_height()), (b.get_x() + b.get_width() / 2, b.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=9, color=INK)


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name), dpi=160)
    plt.close(fig)
    print("saved results/" + name)


def main():
    r = json.load(open(os.path.join(OUT, "perf.json")))

    # 1. latency of granting and revoking access
    lat = r["latency"]
    keys = [("auth_ms", "Login reply"), ("access_ms", "Login → access\nallowed"),
            ("revoke_ms", "Logout → access\nrevoked")]
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    bars = ax.bar([k[1] for k in keys], [lat[k[0]]["mean"] for k in keys], width=0.5, color=BLUE)
    ax.errorbar(range(3), [lat[k[0]]["mean"] for k in keys],
                yerr=[[lat[k[0]]["mean"] - lat[k[0]]["min"] for k in keys],
                      [lat[k[0]]["p95"] - lat[k[0]]["mean"] for k in keys]],
                fmt="none", ecolor=MUTED, capsize=4, linewidth=1)
    for b in bars:   # value inside the bar so it never collides with the error bar
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() / 2, f"{b.get_height():.0f} ms",
                ha="center", va="center", color="white", fontsize=10, fontweight="bold")
    ax.set_ylabel("milliseconds (mean, min–p95)")
    ax.set_title(f"How fast the SDN grants and revokes access (n={lat['auth_ms']['n']})")
    save(fig, "latency.png")

    # 2. scalability
    sc = [row for row in r["scalability"] if "mean" in row]
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    x = [row["clients"] for row in sc]
    ax.plot(x, [row["mean"] for row in sc], color=BLUE, linewidth=2, marker="o", markersize=6, label="mean")
    ax.plot(x, [row["max"] for row in sc], color=GREY, linewidth=2, marker="o", markersize=6,
            linestyle="--", label="slowest client")
    for row in sc[-1:]:
        ax.annotate(f"{row['mean']:.0f} ms", (row["clients"], row["mean"]), xytext=(6, -16),
                    textcoords="offset points", ha="center", fontsize=9, color=INK)
    ax.set_xlabel("clients logging in at the same moment")
    ax.set_ylabel("login → access allowed (ms)")
    ax.set_title("Scalability: simultaneous logins")
    ax.legend(frameon=False)
    ax.set_xticks(x)
    save(fig, "scalability.png")

    # 3. throughput per role vs no access control
    tp, base = r["throughput_mbps"], r["baseline"]
    labels = ["No SDN\n(baseline)", "Admin", "Staff", "Guest\n(1 Mbit/s meter)", "Not logged in"]
    vals = [base["throughput_mbps"], tp["admin"], tp["staff"], tp["guest"], tp["unauthenticated"]]
    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    bars = ax.bar(labels, vals, width=0.55, color=[GREY, BLUE, BLUE, BLUE, BLUE])
    bar_labels(ax, bars, lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")
    ax.set_yscale("symlog", linthresh=1)
    ax.set_ylabel("Mbit/s to fileserver (log scale)")
    ax.set_title("Throughput by role (iperf, 5 s)")
    save(fig, "throughput.png")

    # 4. comparison table (markdown) for the report
    md = ["| Metric | With SDN access control | Without (baseline) |", "|---|---|---|",
          f"| Unauthenticated host throughput | {tp['unauthenticated']:.2f} Mbit/s (blocked) | "
          f"{base['unauthenticated_throughput_mbps']:.0f} Mbit/s (open) |",
          f"| Authorized throughput (staff) | {tp['staff']:.0f} Mbit/s | {base['throughput_mbps']:.0f} Mbit/s |",
          f"| Time before first packet allowed | {lat['access_ms']['mean']:.0f} ms (login + rule install) | "
          f"{base['connect_ms']['mean']:.1f} ms (no login) |",
          f"| Revocation time | {lat['revoke_ms']['mean']:.0f} ms | not possible |",
          f"| Guest bandwidth limit | {tp['guest']:.2f} Mbit/s | none |"]
    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
