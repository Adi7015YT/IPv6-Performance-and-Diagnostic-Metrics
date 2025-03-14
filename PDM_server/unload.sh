#!/bin/bash
# Script to unload BPF programs (including XDP)

set -e

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Interface to detach programs from
INTERFACE="wlo1"  # Change to your network interface

# Detach XDP program
echo "Removing XDP program from $INTERFACE..."
ip link set dev $INTERFACE xdp off 2>/dev/null || true

# Detach and remove TC filter
echo "Removing TC filter from $INTERFACE..."
tc filter del dev $INTERFACE egress 2>/dev/null || true
tc qdisc del dev $INTERFACE clsact 2>/dev/null || true

# Detach cgroup program (if applicable)
echo "Detaching socket program from cgroup..."
PROG_ID=$(bpftool prog show pinned /sys/fs/bpf/dns_pdm/dns_request_handler 2>/dev/null | grep -o "id [0-9]*" | awk '{print $2}' || echo "")
if [ -n "$PROG_ID" ]; then
    bpftool cgroup detach /sys/fs/cgroup/unified sock_ops id $PROG_ID 2>/dev/null || true
fi

# Remove pinned maps and programs
echo "Removing pinned BPF objects..."
rm -rf /sys/fs/bpf/dns_pdm 2>/dev/null || true

echo "BPF programs unloaded successfully"