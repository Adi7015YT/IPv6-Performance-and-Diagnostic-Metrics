#!/bin/bash
# Script to load BPF programs (including XDP)

set -e

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Interface to attach programs to
INTERFACE="wlo1"  # Change to your network interface

# Mount the BPF filesystem
echo "Mounting BPF filesystem..."
mount -t bpf bpf /sys/fs/bpf/ || true

# Clean up existing BPF objects
echo "Cleaning up existing BPF objects..."
rm -rf /sys/fs/bpf/dns_pdm 2>/dev/null || true
mkdir -p /sys/fs/bpf/dns_pdm

# Load the BPF programs
echo "Loading BPF programs..."

# Verify object files exist
echo "Checking if dns_request_handler.o exists..."
if [ ! -f obj/dns_request_handler.o ]; then
    echo "Error: dns_request_handler.o not found!"
    exit 1
fi

echo "Checking if dns_response_handler.o exists..."
if [ ! -f obj/dns_response_handler.o ]; then
    echo "Error: dns_response_handler.o not found!"
    exit 1
fi

# Load and attach DNS request handler (XDP program)
echo "Loading and attaching DNS request handler to XDP on $INTERFACE..."
ip link set dev $INTERFACE xdp obj obj/dns_request_handler.o sec xdp

# Load and attach DNS response handler (TC egress program)
echo "Setting up TC for egress classifier on $INTERFACE..."
tc qdisc add dev $INTERFACE clsact 2>/dev/null || tc qdisc change dev $INTERFACE clsact

echo "Attaching DNS response handler to TC egress..."
tc filter add dev $INTERFACE egress bpf direct-action obj obj/dns_response_handler.o sec tc/egress

# Pin maps and programs (if needed)
echo "Pinning BPF objects..."
bpftool prog load obj/dns_request_handler.o /sys/fs/bpf/dns_pdm/dns_request_handler
bpftool prog load obj/dns_response_handler.o /sys/fs/bpf/dns_pdm/dns_response_handler

echo "BPF programs loaded and attached successfully"