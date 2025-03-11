# PDM IPv6 Implementation

This repository contains three implementations of IPv6 Performance Diagnostic Metrics (PDM) using Destination Options headers:

1. **Manual PDM Client**: Constructs and sends IPv6 packets with PDM headers manually.
2. **eBPF PDM Implementation**: Uses eBPF/TC to automatically add PDM headers to outgoing DNS queries.
3. **PDM Server**

## Prerequisites

- Linux kernel 5.15+
- libbpf-dev
- clang/LLVM 12+
- build-essential
- Linux headers (`linux-headers-$(uname -r)`)
- Root privileges

## 1. Manual PDM Client

### Build & Run

```bash
cd manual-pdm-client
# Install dependencies
sudo apt install build-essential

# Compile
gcc pdm.c -o pdm -Wall -Wextra

# Run (requires root for raw sockets)
sudo ./pdm
```

### Key Features
- Creates IPv6 packet with PDM destination option
- UDP payload with DNS query
- Raw socket transmission
- Prints hex dump of sent packet

### Note
- Update interface name in code (`wlo1`) if needed
- Verify source & destination IP addresses match your network

## 2. eBPF PDM Implementation

### Build & Run

```bash
cd ebpf-pdm

# Install dependencies
sudo apt install clang llvm libbpf-dev libelf-dev

# Compile
clang -O2 -target bpf -c pdm_ebpf.c -o pdm_ebpf.o
gcc -o loader loader.c -lbpf

# Load eBPF program
sudo ./pdm
```

### Key Components
1. **eBPF Program** (`pdm_ebpf.c`):
   - TC egress hook
   - Adds PDM option to UDP DNS queries
   - Handles IPv6 header modifications

2. **Loader** (`loader.c`):
   - Attaches eBPF program to TC
   - Uses `tc` commands for setup
   - Clean detachment on exit

### Verification
```bash
# Check TC filter
tc filter show dev wlo1 egress

# Monitor packets
sudo tcpdump -ni wlo1 'ip6 and udp port 53' -XX
```

## Important Notes

1. **Interface Configuration**:
   - Update interface name (`wlo1`) in both code files
   - Requires IPv6 connectivity
   - Test with local/global IPv6 addresses

2. **Security**:
   - Requires root privileges
   - Test in controlled environment
   - Raw sockets bypass firewall rules

3. **Compatibility**:
   - Verified on Ubuntu 22.04 LTS
   - Kernel 5.15+
   - May require adjustments for different network setups

## Testing Recommendations

1. Use Wireshark to inspect:
   - IPv6 Destination Options header
   - PDM option (type 0x0F)
   - Sequence numbers and timing values

2. Test with both:
   - Local network communication
   - Global IPv6 addresses

3. Verify end-to-end compatibility with PDM-aware receivers
   - Use dig or other tools to send DNS query when using ebpf
   - Change the hex of dns query when using manual pdm client

## Cleanup

For eBPF implementation:
```bash
sudo tc qdisc del dev wlo1 clsact 2>/dev/null
```

## License
GPLv3 - See source code headers for details
