# eBPF Firewall Library

This directory contains eBPF programs and tools of BleFSM.

## eBPF library

IoTFirewallCore/ZephyrOS/zephyr/firewall/libebpf/ebpf-src

## eBPF C source code

IoTFirewallCore/ZephyrOS/zephyr/firewall/policy/ebpf_code

## eBPF bytecode

IoTFirewallCore/ZephyrOS/zephyr/firewall/policy/include

## Build

Run the following command to build eBPF C program:

```
# IoTFirewallCore/ZephyrOS/zephyr/firewall/policy
$ ./compile.sh cve_2020_10069
```

The generated bytecode will be written to C head files in policy/include. The script is tested under WSL, so don't forget to set line termination characters to LF.

## Reference

https://github.com/uw-unsat/jitterbug