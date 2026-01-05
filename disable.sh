#!/usr/bin/env bash
set -e

QUEUE_NUM=1
sudo iptables -D OUTPUT -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
echo "[+] NFQUEUE disabled"
