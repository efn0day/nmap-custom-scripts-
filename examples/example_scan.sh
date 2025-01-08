#!/bin/bash

# Simple Nmap scan for the given target
TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: ./example_scan.sh <target-ip>"
    exit 1
fi

echo "Running Nmap scan on $TARGET..."
nmap -p 1-1024 $TARGET
