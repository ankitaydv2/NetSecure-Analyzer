# NetSecure Analyzer

A Python-based offline network traffic analyzer that examines PCAP/PCAPNG
captures to identify TCP behavior, connection events, TLS handshake activity,
possible retransmissions, and potential network-level issues.

---

## Overview

NetSecure Analyzer analyzes previously captured network traffic and converts
raw packets into meaningful network events and diagnostic information.

The analyzer focuses on:

- TCP connection establishment and termination
- TCP flags and handshake behavior
- Possible TCP retransmissions
- TLS handshake detection
- ClientHello and ServerHello identification
- Basic protocol statistics
- Rule-based network diagnosis

The project is designed as an offline analysis tool, meaning that it does not
capture live traffic itself. Network traffic can be captured using Wireshark
and then provided to the analyzer as a `.pcap` or `.pcapng` file.

---

## Problem Statement

Network packet captures contain a large amount of low-level information.
Manually analyzing thousands of packets in Wireshark can be time-consuming,
especially when the objective is to quickly understand:

- Whether TCP connections were successfully established
- Whether connections were reset or normally terminated
- Whether packet retransmissions may be occurring
- Whether TLS communication is present
- Whether a TLS handshake was observed
- Whether the traffic indicates possible packet loss or network instability

NetSecure Analyzer automates this initial analysis by processing the capture
and producing a structured summary of important network events.

---

## Objectives

The main objectives of the project are:

1. Parse offline PCAP/PCAPNG network captures.
2. Identify TCP and UDP traffic.
3. Analyze TCP connection behavior.
4. Detect TCP handshake activity.
5. Identify TCP RST and FIN packets.
6. Detect possible TCP retransmissions.
7. Identify TLS ClientHello and ServerHello messages.
8. Provide protocol-level statistics.
9. Generate rule-based diagnostic hints.
10. Reduce the effort required for initial packet analysis.

---

## Key Features

### TCP Analysis

The analyzer identifies important TCP events including:

- SYN packets
- SYN-ACK packets
- ACK packets
- FIN packets
- RST packets
- TCP handshake status
- Possible retransmissions

### TLS Analysis

The analyzer examines TLS handshake traffic and identifies:

- ClientHello messages
- ServerHello messages
- TLS handshake presence
- TLS version information available from the capture

### Protocol Statistics

The analyzer provides:

- Total packet count
- TCP connection count
- UDP connection count
- TCP event statistics
- TLS handshake statistics

### Rule-Based Diagnosis

The analyzer generates diagnostic hints based on observed packet behavior.

For example:

TCP reset packets detected.
Investigate connection termination.

Possible TCP retransmissions detected.
Investigate packet loss, congestion, or network path issues.



### Architecture
                Network Traffic
                       │
                       ▼
                Wireshark Capture
                       │
                       ▼
                  PCAP / PCAPNG
                       │
                       ▼
              ┌──────────────────┐
              │ NetSecure        │
              │ Analyzer         │
              └────────┬─────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     TCP Analysis  UDP Analysis  TLS Analysis
          │            │            │
          └────────────┼────────────┘
                       ▼
              Event & Statistics
                       │
                       ▼
              Rule-Based Diagnosis
                       │
                       ▼
                 Final Report


###  Packet Analysis Pipeline 

PCAP / PCAPNG
      │
      ▼
Read Packets
      │
      ▼
Identify Protocol Layers
      │
      ├───────────────┐
      ▼               ▼
 TCP Analysis     UDP Analysis
      │
      ▼
TCP Flags & Events
      │
      ▼
Possible Retransmissions
      │
      ▼
TLS Handshake Analysis
      │
      ▼
Generate Statistics
      │
      ▼
Rule-Based Diagnosis
      │
      ▼
Final Analysis Report

The core idea is: Packet → Protocol Event → Network Meaning → Possible Diagnosis

### TCP Connection Analysis
Client                         Server
  │                              │
  │ -------- SYN --------------> │
  │                              │
  │ <------ SYN + ACK ---------- │
  │                              │
  │ -------- ACK --------------> │
  │                              │
  │       Connection Ready       │
