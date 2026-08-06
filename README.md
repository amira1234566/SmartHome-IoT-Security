# Secure Smart Home IoT Authentication and Access Control

This repository contains the ns-3.41 implementation and supporting documentation for a secure Smart Home IoT authentication and access-control architecture.

## Implemented Security Components

- IEEE 802.1X with EAP/EAPOL
- RADIUS (AAA)
- LDAP and LDAP Cache
- Kerberos-inspired Ticketing
- Role-Based Access Control (RBAC)
- Command MAC Verification
- Sequence Number Replay Protection
- Privilege Escalation Protection

## Implemented Attack Scenarios

- Replay Attack
- Privilege Escalation Attack

## Security Workflow

Supplicant  
→ IEEE 802.1X Authenticator  
→ RADIUS  
→ LDAP / LDAP Cache  
→ RADIUS Access-Accept or Access-Reject  
→ Kerberos-inspired KDC  
→ Smart-Home Gateway  
→ Ticket Validation  
→ Command MAC Verification  
→ Sequence Number Replay Detection  
→ RBAC Permission Check  
→ IoT Device

## Repository Contents

- `iot-defense-demo.cc` — Main ns-3.41 simulation source file.
- `Source_Code_and_Implementation_Guide.pdf` — Source code and implementation guide.

## Development Environment

- ns-3.41
- Ubuntu Linux
- VMware
- C++
