# Port Monitoring Alerts Guide

## Overview
Configuring alerts for suspicious port activity and unauthorized services.

## Alert Categories

### Unauthorized Ports
- New listening ports
- Unexpected services
- Rogue applications
- Backdoor indicators

### Suspicious Connections
- Outbound to known bad IPs
- Non-standard port usage
- Beaconing patterns
- Data exfiltration

## Alert Rules

### High Priority
- Port 4444 (Metasploit default)
- Port 1337 (common backdoor)
- Port 31337 (elite backdoor)
- Ports > 49152 new listeners

### Medium Priority
- RDP from external IPs
- SSH brute force patterns
- Database port exposure
- Admin port changes

### Low Priority
- Ephemeral port changes
- Browser connections
- Update services

## Configuration

### Thresholds
- Connection rate limits
- New port detection window
- Baseline learning period
- Alert cooldown

### Notification Methods
- Email alerts
- Slack/Teams webhooks
- SIEM integration
- SMS for critical

## Response Actions
- Auto-block suspicious IPs
- Kill unauthorized processes
- Firewall rule updates
- Incident ticket creation

## Legal Notice
For authorized network monitoring.
