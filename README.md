# wg-monitor
Wireguard monitor

A Python script to monitor devices connected to a WireGuard interface and send email notifications when a device comes online.

## Features

- Monitors a specific WireGuard interface.  
- Tracks packet activity and last handshakes of devices.  
- Detects when a watched device becomes online based on a defined threshold.  
- Sends email notifications when a monitored device connects.  
- Logs events to the console.  

## Requirements

- Python 3.6 or higher  
- [WireGuard](https://www.wireguard.com/) installed and configured  
- `msmtp` configured on your system for sending emails  
- Permissions to run `wg show <interface> dump`  

## Configuration

In the script, update the following variables:

```python
INTERFACE = "wgX"  # Your WireGuard interface name
EMAIL = "xxx@xxx"  # Recipient email for notifications
WATCHED_IPS = {"X.X.X.X/32", "X.X.X.X/32"}  # Internal IPs to monitor
ONLINE_THRESHOLD = 600  # Seconds to consider a device "online"
CHECK_INTERVAL = 5  # Check interval in seconds
