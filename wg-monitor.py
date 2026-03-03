#!/usr/bin/env python3

import subprocess
import os
import json
import logging
import time
from datetime import datetime

INTERFACE = "wgX"
EMAIL = "xxx@xxx"
WATCHED_IPS = {"X.X.X.X/32", "X.X.X.X/32"}
ONLINE_THRESHOLD = 600
CHECK_INTERVAL = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

_previous_state = {}

def send_mail(subject, body):
    message = f"Subject: {subject}\n\n{body}"
    try:
        subprocess.run(["msmtp", EMAIL], input=message, 
            text=True, check=True, capture_output=True
        )
    except Exception as e:
        logging.error("Failed to send email: %s", str(e))
        raise

def check_wireguard():
    global _previous_state
    
    output = subprocess.run(["wg", "show", INTERFACE, "dump"],
                 text=True, check=True, capture_output=True
             )
    lines = output.stdout.strip().splitlines()
    
    if len(lines) <= 1:
        return
    
    peer_lines = lines[1:]
    now = int(datetime.now().timestamp())
    
    for line in peer_lines:
        fields = line.split("\t")

        public_key = fields[0]
        endpoint = fields[2]
        allowed_ips = fields[3]
        latest_handshake = fields[4]
        rx = int(fields[5])

        if not any(ip in allowed_ips for ip in WATCHED_IPS):
            continue

        previous = _previous_state.get(public_key, {
            "rx": None,
            "latest_handshake": None,
            "last_packet": None,
            "online": False
        })
        
        new_packet = ((previous["rx"] is not None and rx > previous["rx"]) or
            (previous["latest_handshake"] is not None and latest_handshake > previous["latest_handshake"])
        )
        last_packet = previous["last_packet"]
        
        if new_packet:
            last_packet = now
        
        is_online = (last_packet is not None and (now - last_packet) <= ONLINE_THRESHOLD)
        
        if (
            is_online and
            not previous["online"]
        ):
            log_msg = f"Wireguard device connected: {allowed_ips}"
            logging.info(log_msg)
            
            body = (
                f"Wireguard device connected\n\n"
                f"Internal IP: {allowed_ips}\n"
                f"Endpoint: {endpoint}\n"
                f"RX: {rx} bytes\n"
                f"Time: {datetime.now()}\n"
            )
            
            send_mail(
                "Wireguard device connected",
                body
            )
        
        _previous_state[public_key] = {
            "rx": rx,
            "latest_handshake": latest_handshake,
            "last_packet": last_packet,
            "online": is_online
        }

def main():
    while True:
        try:
            check_wireguard()
        except Exception as e:
            logging.error("Error during check: %s", str(e))
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
  main()
