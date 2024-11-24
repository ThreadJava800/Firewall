# RawSocket filtering

Start up:
```bash
python raw_socket.py --if1 INF1 --if2 INF2 --config PATH_TO_CONFIG_FILE
```

Config example:
```json
{
    "[banned, allowed]": [
        {
            "protocol": "[tcp, udp, icmp]",
            "src_ip": "ip",
            "dst_ip": "ip",
            "src_port": port,
            "dst_port": port
        },
        {
            "protocol": "[tcp, udp, icmp]",
            "src_ip": "ip",
            "dst_ip": "ip",
            "src_port": port,
            "dst_port": port
        },
        ...
    ]
}
```

# Fsqueue filtering:
Start up:
```bash
python nfqueue.py --queue_cnt CNT --config PATH_TO_CONFIG_FILE
```

Config example:
```json
{
    "[banned, allowed]": [
        {
            "dns_mode": "resp",
            "name": "name",
            "type": type,
            "class": class,
            "len": len
        },
        {
            "dns_mode": "quest",
            "name": "name",
            "type": type,
            "class": class
        },
        ...
    ]
}
```
