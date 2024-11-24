import argparse
import dpkt
import enum
import json
import ipaddress
import os.path
import socket
import struct

TRANSFER_SIZE = 4096

class Protocol(enum.Enum):
    base = 0,
    udp  = 1,
    tcp  = 2,
    icmp = 3

class Mode(enum.Enum):
    DEFAULT    = 0,
    BAN_MODE   = 1,
    ALLOW_MODE = 2

class Filter:
    def __init__(self) -> None:
        self.mode = Mode.DEFAULT
        self.src_ips = list()   # str
        self.dst_ips = list()   # str
        self.src_ports = list() # ints
        self.dst_ports = list() # ints
        self.protocols = list() # Protocols

    def _parse_single_conf(self, allowed_conf: dict, work_mode: Mode):
        self.mode = work_mode
        try:
            src_ip = ipaddress.ip_address(allowed_conf["src_ip"])
            self.src_ips.append(src_ip)
        except KeyError:
           pass
        try:
            src_port = allowed_conf["src_port"]
            self.src_ports.append(src_port)
        except KeyError:
           pass
        try:
            dst_ip = ipaddress.ip_address(allowed_conf["dst_ip"])
            self.dst_ips.append(dst_ip)
        except KeyError:
           pass
        try:
            dst_port = allowed_conf["dst_port"]
            self.dst_ports.append(dst_port)
        except KeyError:
           pass
        try:
            proto = allowed_conf["protocol"]
            try:
                self.protocols.append(Protocol[proto])
            except KeyError:
                raise TypeError("Only TCP/UDP/ICMP allowed!")
        except KeyError:
           pass

    def parse(self, config_file: os.PathLike):
        config_as_json = json.load(config_file)
        is_allowed = False
        try:
            for allowed_conf in config_as_json["allowed"]:
                is_allowed = True
                self._parse_single_conf(allowed_conf, Mode.ALLOW_MODE)
        except KeyError:
            pass

        if not is_allowed:
            try:
                for banned_conf in config_as_json["banned"]:
                    self._parse_single_conf(banned_conf, Mode.BAN_MODE)
            except KeyError:
                pass

    def defineProtocol(self, request: dpkt.ip.IP) -> Protocol:
        if isinstance(request.data, dpkt.icmp.ICMP):
            return Protocol.icmp
        if isinstance(request.data, dpkt.udp.UDP):
            return Protocol.udp
        if isinstance(request.data, dpkt.tcp.TCP):
            return Protocol.tcp
        return Protocol.base

    def filter(self, request: dpkt.ethernet.Ethernet) -> bool:
        if isinstance(request.data, dpkt.ip.IP) and self.mode.value != Mode.DEFAULT.value:
            proto = self.defineProtocol(request.data)
            is_allowed = (self.mode.value == Mode.ALLOW_MODE.value)

            src_ip = ipaddress.ip_address(str(socket.inet_ntop(socket.AF_INET, request.data.src)))
            dst_ip = ipaddress.ip_address(str(socket.inet_ntop(socket.AF_INET, request.data.dst)))

            if len(self.protocols) != 0 and ((is_allowed and not proto in self.protocols) or (not is_allowed and proto in self.protocols)):
               return False 
            if len(self.src_ips) != 0 and ((is_allowed and not src_ip in self.src_ips) or (not is_allowed and src_ip in self.src_ips)):
               return False 
            if len(self.dst_ips) != 0 and ((is_allowed and not dst_ip in self.dst_ips) or (not is_allowed and dst_ip in self.dst_ips)):
               return False 
            
            if proto.value != Protocol.icmp.value:
                src_port = socket.ntohs(request.data.data.sport)
                dst_port = socket.ntohs(request.data.data.dport)

                if len(self.src_ports) != 0 and ((is_allowed and not src_port in self.src_ports) or (not is_allowed and src_port in self.src_ports)):
                    return False 
                if len(self.dst_ports) != 0 and ((is_allowed and not dst_port in self.dst_ports) or (not is_allowed and dst_port in self.dst_ports)):
                    return False 
                
            return True
        return False

def getSocket(ifname: str) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((ifname, socket.ETH_P_ALL))

    return sock
        
def listen(in_sock: socket, out_sock: socket, filter: Filter):
    while True:
        raw_request = in_sock.recv(TRANSFER_SIZE)
        parsed_request = dpkt.ethernet.Ethernet(raw_request)
        passed = filter.filter(parsed_request)

        if passed:
            out_sock.sendall(raw_request)

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, "r")

def createParser() -> argparse:
    parser = argparse.ArgumentParser(
                            prog="RawSocket filter",
                            description="Filter for communication between two raw sockets.",
                        )
    parser.add_argument(
                            "--if1", 
                            type=str, 
                            help="first interface name", 
                            required=True
                        )
    parser.add_argument(
                            "--if2", 
                            type=str, 
                            help="second interface name", 
                            required=True
                        )
    parser.add_argument(
                            "--config", 
                            type=lambda x: is_valid_file(parser, x), 
                            help="path to config file with filter options", 
                            required=True
                        )

    return parser

def realMain():
    parser = createParser()
    args = parser.parse_args()

    filter_inst = Filter()
    filter_inst.parse(args.config)

    socket1 = getSocket(args.if1)
    socket2 = getSocket(args.if2)

    if os.fork() == 0:
        listen(socket1, socket2, filter_inst)
    else:
        listen(socket2, socket1, filter_inst)

if __name__ == "__main__":
    realMain()
