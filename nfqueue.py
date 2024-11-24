import argparse
import dpkt
import enum
import json
import netfilterqueue
import os
import socket

class DNSType(enum.Enum):
    QUESTION = 0,
    REQUEST  = 1

class Mode(enum.Enum):
    DEFAULT    = 0,
    BAN_MODE   = 1,
    ALLOW_MODE = 2

class Filter:
    def __init__(self) -> None:
        self.mode = Mode.DEFAULT
        self.response_names = list()
        self.response_types = list()
        self.response_classes = list()
        self.response_len = list()
        self.quest_names = list()
        self.quest_types = list()
        self.quest_classes = list()

    def _parse_single_conf(self, allowed_conf: dict, work_mode: Mode):
        self.mode = work_mode
        
        try:
            dns_mode = allowed_conf["dns_mode"]
        except KeyError:
            print("DNS_MODE must be provided (response, question)")
            return

        try:
            name_  = allowed_conf["name"]
            if dns_mode == "resp":
                self.response_names.append(name_)
            if dns_mode == "quest":
                self.quest_names.append(name_)
        except KeyError:
            pass
        try:
            type_  = allowed_conf["type"]
            if dns_mode == "resp":
                self.response_types.append(type_)
            if dns_mode == "quest":
                self.quest_types.append(type_)
        except KeyError:
            pass
        try:
            class_  = allowed_conf["class"]
            if dns_mode == "resp":
                self.response_classes.append(class_)
            if dns_mode == "quest":
                self.quest_classes.append(class_)
        except KeyError:
            pass
        try:
            len_  = allowed_conf["len"]
            if dns_mode == "resp":
                self.response_types.append(len_)
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

    def filter(self, package: dpkt.ethernet.Ethernet) -> bool:
        dns_level_packet = dpkt.dns.DNS(package.data.data.data)

        is_allowed = (self.mode.value == Mode.ALLOW_MODE.value)
        if dns_level_packet.qr == dpkt.dns.DNS_R:
            dns_resp_level = dns_level_packet.unpack_rr(package, 0)[0]
            name_, type_, class_, len_ = dns_resp_level.name, dns_resp_level.type, dns_resp_level.cls, dns_resp_level.rlaen

            if len(self.response_names) != 0 and ((is_allowed and not name_ in self.response_names) or (not is_allowed and name_ in self.response_names)):
               return False 
            if len(self.response_types) != 0 and ((is_allowed and not type_ in self.response_types) or (not is_allowed and type_ in self.response_types)):
               return False 
            if len(self.response_classes) != 0 and ((is_allowed and not class_ in self.response_classes) or (not is_allowed and class_ in self.response_classes)):
               return False 
            if len(self.response_len) != 0 and ((is_allowed and not len_ in self.response_len) or (not is_allowed and len_ in self.response_len)):
               return False 
        if dns_level_packet.qr == dpkt.dns.DNS_Q:
            dns_quest_level = dns_level_packet.unpack_q(package, 0)[0]
            name_, type_, class_ = dns_quest_level.name, dns_quest_level.type, dns_quest_level.cls

            if len(self.quest_names_names) != 0 and ((is_allowed and not name_ in self.response_names) or (not is_allowed and name_ in self.response_names)):
               return False 
            if len(self.quest_types_types) != 0 and ((is_allowed and not type_ in self.response_types) or (not is_allowed and type_ in self.response_types)):
               return False 
            if len(self.response_classes) != 0 and ((is_allowed and not class_ in self.response_classes) or (not is_allowed and class_ in self.response_classes)):
               return False
        return True

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, "r")

def createParser() -> argparse:
    parser = argparse.ArgumentParser(
                            prog="NFQUEUE filter",
                            description="Filter for nfqueue communication.",
                        )
    parser.add_argument(
                            "--queue_cnt", 
                            type=int, 
                            help="queue size", 
                            required=True
                        )
    parser.add_argument(
                            "--config", 
                            type=lambda x: is_valid_file(parser, x), 
                            help="path to config file with filter options", 
                            required=True
                        )

    return parser

def evtQueue(package, filter: Filter):
    request = package.get_payload()
    parsed_request = dpkt.ethernet.Ethernet(request)

    if isinstance(parsed_request.data, dpkt.ip.IP) and isinstance(parsed_request.data.data.data, dpkt.dns.DNS):
        if filter.filter(parsed_request):
            print("PACKET PASSED")
            return request.accept()
        
    print("PACKET NOT PASSED")
    return request.drop()

def runQueue(args, filter: Filter) -> netfilterqueue.NetfilterQueue:
    callback = lambda package: evtQueue(package, filter)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(args.queue_cnt, callback)
    socket_ = socket.fromfd(queue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    queue.run_socket(socket_)


def realMain():
    parser = createParser()
    args = parser.parse_args()

    filter = Filter()
    filter.parse(args.config)

    runQueue(args, filter)

if __name__ == "__main__":
    realMain()