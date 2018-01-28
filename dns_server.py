import sys
from os import listdir
from os.path import isfile, join
from easyzone import easyzone
from socket import *
from request import Request
import struct


class DNSServer:
    TYPE_A = 1
    TYPE_NS = 2
    TYPE_CNAME = 5
    TYPE_SOA = 6
    TYPE_MX = 15
    TYPE_TXT = 16
    TYPE_AAAA = 28
    CLASS_IP = 1

    def __init__(self, config_path):
        self.root_servers = {"A.ROOT-SERVERS.NET.": [3600000, "A", "198.41.0.4"],
                             "B.ROOT-SERVERS.NET.": [3600000, "A", "192.228.79.201"],
                             "C.ROOT-SERVERS.NET.": [3600000, 'A', "192.33.4.12"],
                             "D.ROOT-SERVERS.NET.": [3600000, 'A', "199.7.91.13"],
                             "E.ROOT-SERVERS.NET.": [3600000, 'A', "192.203.230.10"],
                             "F.ROOT-SERVERS.NET.": [3600000, 'A', "192.5.5.241"],
                             "G.ROOT-SERVERS.NET.": [3600000, 'A', "192.112.36.4"],
                             "H.ROOT-SERVERS.NET.": [3600000, 'A', "128.63.2.53"],
                             "I.ROOT-SERVERS.NET.": [3600000, 'A', "192.36.148.17"],
                             "J.ROOT-SERVERS.NET.": [3600000, 'A', "192.58.128.30"],
                             "K.ROOT-SERVERS.NET.": [3600000, 'A', "193.0.14.129"],
                             "L.ROOT-SERVERS.NET.": [3600000, 'A', "199.7.83.42"],
                             "M.ROOT-SERVERS.NET.": [3600000, 'A', "202.12.27.33"]}
        self.type_constants = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}

        self.config_data = {}
        files = [f for f in listdir(config_path) if isfile(join(config_path, f))]
        for f in files:
            self.parse_config_files(config_path, f)

        self.server_port = 53535
        self.server_socket = socket(AF_INET, SOCK_DGRAM)
        self.server_socket.bind(('', self.server_port))
        self.serve_requests()

    def parse_config_files(self, path, file_name):
        ind = file_name.find(".conf")
        domain = file_name[:ind]
        self.config_data[domain] = easyzone.zone_from_file(domain, path + file_name)

    def serve_requests(self):
        while 1:
            message, client_address = self.server_socket.recvfrom(512)
            req = Request(message)
            questions = req.get_questions()
            resp = ""  # id, header ...
            answers = []
            found = False
            if message != None and message != "":
                print()
                print(" ========== Answers =========")
                print("ID : ", req.tid)
                print("Recursion Available :   1")
            for q in questions:
                found = self.is_authoritative(q)
                if found[0]:
                    answers.append(self.generate_auth_answer(q, questions[q], found[1]))
                else:
                    answers.append(self.generate_recursive_answer(q, questions[q]))

            header = req.get_response_header(found)
            questions = message[12:req.end_of_questions]
            result = header + questions
            for a in answers:
                result += a[9:]
            result += req.additional
            self.server_socket.sendto(result, client_address)


    def get_A_response(self, data):
        dots_removed = [int(d) for d in data[0].split('.')]
        res = bytearray()
        for d in dots_removed:
            res += struct.pack('!B', d)
        print("                                        ", data[0])
        return res

    def get_NS_response(self, data):
        res = bytearray()
        for dom in data:
            print("                                        ", dom)
            res += self.get_formatted_name(dom)
        return res

    def get_MX_response(self, data):
        res = bytearray()
        for d in data:
            pref = d[0]
            exchange = d[1].strip()
            res += struct.pack('!H', pref)
            res += self.get_formatted_name(exchange)
            print("                                        ", pref, "  ", exchange)
        return res

    def get_TXT_response(self, data):
        print("                                        ", data[0])
        return data[0].encode()

    def get_CNAME_response(self, data):
        print("                                        ", data[0])
        return self.get_formatted_name(data[0])

    def get_SOA_response(self, data):
        split_data = data[0].split(' ')
        to_print = "                           "
        for d in data:
            to_print += "  " + str(d)
        print(to_print)
        res = bytearray()
        res += self.get_formatted_name(split_data[0])
        res += self.get_formatted_name(split_data[1])
        res += struct.pack('!I', int(split_data[2]))
        res += struct.pack('!I', int(split_data[3]))
        res += struct.pack('!I', int(split_data[4]))
        res += struct.pack('!I', int(split_data[5]))
        res += struct.pack('!I', int(split_data[6]))
        return res

    def parse_AAAA_data(self, data):
        quartets = data.split(':')
        decimals = []
        for q in quartets:
            if q == "":
                decimals.append(0)
            else:
                decimals.append(int(q, 16))
        print("                     ", data[0])
        return decimals

    def get_AAAA_response(self, data):
        decimals = self.parse_AAAA_data(data[0])
        res = bytearray()
        for d in decimals:
            res += struct.pack('!I', d)
        return res

    def get_formatted_name(self, domain):
        res_b = bytearray()
        without_dots = domain.split('.')
        for d in without_dots:
            res_b += struct.pack('!B', len(d))  # str(len(d))
            res_b += d.encode()
        return res_b

    def generate_auth_answer(self, domain, q_info, zone_name):
        req_type = int(q_info[0])
        ttl = self.config_data[zone_name].root.soa.get_minttl()
        print(domain, "    ", ttl, "     IN     ", self.type_constants[req_type])
        # print(self.config_data[zone_name].names)
        resp_data = self.config_data[zone_name].names[domain].records(self.type_constants[req_type]).items
        resp = ""
        if req_type == self.TYPE_A:
            resp = self.get_A_response(resp_data)
        elif req_type == self.TYPE_NS:
            resp = self.get_NS_response(resp_data)
        elif req_type == self.TYPE_MX:
            resp = self.get_MX_response(resp_data)
        elif req_type == self.TYPE_AAAA:
            resp = self.get_AAAA_response(resp_data)
        elif req_type == self.TYPE_CNAME:
            resp = self.get_CNAME_response(resp_data)
        elif req_type == self.TYPE_SOA:
            resp = self.get_SOA_response(resp_data)
        elif req_type == self.TYPE_TXT:
            resp = self.get_TXT_response(resp_data)
        ans = self.get_formatted_name(domain)
        ans += struct.pack('!H', q_info[0])
        ans += struct.pack('!H', q_info[1])
        ans += struct.pack('!H', ttl)
        ans += struct.pack('!H', len(resp))
        ans += resp
        return ans

    def is_authoritative(self, domain):
        for z in self.config_data:
            if domain.find(z) != -1:  # domain.endswith(z):
                return True, z
        return False, None

    def generate_recursive_answer(self, domain, q_info):
        data = socket.gethostbyid()
        return ""


if __name__ == '__main__':
    config = sys.argv[1]
    server = DNSServer(config)
