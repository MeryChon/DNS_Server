import struct

class Request:
    def __init__(self, message):
        self.message = message
        self.header = struct.unpack('!6H', message[:12])
        self.tid, self.flags, self.t_question, self.t_ans, self.t_authrr, self.t_addrr = self.header
        self.flag_bits = "{0:b}".format(self.flags).zfill(16)
        self.authoritative_ans, self.tc, self.recursion_desired, self.recursion_available = self.flag_bits[5:9]
        self.z = self.flag_bits[9:12]
        self.response_code = self.flag_bits[12:16]
        self.end_of_questions = 0
        self.additional = ""
        self.type_constants = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
        print("======= Request =======")
        print("ID : ", self.tid)
        print("Recursion Desired : ", self.recursion_desired)


    def get_header(self):
        return self.header

    def get_response_header(self, is_authoritative):
        b = 0
        if is_authoritative:
            b = 1
        flags = str(1) + self.flag_bits[1:5] + str(b) + self.flag_bits[6:]
        res = struct.pack('!6H', self.tid, int(flags, 2), self.t_question, self.t_ans, self.t_authrr, self.t_addrr)
        return res

    def get_questions(self):
        start = 12
        questions = {}
        print("Number of questions : ", self.t_question)
        for i in range(self.t_question):
            length = self.message[start]
            domain_name = ""
            while length != 0:
                domain_name += self.message[start+1: start+1+length].decode() + '.'
                start += length+1
                length = self.message[start]
            start += 1  #start was the index of 0
            req_type = struct.unpack('!H', self.message[start:start+2])[0]
            start += 2
            req_class = struct.unpack('!H', self.message[start:start+2])[0]
            start += 2
            questions[domain_name] = (req_type, req_class)
            print("Domain :    ", domain_name)
            print("Type   :      ", self.type_constants[req_type])
            print("Class  :     IN")
        self.end_of_questions = start
        self.additional = self.message[start:]
        # print(self.additional)
        # additional_info = self.message[start:]
        return questions



    def get_num_queries(self):
        return self.t_question

