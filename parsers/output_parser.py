from struct import unpack
import ipaddress

class Result:
    def __init__(self, dest_ip: int, resp_ip: int, rtt: int, distance: int,
                 from_dest: bool, ipv4_addr: bool):
        self.dest_ip = dest_ip
        self.resp_ip = resp_ip
        self.rtt = rtt
        self.distance = distance
        self.from_dest = from_dest
        self.ipv4_addr = ipv4_addr
    def __repr__(self):
        return f"Destination: {ipaddress.ip_address(self.dest_ip)}\n" +\
            f"Responder: {ipaddress.ip_address(self.resp_ip)}\n" +\
            f"distance: {self.distance}\n" +\
            f"rtt: {self.rtt}\n" +\
            f"from_dest: {self.from_dest}\n" +\
            f"ipv4: {self.ipv4_addr}\n"


class FlashRouteParser:
    def __init__(self, filepath: str):
        self.file = open(filepath, mode='rb')

    def next(self) -> Result:
        file_content = self.file.read(39)
        if (len(file_content) < 39):
            return None
        [dest_ip, _, _, _, resp_ip, _, _, _, rtt,
            distance, from_dest, ipv4_addr] = unpack("IIIIIIIIIB??", file_content)
        return Result(dest_ip, resp_ip, rtt, distance, from_dest, ipv4_addr)
