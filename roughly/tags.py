def name_to_tag(name: str) -> int:
    return int.from_bytes(name.ljust(4, "\x00").encode("ascii"), "little")


CERT = name_to_tag("CERT")
DELE = name_to_tag("DELE")
INDX = name_to_tag("INDX")
MAXT = name_to_tag("MAXT")
MIDP = name_to_tag("MIDP")
MINT = name_to_tag("MINT")
NONC = name_to_tag("NONC")
PATH = name_to_tag("PATH")
PUBK = name_to_tag("PUBK")
RADI = name_to_tag("RADI")
ROOT = name_to_tag("ROOT")
SIG = name_to_tag("SIG")
SREP = name_to_tag("SREP")
SRV = name_to_tag("SRV")
TYPE = name_to_tag("TYPE")
VER = name_to_tag("VER")
VERS = name_to_tag("VERS")
ZZZZ = name_to_tag("ZZZZ")

TYPE_REQUEST = 0
TYPE_RESPONSE = 1
