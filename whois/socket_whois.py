import re
import socket
from .whois_server_list import whois_server_list

def perform_whois(server: str, query: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect((server, 43))
    s.send((query + "\r\n").encode())
    msg = ""
    while len(msg) < 10000:
        chunk = s.recv(100).decode(errors="ignore")
        if chunk == "":
            break
        msg = msg + chunk
    return msg


def get_whois_server(extension: str) -> str:
    if extension in whois_server_list:
        return whois_server_list[extension]
    whois_server = "whois.iana.org"
    msg = perform_whois(server=whois_server, query=extension)
    whois_server = re.search("whois:        (.*)", msg).group(1)
    return whois_server


def get_whois_data(dl: list[str]) -> str:
    domain = ".".join(dl)
    extension = dl[-1]
    whois_server = get_whois_server(extension=extension)
    # Fpr .jp domain, to suppress Japanese output, add '/e' at the end of command.
    msg = perform_whois(server=whois_server, query=domain + "/e" if extension == "jp" else domain)
    # print(msg)
    return msg
