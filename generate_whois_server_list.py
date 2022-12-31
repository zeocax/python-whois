import whois
import re
import socket


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
    whois_server = "whois.iana.org"
    msg = perform_whois(server=whois_server, query=extension)
    whois_server = re.search("whois:        (.*)", msg).group(1)
    return whois_server


tlds = whois.validTlds()

whois_server_list = {}

for tld in tlds:
    # Skip SLD
    if "." in tld:
        continue
    # Skip .onion
    if tld == "onion":
        continue
    print(tld)
    whois_server = get_whois_server(tld)
    whois_server_list[tld] = whois_server


tld_whois_server_not_in_iana_database = {
    "buzz": "whois.nic.buzz",
    "cd": "whois.nic.cd",
    "kred": "whois.nic.kred",
    "nyc": "whois.nic.nyc"
}

for tld in tld_whois_server_not_in_iana_database:
    whois_server_list[tld] = tld_whois_server_not_in_iana_database[tld]

whois_server_list_file = open("whois/whois_server_list.py", "w", encoding="utf-8")
print("whois_server_list = ", end="", file=whois_server_list_file)
print(whois_server_list, file=whois_server_list_file)
whois_server_list_file.close()
