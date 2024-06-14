# -*- coding:utf-8 -*-

# Modules

import requests
from bs4 import BeautifulSoup
import socket
import os
import dns.resolver
import dns.reversename
import ssl
from OpenSSL import crypto
import subprocess
import re

# Variables fixes

url = "http://taisen.fr"
host = 'www.taisen.fr'
domain = 'taisen.fr'
port = 443

# Fonctions

def requet_web(domain):
    r = requests.get(url)
    print(r)


def ip_and_dns(domain):
    ip = socket.gethostbyname(domain)
    dns_name = socket.gethostbyaddr(ip)[0]
    return ip

# Autre manière
def autre_tech(domain):
    answers_IPv4 = dns.resolver.resolve(host, 'A')
    for rdata in answers_IPv4:
        print('IPv4', rdata.address)
    name = dns.reversename.from_address(ip)
    answers_DNS = dns.resolver.resolve(name, 'PTR')
    for rdata in answers_DNS:
        print(rdata.target)


def ip_source_dest(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((domain,port))
    sock.send(b'test')
    sock.close
    print(sock.close)


def head_use(domain):
    response = requests.head(url)
    print(response.headers)


def balise_web(domain):
    page = requests.get(url)
    soup = BeautifulSoup(page.text, 'html.parser')
    array = [tag.name for tag in soup.find_all()]
    print(array)


def get_cert_info(domain):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.connect((domain, 443))
        cert = s.getpeercert(binary_form=True)
    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
    return x509

def print_cert_info(cert):
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        print(f"{ext.get_short_name().decode()}: {ext}")

def traceroute(domain):
    os.system("tracert " + domain)


if __name__ == "__main__" :

    # Afficher l'IP et le nom du serveur DNS
    ip = ip_and_dns(domain)
    print("IP: " + ip)
    
    # Afficher l'IP et le port Source et Déstination
    print("L'IP - port de la Soruce et la Déstination :")
    ip_source_dest(ip, port)
    print("\n")

    # Afficher les Headers
    head_use(domain)
    print('\n')

    # Stocker dans une variable de type array les différentes balises Web
    balise_web(domain)

    # Afficher la liste des IP des équipements réseau traversés pour atteindre le site Web
    traceroute(domain)
    print('\n')

    # Afficher les différents éléments du certificat
    cert = get_cert_info(domain)
    print_cert_info(cert)
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'authorityInfoAccess':
            print(ext)

