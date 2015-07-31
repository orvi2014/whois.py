#!/usr/bin/python

import socket, sys

def perform_whois(server , query) :
    #socket connection
    s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    s.connect((server , 43))
    s.send(query + '\r\n')
    msg = ''
    while len(msg) < 10000:
        c = s.recv(100)
        if(c == ''):
            break
        msg = msg + c
     
    return msg

# Domain name
def get_whois_data(domain):
     
    domain = domain.replace('http://','')
    domain = domain.replace('www.','')
    
    #get the extension , .com , .org , .edu
    ext = domain[-3:]
     
    #top level domain .com .org .net
    if(ext == 'com' or ext == 'org' or ext == 'net'):
        whois = 'whois.internic.net'
        msg = perform_whois(whois , domain)
         
        #Now scan the reply for the whois server
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if  'Whois' in words[0] and 'whois.' in words[1]:
                    whois = words[1].strip()
                    break;
     
    else:
        ext = domain.split('.')[-1]
         
        whois = 'whois.iana.org'
        msg = perform_whois(whois , ext)
         
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if 'whois.' in words[1] and 'Whois Server (port 43)' in words[0]:
                    whois = words[1].strip()
                    break;
     
    msg = perform_whois(whois , domain)
     
    return msg

domain_name = sys.argv[1]
print get_whois_data(domain_name)
