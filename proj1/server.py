#!/usr/bin/env python3

import sys
import socket

""" ERROR CODES"""
CONTENT_0 = "content-length: 0 \r\n\r\n"
ERR_OK = "HTTP/1.1 200 OK \r\ncontent-length: "
ERR_BAD_REQ = "HTTP/1.1 400 Bad Request \r\n" + CONTENT_0
ERR_NOT_FOUND = "HTTP/1.1 404 Not Found \r\n" + CONTENT_0
ERR_COMM = "HTTP/1.1 405 Method Not Allowed \r\n" + CONTENT_0
ERR_INTERN = "500 Internal Server Error"


#translates domain name to ip address or other way aroud
def get(typ,name):
    if typ == 'A':
        try: #check if its domain name or IP adress.
            #if its IP address it will result in not found 
            socket.inet_aton(name)
            return 0
        except socket.error: #its domain name
            try: #check if its valid domian name
                ip_addr = socket.getaddrinfo(name,80,socket.AF_INET)
                addr = ip_addr[0][4]
                addr = addr[0]
                return name + ':' + typ + '=' + addr + '\r\n'
            except socket.error:
                return 0
    elif typ == 'PTR':
        try: #check if its a valid ip address
            socket.inet_aton(name) 
            try:
                hostname = socket.getnameinfo((name,80),socket.NI_NOFQDN)
                addr = hostname[0]
                return name + ':' + typ + '=' + addr + '\r\n'
            except socket.error:
                return 0
        except socket.error:
           return ERR_BAD_REQ #toto return ERR_BAD_REQ OR NOT FOUND???
    else: #unknown type
        return ERR_BAD_REQ


def post(body):
    question = body[1].split('\n')
    answer = '';
    for x in range(len(question)):
        ques_split = question[x].split(':')
        if len(ques_split) < 2:
            break
        a = get(ques_split[1],ques_split[0])
        if a != 0 and a != ERR_BAD_REQ: #add answer to the list 
            answer = answer + a
    if not answer: #nothing was found
        return  ERR_NOT_FOUND
    else:
        return  ERR_OK + str(len(answer.encode('utf-8')))+ '\r\n\r\n' + answer


def get_answer(message):
    message = message.decode("utf-8")
    command = message.split()
    
    if command[0] == 'GET':
        #parse question 
        split = command[1].split('=')
	    
        if len(split) != 3: #bad format 
           return  ERR_BAD_REQ 

        if command[2] != 'HTTP/1.1':
            return  ERR_BAD_REQ 

        if (split[0].split('?'))[0] != '/resolve': # missing resolve
           return  ERR_BAD_REQ 

        typ = split[2] 
        split = split[1].split('&type') #get name
        name = split[0]

        answer = get(typ,name)

        if answer == 0:
            return  ERR_NOT_FOUND 
        elif answer == ERR_BAD_REQ:
            return  ERR_BAD_REQ 
        else:
            return  ERR_OK + str(len(answer.encode('utf-8'))) + '\r\n\r\n' + answer

    elif command[0] == 'POST':

        if command[1] != '/dns-query':
            return  ERR_BAD_REQ 

        if command[2] != 'HTTP/1.1':
            return  ERR_BAD_REQ 

        body = message.split('\r\n\r\n')

        return post(body)
        
    else: #command other than get and post
        return  ERR_COMM 
    

##################### MAIN #####################
argc = len(sys.argv)

HOST = sys.argv[1] #'127.0.0.1'
PORT = int(sys.argv[2])

if not 0 <= PORT <= 65535:
    print ('Port number must be in range 0-65535.')
    sys.exit(1)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST,PORT))
    print('server is running')
    s.listen(1)
    while True:
        print('waiting for connection')
        try:
            conn, addr = s.accept()
        except KeyboardInterrupt:
            print(' server shutdown')
            sys.exit(0)
            
        with conn:
            print('Connection from',addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                answer = get_answer(data)
                msg_back = bytearray(answer,'utf-8')
                conn.sendall(msg_back)
