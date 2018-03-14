#!/usr/bin/env python
import socket
import json


def connect():
    TCP_IP = '127.0.0.1'
    TCP_PORT = 6969
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    return s

def receive_and_close(sock):
    BUFFER_SIZE = 1024
    data = sock.recv(BUFFER_SIZE)
    sock.close()
    response = json.loads(data)
    return response

def get_secret(key):
    sock = connect()
    message = json.dumps({"action":"get", "key":key})
    sock.send(message)
    response = receive_and_close(sock)
    if response["result"] == "ok":
        return response["value"]
    return ""

def set_secret(key, secret):
    sock = connect()
    message = json.dumps({"action":"set", "key":key, "value":secret})
    sock.send(message)
    response = receive_and_close(sock)
    if response["result"] == "ok":
        return "secret set"
    return "secret NOT set"



def main():
    print set_secret("python_test", "this python test was good :)")
    print get_secret("python_test")

if __name__ == "__main__":
    main()
