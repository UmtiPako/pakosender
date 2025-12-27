import json
import argparse
import os
import shlex
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from spake2 import SPAKE2_A, SPAKE2_B


class Contact:
    def __init__(self, name, ip_addr):
        self.name = name
        self.ip_addr = ip_addr

    def __repr__(self):
        return f"\n\t{self.name}, IP: {self.ip_addr}"

def load_contacts():
    try:
        with open("contacts.json", "r") as data:
            devices_dict = json.load(data)
            return [Contact(item['name'], item['ip_addr']) for item in devices_dict]
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def add_contact(name: str, ipv4: str):
    devices = load_contacts() 
    new_contact = Contact(name, ipv4)
    devices.append(new_contact)
    
    with open("contacts.json", 'w') as f:
        json_data = [{"name": c.name, "ip_addr": c.ip_addr} for c in devices]
        json.dump(json_data, f, indent=4)
    
    print(f"[+] {name} added to contacts.")

def send(file_path, passcode):
    shared_psc = passcode.encode('utf-8')
    sender = SPAKE2_A(shared_psc)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 9000)) 
    s.listen(1)
    print(f"[*] LISTENING on port 9000... Passcode: {passcode}")
    
    conn, addr = s.accept()
    print(f"[+] CONNECTION from: {addr}")

    conn.send(sender.start())
    received_msg = conn.recv(1024)
    key = sender.finish(received_msg) 
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) 
    conn.send(nonce) 
    print("[+] KEY established and ENCRYPTION initialized.")

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    header = f"{file_name}:{file_size}".encode('utf-8')
    enc_header = aesgcm.encrypt(nonce, header, None)
    
    conn.send(len(enc_header).to_bytes(4, 'big'))
    conn.send(enc_header)
    
    conn.recv(1024)

    print(f"[*] SENDING ENCRYPTED: {file_name} ({file_size} bytes)")
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(128 * 1024) 
            if not chunk: break
            
            chunk_nonce = os.urandom(12)
            enc_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)
            conn.sendall(len(enc_chunk).to_bytes(4, 'big'))
            conn.sendall(enc_chunk)
            conn.sendall(chunk_nonce)
            
    print("[✓] TRANSFER COMPLETE.")
    conn.close()
    s.close()

def receive(target_ip, passcode):
    shared_psc = passcode.encode('utf-8')
    receiver = SPAKE2_B(shared_psc)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] CONNECTING to {target_ip}:9000...")
    s.connect((target_ip, 9000))

    msg = s.recv(1024)
    s.send(receiver.start())
    key = receiver.finish(msg)

    aesgcm = AESGCM(key)
    header_nonce = s.recv(12)
    print("[+] SECURE connection established.")

    h_len = int.from_bytes(s.recv(4), 'big')
    enc_header = s.recv(h_len)
    header = aesgcm.decrypt(header_nonce, enc_header, None).decode('utf-8')
    
    file_name, file_size = header.split(":")
    file_size = int(file_size)
    s.send(b"READY")

    print(f"[*] RECEIVING & DECRYPTING: {file_name}")
    with open(f"received_{file_name}", "wb") as f:
        received_bytes = 0
        while received_bytes < file_size:
            len_data = s.recv(4)
            if not len_data: break
            chunk_len = int.from_bytes(len_data, 'big')
            
            enc_chunk = b""
            while len(enc_chunk) < chunk_len:
                remaining = chunk_len - len(enc_chunk)
                enc_chunk += s.recv(remaining)
            
            chunk_nonce = s.recv(12)
            chunk = aesgcm.decrypt(chunk_nonce, enc_chunk, None)
            f.write(chunk)
            received_bytes += len(chunk)
            print(f"Progress: {received_bytes}/{file_size}", end="\r")

    print(f"\n[✓] DONE. File saved as 'received_{file_name}'")
    s.close()

def main():
    devices = load_contacts()
    parser = argparse.ArgumentParser(prog="pako")
    subparsers = parser.add_subparsers(dest="command")

    send_p = subparsers.add_parser("send")
    send_p.add_argument("-f", "--file", required=True)
    send_p.add_argument("-pw", "--password", required=True)

    recv_p = subparsers.add_parser("receive")
    recv_p.add_argument("-t", "--target", required=True) 
    recv_p.add_argument("-pw", "--password", required=True)

    subparsers.add_parser("contacts")

    add_contact_p = subparsers.add_parser("add-contact")
    add_contact_p.add_argument("-n","--name",required=True)
    add_contact_p.add_argument("-i","--ip",required=True)

    subparsers.add_parser("exit")

    while True:
        try:
            cmd = input("\npako > ").strip()
            if not cmd: continue
            args = parser.parse_args(shlex.split(cmd))

            if args.command == "send":
                send(args.file, args.password)
            
            elif args.command == "receive":
                contact = next((c for c in devices if c.name == args.target), None)
                if contact:
                    receive(contact.ip_addr, args.password)
                else:
                    print("[!] Contact information is wrong.")

            elif args.command == "add-contact":
                add_contact(args.name, args.ip)
                devices = load_contacts()

            elif args.command == "contacts":
                print(devices)
            
            elif args.command == "exit": break

        except SystemExit: continue
        except KeyboardInterrupt: break

if __name__ == "__main__":
    main()