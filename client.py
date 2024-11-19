from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import socket
import ssl
import hashlib
import threading
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import customtkinter as ctk
import time

# AES and RSA keys generation
key = RSA.generate(2048)
rsa_pub = key.publickey().export_key()
rsa_priv = key.export_key()

rsa_event = threading.Event()
ui_loaded = False

# Server's public key
serv_key = ''

# Variables
hostname = "YOUR_SERVER_HOSTNAME"
server_ip = "SERVER-PUBLIC-IP"
server_port = 777 # YOUR_SERVER_PORT

# Normalize keys after exchange
def normalize_key(key):
    return key.replace("\n", "").replace(" ", "").replace("\t", "")

# Get public key from certificate
def get_public_key_from_cert(cert):
    cert = x509.load_der_x509_certificate(cert, default_backend())
    public_key = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key

# Send RSA public key to server
# Key is sent to server only after another user connection
def rsa_send(sock):
    retries = 0
    while retries < 5:
        try:
            sock.send(rsa_pub)
            break
        except Exception:
            retries += 1
            continue

# Recieving session AES key from server
def rsa_resolve(sock):
    recv_aes = sock.recv(2048)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_priv))
    global aes_key
    aes_key = cipher_rsa.decrypt(recv_aes)

# Pad message to be multiple of 16 bytes
def pad_msg(msg):
    while len(msg) % 16 != 0:
        msg += ' '
    return msg

# Encrypt message with AES
def encrypt_msg(msg):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    encrypt_bytes = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size))
    return iv + encrypt_bytes

# Decrypt message with AES
def decrypt_msg(msg):
    iv = msg[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypt_bytes = cipher.decrypt(msg[16:])
    return unpad(decrypt_bytes, AES.block_size).decode('utf-8').strip()

# UI function to display message
def display_msg(msg, sender):
    textbox.configure(state="normal")
    textbox.insert(ctk.END, f"[{sender}]: {msg}\n")
    textbox.configure(state="disabled")
    textbox.see(ctk.END)

# Sending encrypted message to the server
def send_msg():
    msg = msg_entry.get().strip()
    if msg:
        encrypted_msg = encrypt_msg(msg)
        serv_socket.sendall(encrypted_msg)
        msg_entry.delete(0, ctk.END)
        display_msg(msg, "You")

# Stopping thread for receiving messages
def stop_get_msg():
    global stop_thread
    stop_thread = True

# Receiving messages from the server
def get_msg():
    global ui_loaded, stop_thread
    stop_thread = False

    while not ui_loaded:
        threading.Event().wait(0.1)

    while not stop_thread:
        try:
            msg = serv_socket.recv(1024)
            if msg and msg != b'CONN' and msg != b'OPD':
                display_msg(decrypt_msg(msg), "Broski")
            elif msg == b'OPD':
                display_msg("Broski disconnected", "SERVER")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
        
# Connection to the server
def connect():
    display_msg("Connection proccess initialized...", "SERVER")

    global client_socket, serv_socket
    
    try:
        # Creating a socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connecting to the server via SSL with self-signed certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssl_socket = context.wrap_socket(client_socket, server_hostname=hostname, do_handshake_on_connect=True)

        ssl_socket.connect((server_ip, server_port))
        serv_cert = ssl_socket.getpeercert(True)
        serv_pub_key = get_public_key_from_cert(serv_cert)

        # Converting the key to single line string
        norm_serv_key = normalize_key(serv_key)
        norm_serv_pub_key = normalize_key(serv_pub_key.decode('utf-8'))

        if norm_serv_key == norm_serv_pub_key:
            threading.Thread(target=rsa_resolve, args=(serv_socket,)).start()
            rsa_event.wait()
            send_thread = threading.Thread(target=send_msg, args=(ssl_socket,))
            send_thread.start()
    
            while True:
                try:
                    msg = ssl_socket.recv(1024)
                    print(f"Received (encrypted): {decrypt_msg(msg)}")
                except Exception as e:
                    print(f"Error receiving message: {e}")
                    break

            send_thread.join(timeout=1)
            ssl_socket.close()
        else:
            print("Public key mismatch. Closing connection.")
            ssl_socket.close()
    except Exception as e:
        display_msg(f"Error connecting: {e}", "SERVER")
        time.sleep(10)
        close_app()

# Closing the app on quit
def close_app():
    global serv_socket, root

    stop_get_msg()

    try:
        serv_socket.shutdown(socket.SHUT_RDWR)
        serv_socket.close()
    except Exception as e:
        print(f"Error closing socket: {e}")

    root.quit()
    root.destroy()

# Resetting the server ip and port entries
def reset():
    global ip_entry, port_entry
    ip_entry.delete(0, ctk.END)
    ip_entry.insert(0, server_ip)
    port_entry.delete(0, ctk.END)
    port_entry.insert(0, server_port)

# Loading server ip and port choice UI
def load_server_ui():
    global ip_entry, port_entry, ip_label, port_label, connect_btn, reset_btn

    ip_label.grid(row=0, column=0, padx=5, pady=(10, 0))
    port_label.grid(row=0, column=1, padx=5, pady=(10, 0))
    ip_entry.grid(row=2, column=0, padx=5, pady=(0, 10))
    port_entry.grid(row=2, column=1, padx=5, pady=(0, 10))
    connect_btn.grid(row=3, column=0, columnspan=2, pady=(10, 0))
    reset_btn.grid(row=4, column=0, columnspan=2, pady=5)

# Loading chat UI
def load_chat_ui():
    global ip_entry, port_entry, ip_label, port_label, connect_btn, reset_btn, root

    ip = ip_entry.get().strip()
    port = port_entry.get().strip()

    if not ip or not port:
        return

    root.title("TCP-SEND | Chat")
    ip_label.destroy()
    port_label.destroy()
    ip_entry.destroy()
    port_entry.destroy()
    connect_btn.destroy()
    reset_btn.destroy()

    quit_btn.pack(side=ctk.TOP, padx=10, pady=10)
    textbox.pack(expand=True, fill='both', padx=15, pady=15)
    msg_entry.pack(side=ctk.LEFT, expand='True', fill='x', padx=10, pady=10)
    send_btn.pack(side=ctk.RIGHT, fill='x', padx=10, pady=10)

    try:
        threading.Thread(target=connect).start()
    except Exception as e:
        display_msg(f"{e}", "SERVER ERROR")
        time.sleep(10)
        quit_btn.pack_forget()
        textbox.pack_forget()
        msg_entry.pack_forget()
        send_btn.pack_forget()
        return

# Loading the UI
def main():
    global msg_entry, textbox, root, ip_entry, port_entry, connect_btn, reset_btn, send_btn, quit_btn, ip_label, port_label

    root = ctk.CTk()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")

    root.title("TCP-SEND | Server Choice")

    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    window_w = int(screen_w / 2)
    window_h = int(screen_h / 2)
    root.geometry(f"{window_w}x{window_h}")

    #Chat UI:
    quit_btn = ctk.CTkButton(root, text="Disconnect", command=close_app)

    textbox = ctk.CTkTextbox(root, wrap="word", cursor="arrow")
    textbox.configure(state="disabled")    

    msg_entry = ctk.CTkEntry(root, placeholder_text="Message", placeholder_text_color="grey")

    send_btn = ctk.CTkButton(root, text="Send", command=send_msg)

    #Server ip choice UI:
    ip_label = ctk.CTkLabel(root, text="Server IP:")
    port_label = ctk.CTkLabel(root, text="Server Port:")

    ip_entry = ctk.CTkEntry(root, placeholder_text="Server IP", placeholder_text_color="grey")
    ip_entry.insert(0, server_ip)

    port_entry = ctk.CTkEntry(root, placeholder_text="Server Port", placeholder_text_color="grey")
    port_entry.insert(0, server_port)

    connect_btn = ctk.CTkButton(root, text="Connect", command=load_chat_ui)
    reset_btn = ctk.CTkButton(root, text="Set to default", command=reset)

    load_server_ui()

    root.bind("<Return>", lambda e: send_msg())
    
    root.mainloop()
    
if __name__ == "__main__":
    main()