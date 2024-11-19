import socket
import threading
import ssl
import time

# Self-signed certificate and private key
CERT = '/path/to/certificate.pem'
KEY = '/path/to/certificate/key.key'

#Storing clients in the list
clients = []

# Variables
port = 7777 # Server port, change if needed

# Function to handle client connections
def handle_client(client_socket, client_address):
    print(f"Client {client_address} connected")

    # If single user is connected, wait for another user to connect
    while len(clients) < 2:
        try:
            client_socket.send(b'WFOP')
            threading.Event().wait(1)
        except ssl.SSLEOFError as e:
            print(f"SSL EOF error occured: {e}")
        except Exception as e:
            print(e)
            continue

    # Notify the clients that the connection is established
    client_socket.send(b'CONN')
    # Reveiving the RSA public key from the client then sending it to admin
    rsa_msg = client_socket.recv(2048)
    for client in clients:
        if client != client_socket:
            try:
                client.send(rsa_msg)
            except Exception as e:
                print(e)
                remove_client(client_socket)

    # Getting messages from users, then broadcasting them to the other user
    # There is no encryption/decryption here for security reasons (encr/decr is handled on the client side)
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                print(f"Received message from {client_address}: ")
                broadcast(message, client_socket)
            else:
                remove_client(client_socket)
                break
        except Exception as e:
            print(e)
            remove_client(client_socket)
            break

# Function to broadcast messages to all clients
def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except Exception as e:
                print(e)
                remove_client(client)

# Function to remove clients on disconnect
def remove_client(client_socket):
    if client_socket in clients:
        clients.remove(client_socket)
        client_socket.close()
        for client in clients:
            if client != client_socket:
                client.send(b'OPD')
        print(f"Client {client_socket} disconnected")

# Function to start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(2)
    print("Server is listening...")

    # SSL context for self-signed certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT, keyfile=KEY)

    # Accepting clients and starting a new thread for each client
    while True:
        client_socket, client_address = server.accept()
        ssl_client = context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=True)
        clients.append(ssl_client)

        client_thread = threading.Thread(target=handle_client, args=(ssl_client, client_address))
        client_thread.start()

# Main function to start the server and handle errors
def main():
    while True:
        try:
            start_server()
        except Exception as e:
            print(f"Server error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
