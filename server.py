import socket
import threading

clients = []

def handle_client(client_socket, client_address):
    print(f"Client {client_address} connected")
    
    rsa_msg = client_socket.recv(2048)
    for client in clients:
        if client != client_socket:
            try:
                client.send(rsa_msg)
            except Exception as e:
                print(e)
                remove_client(client_socket)

    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                print(f"Received message from {client_address}:")
                broadcast(message, client_socket)
            else:
                remove_client(client_socket)
                break
        except Exception as e:
            print(e)
            remove_client(client_socket)
            break

def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except Exception as e:
                print(e)
                remove_client(client)

def remove_client(client_socket):
    if client_socket in clients:
        clients.remove(client_socket)
        client_socket.close()
        print(f"Client {client_socket} disconnected")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 510))
    server.listen(5)
    print("Server is listening...")

    while True:
        client_socket, client_address = server.accept()
        clients.append(client_socket)

        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    main()