import socket
import threading

HOST="127.0.0.1"
PORT=12345

clients=[]

def handle_client(client_socket,address):
    print(f"[NEW CONNECTION] {address} connected.")

    while True:
        try:
            message=client_socket.recv(1024).decode("utf-8")
            if message:
                print(f"{address} says: {message}")
                broadcast(message,client_socket)
            else:
                remove_client(client_socket)
                break
        except:
            remove_client(client_socket)
            break


def broadcast(message,sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode("utf-8"))
            except:
                remove_client(client)


def remove_client(client_socket):
    if client_socket in clients:
        print(f"[DISCONNECTED] {client_socket.getpeername()} left the chat.")
        clients.remove(client_socket)
        client_socket.close()


def start_server():
    server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server_socket.bind((HOST,PORT))
    server_socket.listen()

    print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")

    while True:
        client_socket,address=server_socket.accept()
        clients.append(client_socket)
        thread=threading.Thread(target=handle_client,args=(client_socket,address))
        thread.start()

if __name__=="__main__":
    start_server()
