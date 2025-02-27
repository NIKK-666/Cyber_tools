import socket
import threading

HOST="127.0.0.1"
PORT=12345

def receive_messages(client_socket):
    while True:
        try:
            message=client_socket.recv(1024).decode("utf-8")
            if message:
                print("\n"+message)
            else:
                break
        except:
            print("Connection lost.")
            client_socket.close()
            break

def send_messages(client_socket):
    while True:
        message=input("")
        if message.lower()=="exit":
            client_socket.close()
            break
        client_socket.send(message.encode("utf-8"))

def start_client():
    client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client_socket.connect((HOST,PORT))

    print("[CONNECTED] Type your message. Type 'exit' to leave.")


    receive_thread=threading.Thread(target=receive_messages,args=(client_socket,))
    send_thread = threading.Thread(target=send_messages, args=(client_socket,))

    receive_thread.start()
    send_thread.start()

if __name__== "__main__" :
    start_client()
