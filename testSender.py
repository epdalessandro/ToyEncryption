from testServer import sendData, decrypt_message
from encrypt import AES_Encryption
import socket
import time
import secrets

def main():
    HOST = "127.0.0.1"
    PORT = 7400

    # Encrypt message
    cipherKey = "740_IS_THE_BEST!".encode("utf-8") # TODO: Change to random bytes
    hmacKey = "740_IS_THE_BEST!".encode("utf-8") # TODO: Change to random bytes
    period = 8

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        # Here to show how messages in the same window can be decoded, but outside cannot
        counter = 1
        while(counter < 8):
            nonce = secrets.token_bytes(16)
            aes = AES_Encryption(cipherKey, hmacKey, nonce, period)
            print(f"Counter = {int(time.time() / period)}")
            message = ("Happy Pi Day: " + str(counter)).encode("utf-8")
            ciphertext, nonce_used, mac = aes.encrypt_and_get_metadata(message)

            messageHeader = (len(ciphertext) + len(nonce_used) + len(mac)).to_bytes(4, "big", signed=False)
            bytesToSend = messageHeader + mac + nonce_used + ciphertext
            
            sendData(sock, bytesToSend)
            counter += 1

if __name__ == "__main__":
    main()