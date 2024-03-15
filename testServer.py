from encrypt import AES_Encryption
import time
import socket

def sendData(sock: socket, data: bytes):
    try:
        sock.sendall(data)
    except Exception as exception: 
        print(f"Error transmitting data: {exception}")

def receiveData(sock: socket, totalBytesToReceive: int, dataArray: bytearray) -> bytearray:
    while(len(dataArray) < totalBytesToReceive):
        # Receive the rest of the bytes
        dataBytes = sock.recv(totalBytesToReceive - len(dataArray))
        dataArray.extend(dataBytes)
    return dataArray

def parseData(receivedData: bytearray, totalBytes: int):
    mac = receivedData[0:32]
    nonce = receivedData[32:48]
    ciphertext = receivedData[48:totalBytes]
    return ciphertext, nonce, mac

def decrypt_message(ciphertext: bytes, receivedMac: bytes, cipherKey: bytes, 
                    hmacKey: bytes, receivedNonce: bytes, period: int):
    newAes = AES_Encryption(cipherKey, hmacKey, receivedNonce, period)
    msg = newAes.verify_and_decrypt_message(ciphertext, receivedMac)
    if(msg == None): 
        print(f"Message could not be verified {receivedMac}")
    else:
        msgString = msg.decode("utf-8")
        print(f"Message: {msgString}")

def main():
    HOST = "127.0.0.1"
    PORT = 7400
    COMMAND_LENGTH_PARAMETER_SIZE = 4

    cipherKey = "740_IS_THE_BEST!".encode("utf-8") # TODO: Change to random bytes
    hmacKey = "740_IS_THE_BEST!".encode("utf-8") # TODO: Change to random bytes
    PERIOD = 8 #s

    # Create the socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)

        print(f"Server started on port {PORT}.")
        client_socket, client_address = sock.accept()
        print(f"Client connected: {client_address}")

        receivedData = bytearray()
        numMessageBytes = 0
        counter = 0
        while True:
            # Have not yet received enough bytes to parse length parameter
            while(len(receivedData) < COMMAND_LENGTH_PARAMETER_SIZE):
                data = client_socket.recv(COMMAND_LENGTH_PARAMETER_SIZE - len(receivedData))
                receivedData.extend(data)
            
            # Get number of message bytes
            numMessageBytes = int.from_bytes(data, "big", signed=False)
            receivedData.clear()
            
            print(f"{numMessageBytes} bytes received")
            receivedData = receiveData(client_socket, numMessageBytes, receivedData)
            ciphertext, nonce, mac = parseData(receivedData, numMessageBytes)
            receivedData = receivedData[numMessageBytes:] # Chop off the bytes we processed

            time.sleep(1) # Wait before we try to verify and decrypt
            print(f"Counter = {int(time.time() / PERIOD)}")
            decrypt_message(ciphertext, mac, cipherKey, hmacKey, nonce, PERIOD)
            counter += 1
            

if __name__ == "__main__":
    main()