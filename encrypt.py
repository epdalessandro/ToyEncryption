from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import time

class AES_Encryption:
    cipher: AES
    cipherKey: bytes
    hmacKey: bytes
    period: int # seconds

    def __init__(self, _cipherKey, _hmacKey, _nonce, _period):
        self.cipherKey = _cipherKey
        self.hmacKey = _hmacKey
        self.cipher = AES.new(self.cipherKey, AES.MODE_EAX, nonce=_nonce)
        self.period = _period

    def encrypt_and_get_metadata(self, message: bytes): # -> tuple[bytes, bytes, bytes]:
        ciphertext = self.encrypt_data(message)
        return ciphertext, self.cipher.nonce, self.getTimeBasedOneTimePad(ciphertext)

    def encrypt_data(self, message: bytes) -> bytes:
        return self.cipher.encrypt(message)

    def decrypt_data(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(ciphertext)
    
    def getTimeBasedHashFunction(self, message: bytes) -> HMAC:
        counter = int(time.time() / self.period) # Time-based counter
        key = self.hmacKey + counter.to_bytes(8, "big", signed=False) # Key + counter bytes, unique for each period
        hmac = HMAC.new(key, digestmod=SHA256)
        hmac.update(message)
        return hmac
    
    def getTimeBasedOneTimePad(self, message: bytes):
        hmac = self.getTimeBasedHashFunction(message)
        return hmac.digest()
    
    def verify_message(self, message: bytes, receivedMAC: bytes) -> bool:
        try:
            hmac = self.getTimeBasedHashFunction(message)
            hmac.verify(receivedMAC)
            return True
        except ValueError:
            return False
        
    def verify_and_decrypt_message(self, ciphertext: bytes, receivedMAC: bytes):
        verified = self.verify_message(ciphertext, receivedMAC)

        if(verified):
            return self.decrypt_data(ciphertext)
        else: return None