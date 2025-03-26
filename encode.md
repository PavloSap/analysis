rom Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class AESCipher:
    def __init__(self, key: str):
        self.key = key.encode('utf-8')

    def encrypt(self, data: str) -> str:
        cipher = AES.new(self.key, AES.MODE_CBC, self.key[:16])
        encrypted_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + encrypted_bytes).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        raw_data = base64.b64decode(encrypted_data)
        cipher = AES.new(self.key, AES.MODE_CBC, raw_data[:16])
        decrypted_bytes = unpad(cipher.decrypt(raw_data[16:]), AES.block_size)
        return decrypted_bytes.decode('utf-8')

# Example usage
if __name__ == "__main__":
    key = "thisisaverysecretkey!"  # Must be 16, 24, or 32 bytes long
    aes = AESCipher(key)
    
    message = "Hello, Crypto!"
    encrypted_message = aes.encrypt(message)
    decrypted_message = aes.decrypt(encrypted_message)
    
    print(f"Original: {message}")
    print(f"Encrypted: {encrypted_message}")
    print(f"Decrypted: {decrypted_message}")
