#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()


if __name__ == "__main__":
    oracle = PaddingOracle('localhost', 6000)
    iv_and_ctext = bytearray(oracle.ctext)
    IV = iv_and_ctext[0:16]
    ciphertext_blocks = [iv_and_ctext[i:i+16] for i in range(0, len(iv_and_ctext), 16)]
    for i in range(len(ciphertext_blocks)):
        print("C"+str(i)+":  " + ciphertext_blocks[i].hex())

    P = bytearray()
    # Start from the first actual ciphertext block (after IV)
    for block_num in range(1, len(ciphertext_blocks)):
        D = bytearray(16)
        CC = bytearray(16)
        C_prev = ciphertext_blocks[block_num-1]  # Only need the immediate previous block
        C_current = ciphertext_blocks[block_num]
        
        for K in range(1, 17):  # For each byte in the block (padding from 1 to 16)
            print("K", K)
            # Set bytes we already know
            for j in range(15, 15-K+1, -1):
                CC[j] = D[j] ^ K
            
            # Brute-force current byte
            for i in range(256):
                CC[16 - K] = i
                status = oracle.decrypt(CC + C_current)  # Only need current manipulated block and next block
                if status == "Valid":
                    print("Valid: i = 0x{:02x}".format(i))
                    print("CC: " + CC.hex())
                    valid_i = i
                    break  # Found the correct byte
            
            D[16-K] = valid_i ^ K
        
        # XOR the intermediate D with the previous ciphertext block to get plaintext
        plaintext_block = xor(C_prev, D)
        P.extend(plaintext_block)

    print("Decrypted plaintext:", P.decode(errors='ignore'))
    print("Hex:", P.hex())
