# Padding Oracle Attack Lab

## Overview

This lab gave practical experience with padding oracle attacks, showing how simple error messages can be used to decrypt data without knowing the key. By working with oracle servers, we studied their responses to find valid padding and gradually uncovered a hidden message. The lab reinforced key ideas about secret-key encryption, encryption modes, and padding, revealing weaknesses in some cryptographic systems.

## Lab Tasks

### Getting Familiar with Padding

To understand how PKCS#7 padding works, We created three files with different lengths—5 bytes, 10 bytes, and 16 bytes. We then encrypted each file using AES-128 in CBC mode with OpenSSL and later decrypted them with the -nopad option to inspect the padding added. Finally, We used xxd to display the raw content of the decrypted files in hexadecimal format.
Steps Taken:

#### Creating files with different sizes:

```sh
echo -n "12345" > P1   # 5 bytes
echo -n "1234567890" > P2  # 10 bytes
echo -n "1234567890123456" > P3  # 16 bytes
```

#### Encrypting the files with AES-128-CBC:
```sh
openssl enc -aes-128-cbc -e -pbkdf2 -in P1 -out C1
openssl enc -aes-128-cbc -e -pbkdf2 -in P2 -out C2
openssl enc -aes-128-cbc -e -pbkdf2 -in P3 -out C3
```
#### Decrypting the files without removing the padding (-nopad option):
```sh
openssl enc -aes-128-cbc -d -pbkdf2 -nopad -in C1 -out P1_new
openssl enc -aes-128-cbc -d -pbkdf2 -nopad -in C2 -out P2_new
openssl enc -aes-128-cbc -d -pbkdf2 -nopad -in C3 -out P3_new


```
#### Viewing the decrypted files in hex format to examine padding:
```sh
$ xxd P1_new
$ xxd P2_new
$ xxd P3_new


00000000: 3132 3334 350b 0b0b 0b0b 0b0b 0b0b 0b0b  12345...........
00000000: 3132 3334 3536 3738 3930 0606 0606 0606  1234567890......
00000000: 3132 3334 3536 3738 3930 3132 3334 3536  1234567890123456
00000010: 1010 1010 1010 1010 1010 1010 1010 1010  ................

```
What padding is added to each file?
 - 5-byte file (P1) → 0x0B (11 times)
 - 10-byte file (P2) → 0x06 (6 times)
 - 16-byte file (P3) → 0x10 (16 times, full block padding)

Why does the 16-byte file have a full block of padding?

AES in CBC mode uses fixed-size blocks (16 bytes for AES-128). If the data fits perfectly, a full padding block is added to mark the end. This ensures OpenSSL can distinguish data from padding and remove it correctly during decryption.

### Padding Oracle Attack (Level 1)

The padding oracle attack exploits the system's response to invalid padding errors, allowing us to recover plaintext one byte at a time. The decryption process relies on modifying the second-to-last ciphertext block (C1) and using the oracle’s feedback to infer intermediate values (D2).

To do this we will use the follwing program:
```py
 oracle = PaddingOracle('localhost', 5000)

    # Get the IV + Ciphertext from the oracle
    iv_and_ctext = bytearray(oracle.ctext)
    IV    = iv_and_ctext[00:16]
    C1    = iv_and_ctext[16:32]  # 1st block of ciphertext
    C2    = iv_and_ctext[32:48]  # 2nd block of ciphertext
    print("C1:  " + C1.hex())
    print("C2:  " + C2.hex())

    D2 = bytearray(16)

    D2[0]  = C1[0]
    D2[1]  = C1[1]
    D2[2]  = C1[2]
    D2[3]  = C1[3]
    D2[4]  = C1[4]
    D2[5]  = C1[5]
    D2[6]  = C1[6]
    D2[7]  = C1[7]
    D2[8]  = C1[8]
    D2[9]  = C1[9]
    D2[10] = C1[10]
    D2[11] = C1[11]
    D2[12] = C1[12]
    D2[13] = C1[13]
    D2[14] = C1[14]
    D2[15] = C1[15]

    CC1 = bytearray(16)

    CC1[0]  = 0x00
    CC1[1]  = 0x00
    CC1[2]  = 0x00
    CC1[3]  = 0x00
    CC1[4]  = 0x00
    CC1[5]  = 0x00
    CC1[6]  = 0x00
    CC1[7]  = 0x00
    CC1[8]  = 0x00
    CC1[9]  = 0x00
    CC1[10] = 0x00
    CC1[11] = 0x00
    CC1[12] = 0x00
    CC1[13] = 0x00
    CC1[14] = 0x00
    CC1[15] = 0x00


    K = 1
    for i in range(256):
          CC1[16 - K] = i
          status = oracle.decrypt(IV + CC1 + C2)
          if status == "Valid":
              print("Valid: i = 0x{:02x}".format(i))
              print("CC1: " + CC1.hex())

    # Once you get all the 16 bytes of D2, you can easily get P2
    P2 = xor(C1, D2)
    print("P2:  " + P2.hex())

```
Step-by-step Decryption Process

1. Recovering D[15] (Last Byte of D2):
    - Set k=1 and run the program to iterate through all possible values (0x00 to 0xFF) for CC1[15].
    - The program will submit the modified ciphertext to the oracle.
    - The oracle responds with "Valid" when the manipulated ciphertext produces correct padding.
    - The valid `i` value obtained is then used to compute D[15] using:
       
            D[15]=i⊕0x01
   
    - Next, we update CC1[15] for k=2 using:
        
            CC1[15]=D[15]⊕0x02
 

2. Recovering D[14] (Second-to-Last Byte of D2D2):

    - Set k=2 and run the program to brute-force CC1[14] by trying all possible values.
    - The oracle returns "Valid" when correct padding is achieved.
    - Compute D[14] using:

            D[14]=i⊕0x02

    - Update CC1[15] and CC1[14] for k=3 using:

            CC1[15]=D[15]⊕0x03
            CC1[14]=D[14]⊕0x03

3. Repeating for the Rest of the Bytes:

    - This process is repeated for D[13], D[12], and so on.
    - At each step k, the padding value is k, and we update CC1 accordingly.
    - After recovering all 16 bytes of D2, we compute the plaintext block:

            P2=C1⊕D2


#### Recovered D2 Values:
```
    D2[10] = 0xec
    D2[11] = 0x45
    D2[12] = 0x1c
    D2[13] = 0xf1
    D2[14] = 0x3b
    D2[15] = 0xce
```
#### Decryption Output:
```sh
CC1: 00000000000000000000ea431af73dc8
P2:  00000000000000000000ccddee030303
```

The last three bytes (0x03) indicate PKCS#7 padding of 3 bytes, ensuring proper that the decryption is being done correctly.

### Automated Padding Oracle Attack (Level 1)

In this task, we automated the process of recovering both the first (P1) and second (P2) blocks of the plaintext using a padding oracle attack.
Step 1: Recovering P2 and D2 (Second Block)

To recover the second plaintext block (P2) and its corresponding decrypted block (D2), we created the following program, which implements the algorithm used in the previous task:


```py
  for K in range(1,17):
        print("K", K)
        valid_i =0
        for j in range(15,15-K +1, -1):            
            CC1[j] = D2[j] ^ K
        for i in range(256):
            CC1[16 - K] = i
            status = oracle.decrypt(IV + CC1 + C2)
            if status == "Valid":
                print("Valid: i = 0x{:02x}".format(i))
                print("CC1: " + CC1.hex())
                valid_i = i
        
        D2[16-K]= valid_i ^ K
```
#### Output:

```sh
$ ./automate_attack.py                                                                          
C1:  a9b2554b0944118061212098f2f238cd
C2:  779ea0aae3d9d020f3677bfcb3cda9ce
K 1
Valid: i = 0xcf
CC1: 000000000000000000000000000000cf
K 2
Valid: i = 0x39
CC1: 000000000000000000000000000039cc
K 3
Valid: i = 0xf2
CC1: 00000000000000000000000000f238cd
K 4
Valid: i = 0x18
CC1: 00000000000000000000000018f53fca
K 5
Valid: i = 0x40
CC1: 00000000000000000000004019f43ecb
K 6
Valid: i = 0xea
CC1: 00000000000000000000ea431af73dc8
K 7
Valid: i = 0x9d
CC1: 0000000000000000009deb421bf63cc9
K 8
Valid: i = 0xc3
CC1: 0000000000000000c392e44d14f933c6
K 9
Valid: i = 0x01
CC1: 0000000000000001c293e54c15f832c7
K 10
Valid: i = 0x6c
CC1: 0000000000006c02c190e64f16fb31c4
K 11
Valid: i = 0x29
CC1: 0000000000296d03c091e74e17fa30c5
K 12
Valid: i = 0x50
CC1: 00000000502e6a04c796e04910fd37c2
K 13
Valid: i = 0x02
CC1: 00000002512f6b05c697e14811fc36c3
K 14
Valid: i = 0x68
CC1: 00006801522c6806c594e24b12ff35c0
K 15
Valid: i = 0x9f
CC1: 009f6900532d6907c495e34a13fe34c1
K 16
Valid: i = 0xa8
CC1: a880761f4c327618db8afc550ce12bde
P2:  1122334455667788aabbccddee030303

```
Step 2: Recovering P1 and D1 (First Block)

Next, to recover the first block of plaintext (P1) and its corresponding decrypted block (D1), we follow a similar approach. This time, instead of modifying the ciphertext, we modify the IV and use the oracle’s feedback to determine the correct value for each byte of D1.

```py
D1 = bytearray(16)  # Initialize D1 (AES decryption of C1)
CC0 = bytearray(16) # Modified IV (like CC1 was modified C1)

for K in range(1, 17):  # For each byte (K=1 to K=16)
    # Set CC0[j] = D1[j] ^ K for j > (16-K)
    for j in range(16 - K + 1, 16):
        CC0[j] = D1[j] ^ K
    # Brute-force CC0[16-K]
    for i in range(256):
        CC0[16 - K] = i
        status = oracle.decrypt(CC0 + C1)  # Send modified IV + C1
        if status == "Valid":
            D1[16 - K] = i ^ K  # Recover D1 byte
            break

P1 = xor(IV, D1)  # P1 = IV ⊕ D1
print("P1:", P1.hex())
```
#### Output of the whole plaintext (in hex):
```sh
P1: 11223344556677881122334455667788
P2:  1122334455667788aabbccddee030303
```
### Padding Oracle Attack (Level 2)


In the Level-2 attack, the server returns a 64-byte ciphertext consisting of multiple blocks. By extending the same logic used for recovering P1 and P2 in Level 1, we can create a loop to calculate the plaintext for the third block (P3).
Step 1: Recovering P3

We begin by recovering the third block of plaintext (P3) and its corresponding decrypted block (D3). Here's the modified code to recover D3 using the oracle:

```py
D3 = bytearray(16)  # Initialize D3
CC2 = bytearray(16) # Modified C2

for K in range(1, 17):  # For each byte (K=1 to K=16)
    # Set CC2[j] = D3[j] ^ K for j > (16-K)
    for j in range(16 - K + 1, 16):
        CC2[j] = D3[j] ^ K
    # Brute-force CC2[16-K]
    for i in range(256):
        CC2[16 - K] = i
        status = oracle.decrypt(IV + C1 + CC2 + C3)  # Send IV + C1 + modified C2 + C3
        if status == "Valid":
            D3[16 - K] = i ^ K  # Recover D3 byte
            break
```
Step 2: Generalizing for Multiple Blocks

To make the code more flexible and capable of handling ciphertexts of any size, we can modify it to automatically determine the number of blocks and recover the plaintext for each block. The following code accomplishes this:

```py
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

```

#### Output for Level 1:
```sh
Decrypted plaintext: "3DUfw"3DUfw"3DUfw
Hex: 112233445566778811223344556677881122334455667788aabbccddee030303


```
#### Output for Level 2:
```sh
Decrypted plaintext: (^_^)(^_^) The SEED Labs are great! (^_^)(^_^)
Hex: 285e5f5e29285e5f5e29205468652053454544204c616273206172652067726561742120285e5f5e29285e5f5e290202

```