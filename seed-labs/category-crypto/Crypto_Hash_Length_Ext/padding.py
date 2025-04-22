import binascii

def calculate_sha256_padding(message):
    """
    Calculate SHA-256 padding for a given message
    Returns the padding bytes and URL-encoded padding
    """
    # Calculate original message length in bytes
    original_length = len(message.encode('utf-8'))
    
    # SHA-256 padding format:
    # 1. Append 0x80
    # 2. Append zeros until length ≡ 56 mod 64
    # 3. Append original bit length as 8-byte big-endian
    
    # Calculate padding length
    padding_length = (56 - (original_length + 1) % 64) % 64
    
    # Construct padding
    padding = b'\x80' + (b'\x00' * padding_length)
    
    # Append original message length in bits (big-endian)
    bit_length = original_length * 8
    padding += bit_length.to_bytes(8, byteorder='big')
    
    return padding

# Original message
message = "123456:myname=Cardoso&uid=1001&lstcmd=1"

# Calculate padding
padding = calculate_sha256_padding(message)

# Print results
print("Original message length:", len(message.encode('utf-8')), "bytes")
print("Raw padding bytes:", padding)
print("Hex representation:", binascii.hexlify(padding).decode('utf-8'))
print("URL-encoded padding:", ''.join(f'%{byte:02x}' for byte in padding))