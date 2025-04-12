#DES based MAC (DAA, Data Authentication Algorithm)
class SimplifiedDES:
    # Initial permutation tables
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    P4 = [2, 4, 3, 1]
    
    # Initial and final permutation for plaintext/ciphertext
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]
    
    S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    def __init__(self, key):
        self.key = key
        self.subkeys = self.subkey_gen()

    def permute(self, input_bits, permutation_table):
        return [input_bits[i-1] for i in permutation_table]

    def shift_left(self, bits, n):
        return bits[n:] + bits[:n] # circular
    
    def xor(self, a, b):
        return [x ^ y for x, y in zip(a, b)]

    def subkey_gen(self):
        key = self.permute(self.key, self.P10)
        
        # Split into two halves
        left = key[:5]
        right = key[5:]
        
        # First round - shift both halves left by 1
        left = self.shift_left(left, 1)
        right = self.shift_left(right, 1)
        key1 = self.permute(left + right, self.P8)
        
        # Second round - shift both halves left by 2
        left = self.shift_left(left, 2)
        right = self.shift_left(right, 2)
        key2 = self.permute(left + right, self.P8)
        
        return [key1, key2]

    def feistel(self, right_half, subkey):
        # Expansion: expand 4 bits to 8 bits
        expanded = [
            right_half[3], right_half[0], 
            right_half[1], right_half[2],
            right_half[1], right_half[2],
            right_half[3], right_half[0]
        ]
        
        # XOR with subkey
        xored = [a ^ b for a, b in zip(expanded, subkey)]
        
        # Split into two parts for S-boxes
        left = xored[:4]
        right = xored[4:]
        
        # S-box substitution
        row_s0 = (left[0] << 1) | left[3]
        col_s0 = (left[1] << 1) | left[2]
        row_s1 = (right[0] << 1) | right[3]
        col_s1 = (right[1] << 1) | right[2]
        
        s0_output = self.S0[row_s0][col_s0]
        s1_output = self.S1[row_s1][col_s1]
        
        # Convert to binary
        s0_bits = [(s0_output >> 1) & 1, s0_output & 1]
        s1_bits = [(s1_output >> 1) & 1, s1_output & 1]
        
        return self.permute(s0_bits + s1_bits, self.P4)

    def one_round(self, block, key):
        left = block[:4]
        right = block[4:]
        
        # F function on right half
        f_output = self.feistel(right, key)
        
        # XOR with left half
        new_right = [a ^ b for a, b in zip(left, f_output)]
        
        # Return right half as new left, original right becomes new right
        return right + new_right

    def encrypt_block(self, plaintext):
        state = self.permute(plaintext, self.IP)
        
        # Two rounds of Feistel network
        state = self.one_round(state, self.subkeys[0])
        state = self.one_round(state, self.subkeys[1])
        
        # Swap last time
        state = state[4:] + state[:4]
        return self.permute(state, self.IP_INV)

    def decrypt_block(self, ciphertext):
        state = self.permute(ciphertext, self.IP)
        
        # Two rounds of Feistel network with keys in reverse order
        state = self.one_round(state, self.subkeys[1])
        state = self.one_round(state, self.subkeys[0])
        
        # Swap last time
        state = state[4:] + state[:4]
        return self.permute(state, self.IP_INV)
    
def test_simplified_des():
    key = [1, 1, 0, 0, 0, 1, 1, 1, 1, 0]
    plaintext = [0, 0, 1, 0, 1, 0, 0, 0]
    
    des = SimplifiedDES(key)
    
    ciphertext = des.encrypt_block(plaintext)
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    
    decrypted = des.decrypt_block(ciphertext)
    print(f"Decrypted:  {decrypted}")
    
    assert decrypted == plaintext, "Decryption failed!"

def generate_mac(message, key):
    sdes = SimplifiedDES(key)
    iv = [0] * 8  # IV=0
    previous = iv
    # Convert to 8-bit ASCII
    blocks = []
    for char in message:
        bits = [int(b) for b in format(ord(char), '08b')]
        blocks.append(bits)
    for block in blocks:
        xored = sdes.xor(block, previous)
        encrypted = sdes.encrypt_block(xored)
        previous = encrypted
    return previous

def birthday_attack(original_mac_, target_message, key, max_attempts=256):
    _ = SimplifiedDES(key)
    for i in range(max_attempts):
        # add random
        fraudulent_msg_ = target_message + chr(i % 256)
        # MAC for fraudulent message
        fraudulent_mac_ = generate_mac(fraudulent_msg_, key)
        if fraudulent_mac_ == original_mac_:
            print(f"Collision found after {i+1} attempts!")
            return fraudulent_msg
    return None

# Shared secret key (10 bits)
KEY = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]  # Binary: 1010000010

# Original legitimate message
ORIGINAL_MSG = "deposit 1000 dollars"
print(f"Original message: {ORIGINAL_MSG}")

# Generate original MAC
original_mac = generate_mac(ORIGINAL_MSG, KEY)
print(f"Original MAC: {original_mac}")

# Target fraudulent message
TARGET_MSG = "withdraw 1000 dollars"
print("\nStarting birthday attack...")

# Perform attack
fraudulent_msg = birthday_attack(original_mac, TARGET_MSG, KEY)

if fraudulent_msg:
    print("\nSuccessful attack!")
    print(f"Fraudulent message: {fraudulent_msg}")
    print(f"Valid MAC: {generate_mac(fraudulent_msg, KEY)}")
else:
    print("Attack failed - no collision found")