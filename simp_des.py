#DES
class SimplifiedDES:
    # https://en.wikipedia.org/wiki/DES_supplementary_material
    # https://ziaullahrajpoot.medium.com/data-encryption-standard-des-dc8610aafdb3
    # Initial and final permutation for plaintext/ciphertext
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Final Permutation Table
    IP_INV = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    
    # P-box permutation
    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]
    
    # PC-1 permutation table (key permutation)
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    # PC-2 permutation table (compression permutation)
    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    
    # S-boxes
    S = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    def __init__(self, key):
        self.key = key
        self.subkeys = self.subkey_gen()
        
    def bytes_bits(self, data):
        bits = []
        for bit in data:
            for i in range(7, -1, -1):
                bits.append((bit >> i) & i)
        return bits
    
    def bits_bytes(self, data):
        bits = []
        for i in range(0, len(data), 8):
            bit = 0
            for j in range(8):
                if i + j < len(data):
                    bit |= bits[i+j] << (7 - j)
            bits.append(bit)
        return bytes(bits)
        
    def permute(self, input_bits, permutation_table):
        return [input_bits[i-1] for i in permutation_table]

    def shift_left(self, bits, n):
        return bits[n:] + bits[:n] # circular

    def subkey_gen(self):
        # how you represent l or r
        shift_schema = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        
        key_bits = self.bytes_bits(self.key)
        perm_key = [key_bits[i-1] for i in self.PC1]
        
        # 56 / 2 = 28
        # l = first half, r = second half
        l = perm_key[:28]
        r = perm_key[28:]
        
        subkeys = []
        for shift in shift_schema:
            l = l[shift:] + l[:shift]
            r = r[shift:] + r[:shift]
            
            lr = l + r
            subkey = [lr[i-1] for i in self.PC2]
            subkeys.append(subkey)

    def feistel(self, data, subkey):
        # https://en.wikipedia.org/wiki/Data_Encryption_Standard
        # Expansion: expand 4 bits to 8 bits
        expanded = [data[i-1] for i in self.E]
        
        # XOR with subkey
        xored = [expanded[i] ^ subkey[i] for i in range(48)]
        
        sbox_output = []
        # S-box substitution
        for i in range(8):
            block = xored[i * 6 : (i+1) * 6]
            r = (block[0] << 1) + block[5]
            c = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
            x = self.S[i][r][c]
            sbox_output += [(x >> (3-j)) & 1 for j in range(4)]
        
        # p-box black magic
        permuted = [sbox_output[i-1] for i in self.P]
        return permuted

    def encrypt_block(self, plaintext):
        # plaintext MUST BE 64 BITS
        bits = self.bytes_bits(plaintext)
        permuted = [bits[i-1] for i in self.IP]
        
        left = permuted[:32]
        right = permuted[32:]
        
        # 16 rounds here, deprecating old one_round func
        for i in range(16):
            l = right.copy()
            r = self.feistel(right, self.subkeys[i])
            
            r = [left[j] ^ r[j] for j in range(32)]
            left, right = l, r
        
        lr = left + right
        c = [lr[i-1] for i in self.IP]
        return self.bits_bytes(c)

    def decrypt_block(self, ciphertext):
        # plaintext MUST BE 64 BITS
        bits = self.bytes_bits(ciphertext)
        permuted = [bits[i-1] for i in self.IP]
        
        left = permuted[:32]
        right = permuted[32:]
        
        # 16 rounds here, deprecating old one_round func
        # copied from ENCRYPT so is in reverse order!
        for i in range(15, -1, -1):
            r = left.copy()
            l = self.feistel(left, self.subkeys[i])
            
            l = [right[j] ^ l[j] for j in range(32)]
            left, right = l, r
        
        rl = right + left
        p = [rl[i-1] for i in self.IP_INV]
        return self.bits_bytes(p)
    
    def xor(self, a, b):
        return [x^y for x, y in zip(a, b)]
    
    # mac stuff goes here ig?
    # wtf how do i impl this
    # https://gist.github.com/TomCorwine/88090a64dc62c2610ce6d55d832766b0
    # https://www.naukri.com/code360/library/cbc-mac-in-cryptography
    def get_mac(self, payload):
        iv = [0] * 64
        
        before = iv
        message = message.encode()
        
        len_pad = 8 - (len(message) % 8)
        message += bytes([len_pad] * len_pad)
        blocks = [message[payload[i:i+8]] for i in range(0, len(message), 8)]
        
        for block in blocks:
            bits = []
            for bit in block:
                bits.extend([int(b) for b in f"{bit:08b}"])
                
            xor = self.xor(bits, before)
            enc = self.encrypt_block(xor)
            before = enc
            
        mac = bytes(int(''.join(map(str, before[i:i+8])), 2) for i in range(0, 64, 8))
        return mac