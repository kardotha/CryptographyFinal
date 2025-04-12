# https://stackoverflow.com/questions/18815820/how-to-convert-string-to-binary

def text_to_bits(s):
    """Convert a string to a list of bits"""
    bits = []
    for char in s:
        byte = ord(char)
        bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
    return bits

# https://stackoverflow.com/questions/7396849/convert-binary-to-ascii-and-vice-versa

def bits_to_text(bits):
    """Convert a list of bits back to a string"""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            byte.extend([0] * (8 - len(byte)))  # Padding if needed
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

# https://stackoverflow.com/questions/57668289/implement-the-function-fast-modular-exponentiation
# DEPRECATED FOR pow(x1, x2, x3)
def mod_exp(b, exp, m):
    res = 1
    while exp > 1:
        if exp & 1:
            res = (res * b) % m
        b = b ** 2 % m
        exp >>= 1
    return (b * res) % m

def encrypt(M, n, x0):
    m_bits = text_to_bits(M)
    t = len(m_bits)
    
    x = x0
    pseudorandom_bits = []
    for _ in range(t):
        x = (x * x) % n
        pseudorandom_bits.append(x % 2)
    
    cipher_bits = [m_bits[i] ^ pseudorandom_bits[i] for i in range(t)]
    x_t_plus_1 = (x * x) % n
    
    return cipher_bits, x_t_plus_1

def decrypt(cipher_bits, x_t_plus_1, p, q, t):
    n = p * q
    d1 = pow((p + 1) // 4, t + 1, p - 1)
    d2 = pow((q + 1) // 4, t + 1, q - 1)
    
    u = pow(x_t_plus_1, d1, p)
    v = pow(x_t_plus_1, d2, q)
    
    # Using CRT
    x0 = (v * p * pow(p, q - 2, q) + u * q * pow(q, p - 2, p)) % n
    
    x = x0
    pseudorandom_bits = []
    for _ in range(len(cipher_bits)):
        x = (x * x) % n
        pseudorandom_bits.append(x % 2)
    
    plain_bits = [cipher_bits[i] ^ pseudorandom_bits[i] for i in range(len(cipher_bits))]
    return plain_bits

m = "NETSEC"
prime_p = 499
prime_q = 547
x_0 = 159201
n = prime_p * prime_q

ciphertext, x_final = encrypt(m, n, x_0)
print("Ciphertext:", ciphertext)
print("X:", x_final)

t = len(text_to_bits(m))
decrypted_bits = decrypt(ciphertext, x_final, prime_p, prime_q, t)
decrypted_text = bits_to_text(decrypted_bits)
print("Decrypted:", decrypted_text)