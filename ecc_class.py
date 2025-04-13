#ECC
#https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
#https://martin.kleppmann.com/papers/curve25519.pdf
class SimplifiedECC:
    def __init__(self, a, b, p, g, n):
        #y² ≡ x³ + ax + b (mod p)
        #g: base point (x, y) tuple
        #n: order of g
        self.a = a
        self.b = b
        self.p = p
        self.g = g
        self.n = n
        
    # Function to compute the modular inverse
    # https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    def mod_inverse(self, x, p):
        return pow(x, p - 2, p)
    
    # https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    
    #https://stackoverflow.com/questions/75089523/elliptic-curve-point-verify-point-is-on-the-curve
    def is_point_on_curve(self, point):
        x, y = point
        # y^2 - x^3 - ax - b % p
        if ((y * y - x * x * x - self.a * x - self.b) % self.p == 0):
            return True
        return False
        
    #https://crypto.stackexchange.com/questions/11744/scalar-multiplication-on-elliptic-curves
    # Function to multiply a point by a scalar (using double-and-add algorithm)
    def scalar_mult(self, k, p):
        result = None  # straight line
        addend = p
        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

    # Function to add two points on the elliptic curve
    def point_add(self, P, Q):
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 != y2:
            return None  # POINT IS VERTICAL LINE XDDDDD
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * self.mod_inverse(2 * y1, self.p) % self.p
        else:
            lam = (y2 - y1) * self.mod_inverse(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)
    
    # gen priv and pub key
    def keypair(self, prng):
        # forward coding (PRNG OBJECT NEEDS TO HAVE .RANDINT FUNCTION !!!)
        priv = prng.randint(1, self.n - 1)
        pub = self.scalar_mult(priv, self.g)
        
        return priv, pub
    
    # https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption
    def encrypt(self, pub, plaintext, prng):
        plaintext = plaintext.encode()
        m = int.from_bytes(plaintext, 'big') % self.p
        point = (m, (m**3 + self.a*m + self.b) % self.p)
        
        k = prng.randint(1, self.n-1)
        c1 = self.scalar_mult(k, self.g)
        c2 = self.point_add(point, self.scalar_mult(k, pub))
        return c1, c2
    
    def decrypt(self, priv, c):
        c1, c2 = c
        s = self.scalar_mult(priv, c1)
        
        invs = (s[0], (-s[1]) % self.p)
        point = self.point_add(c2, invs)
        
        return point[0].to_bytes((point[0].bit_length() + 7) // 8, 'big')