import random
from math import gcd, lcm #https://www.w3schools.com/python/ref_math_gcd.asp

#https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

def L(x, n):
    return (x-1) // n
    
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def encrypt(m, r, n, g):
    return (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)

def decrypt(c, n, lambda_n, mu):
    return (L(pow(c, lambda_n, n*n), n) * mu) % n

# Generate keys
p = 293
q = 433
n = p * q
g = 6497955158
mu = 53022
lambda_n = lcm(p-1, q-1)

rand = [35145, 74384, 10966, 17953, 7292]

m = 1
c = None

for i in range(5):
    r = rand[i]
    if(r == 35145):
        c = encrypt(m, r, n, g)
    else:
        c = (c * pow(g, 1, n*n) * pow(r, n, n*n)) % (n*n)
        
    current_m = decrypt(c, n, lambda_n, mu)
    
    print(f"Iteration {i+1}:")
    print(f"r{i+1}: {r}")
    print(f"Ciphertext: {c}")
    print(f"Decrypted counter value: {current_m}\n")