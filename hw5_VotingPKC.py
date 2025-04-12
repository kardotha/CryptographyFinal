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

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

# paillier
def generate_keys():
    prime_p = 23
    prime_q = 29
    n = prime_p * prime_q
    x = lcm(prime_p-1, prime_q-1)
    g = n + 1
    mu = mod_inverse(x, n)
    return (n, g), (x, mu)

def encrypt(public_key, plaintext):
    n, g = public_key
    while True:
        r = random.randint(1, n-1)
        if gcd(r, n) == 1:
            break
    c = (pow(g, plaintext, n**2) * pow(r, n, n**2)) % (n**2)
    return c

def decrypt(private_key, public_key, ciphertext):
    lambda_val, mu = private_key
    n, _ = public_key
    x = pow(ciphertext, lambda_val, n**2)
    l = (x - 1) // n
    return (l * mu) % n

# Generate keys
public_key, private_key = generate_keys()
n, _ = public_key

print(f"keys: {public_key}, {private_key}")

# v1 -> v5 votes
votes = []
for j in range(1, 6):
    mod_result = j % 3
    if mod_result == 1:
        vote_val = 1    # C1
    elif mod_result == 2:
        vote_val = 10   # C2
    else:
        vote_val = 100  # C3
    votes.append(vote_val)

print(f"votes: {votes}")

# encrypt
encrypted_votes = [encrypt(public_key, v) for v in votes]

print(f"encrypted votes: {encrypted_votes}")

# sum votes
total_cipher = 1
for c in encrypted_votes:
    total_cipher = (total_cipher * c) % (n**2)

print(f"total_cipher: {total_cipher}")

# decrypt
total = decrypt(private_key, public_key, total_cipher)
print(f"total: {total}")

# parse results
c1 = total % 10
total = total // 10
c2 = total % 10
total = total // 10
c3 = total % 10

print(f"C1: {c1}\nC2: {c2}\nC3: {c3}")