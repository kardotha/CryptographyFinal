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
    
def L(x, n):
    return (x-1)//n

# paillier with n = 161
def generate_keys():
    prime_p = 7
    prime_q = 23
    n = prime_p * prime_q # 161
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

def homomorph_add(c1, c2):
    return c1 * c2 % (161*161)

def shuffle(cards, public_key):
    shuffled = cards.copy()
    random.shuffle(shuffled)
    
    randomize_encrypt = encrypt(public_key, 0)
    #https://www.w3schools.com/python/python_lists_comprehension.asp
    returned = [homomorph_add(card, randomize_encrypt) for card in shuffled]
    return returned
    
# generate keys
public_key, private_key = generate_keys()
n, _ = public_key
m1 = 1
m2 = 2

# encrypt cards
encrypted = [encrypt(public_key, m1), encrypt(public_key, m2)]
print("encrypted:", encrypted)

# shuffle cards
shuffled = shuffle(encrypted, public_key)
print("shuffled:", shuffled)

# get cards
#https://stackoverflow.com/questions/4426663/how-do-i-remove-the-first-item-from-a-list
if(random.random() < .5): #5050 random
    alice_card = shuffled.pop(0)
    bob_card = shuffled.pop(0)
else:
    bob_card = shuffled.pop(0)
    alice_card = shuffled.pop(0)
    
alice_card = decrypt(private_key, public_key, alice_card)
bob_card = decrypt(private_key, public_key, bob_card)

print(f"\nAlice's card: {alice_card}")
print(f"Bob's card: {bob_card}")