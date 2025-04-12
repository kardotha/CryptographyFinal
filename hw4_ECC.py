#ECC
#https://crypto.stackexchange.com/questions/11744/scalar-multiplication-on-elliptic-curves
# Define the elliptic curve parameters
q = 257  # Field size
a = 0    # Curve parameter a
b = -4   # Curve parameter b
G = (2, 2)  # Base point G

# Bob's private key
bob_key = 101

# Alice's message point
message_point = (112, 26)

# Alice's random integer
k = 41

# Function to compute the modular inverse
# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def mod_inverse(x, p):
    return pow(x, p - 2, p)

# Function to add two points on the elliptic curve
def point_add(P, Q):
    if P == "O":
        return Q
    if Q == "O":
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return "O"  # Point at infinity
    if P == Q:
        lam = (3 * x1 * x1 + a) * mod_inverse(2 * y1, q) % q
    else:
        lam = (y2 - y1) * mod_inverse(x2 - x1, q) % q
    x3 = (lam * lam - x1 - x2) % q
    y3 = (lam * (x1 - x3) - y1) % q
    return (x3, y3)

# Function to multiply a point by a scalar (using double-and-add algorithm)
def scalar_mult(k_, P):
    result = "O"  # Point at infinity
    addend = P
    while k_ > 0:
        if k_ & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k_ >>= 1
    return result

# Function to negate a point
def point_neg(P):
    if P == "O":
        return "O"
    x, y = P
    return (x, (-y) % q)


# Bob's public key P_B = N_B * G
P_B = scalar_mult(bob_key, G)

# Get ciphertext
C_1 = scalar_mult(k, G)
C_2 = point_add(message_point, scalar_mult(k, P_B))

print("Bob's public key P_B:", P_B)
print("Ciphertext (C_1, C_2):")
print("C_1:", C_1)
print("C_2:", C_2)

# Decrypt
k_times_P_B = scalar_mult(bob_key, C_1)  # N_B * C_1
neg_k_times_P_B = point_neg(k_times_P_B)  # Negate 
P_m = point_add(C_2, neg_k_times_P_B)  # Add to C_2 get P_m

# Print decrypted 
print("Decrypted message P_m:", P_m)