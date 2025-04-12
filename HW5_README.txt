part 1:

keygen = p and q are congruent to 3 mod 4

encryption: 
    turn message into bit string (binary encoding of ascii)

    use blum blum to create prng bits

        for bit in M,
            x = x^2 mod n
            get least sig fig of x
            use this bit

    xor each bit of M with each random sig fig of xor

    after each bit is encrypted, compute x_t+1 = x_t^2 mod n

decryption:
    find p and q
    ( (p+1) / 4 ) ^ (t+1) (mod p-1)
    ( (q+1) / 4 ) ^ (t+1) (mod q-1)
    
    find u and v s.t
    u = x^(d_p)_t+1 mod p
    v = x^(d_q)_t+1 mod q

    use CRT and get x_0
    x_0 = (v * p * p_inv mod q + v * q * q_inv mod p) mod n

    use blum blun func again to create prng bits
        for bit in M,
            x = x^2 mod n
            get least sig fig of x
            use this bit

    get message bits with xor again

    back to strung

(run hw5.py)

part 2:
https://en.wikipedia.org/wiki/Paillier_cryptosystem
https://people.csail.mit.edu/rivest/voting/papers/BaudronFouquePointchevalPoupardStern-PracticalMultiCandidateElectionSystem.pdf
https://medium.com/@GalinDinkov/privacy-preserving-voting-system-using-partial-homomorphic-encryption-ee9a39b867f9

keygen:
    p and q = (23, 29). chose small ones because big ones took too long to test
    23 and 29 are coprime s.t. totient(p, q) = 1

    n = p * q
    lambda = lcm(p-1,q-1)

    g = n+1
    mu = mod^-1(lambda, n)

    public key = n,g
    private key = lambda, mu

encryption:
    message m greater than 0, less than n

    find r < n s.t. r is coprime with n

    ciphertext c = g^m * r^n mod n^2

decrypt:
    m = (((c^lambda mod n^2) - 1) / n) * lambda mod n

homomorphic addition (voting impl)
    decryption of (encrypt(m1, r1) * encrypt(m2, r2) mod n^2) = m1 + m2 mod n

    from wikipedia: m voters cast ballot containing 1 or 0. 
    
    Choice is encrypted

    use above formula m1, m2, ... mn 

    encrypt(m1, r1), encrypt(m2, r2), ... encrypt (mn, rn) mod n^2 = m1 + m2 + ... + mn

    n votes for
    m-n votes against

    to incorporate into n > 2 voter system i will encode using digit place

    c1 is ones
    c2 is tens
    c3 is 100s
    cn = 1 * (10^(n-1))

part 3:
    same as hw5_2, moved some functions around

    counter m = 1, increments homomorphically at each step
    decrypted counter value = m on the print

    homomorphic add

part 4:
    reuses hw5_2,
    p and q are prime factors of given N (7, 23)
    uses random.shuffle and encrypts the array homomorphically (with 0)
    so that it changes the encrypted

    forces cards onto alice and bob randomly with 50/50 for order (though probably doesn't matter)
    nobody knows the others card, shuffling is encrypted

    decrypt at end