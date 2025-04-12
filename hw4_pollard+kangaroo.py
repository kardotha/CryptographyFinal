#pollard's rho factoring algo and pollard's kangaroo algo for solving modular exponeitation problems
def pollards_rho(n_):
    # Greatest Common Divisor function
    # https://stackoverflow.com/questions/11175131/code-for-greatest-common-divisor-in-python
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    # Pseudorandom function x^2 + 1 (mod n)
    def f(x_):
        return (x_ * x_ + 1) % n_

    # Initialize a and b
    a, b = 2, 2
    while True:
        a = f(a)         # Move a one step
        b = f(f(b))      # Move b two steps
        d = gcd(abs(a - b), n_)
        print(d)
        if d > 1 and d < n_:
            return d    # Found a non-trivial factor
        if d == n_:
            return None  # Failure (try a different f(x))

# Factorize n = 1351
n = 1351
factor = pollards_rho(n)
print(f"Prime factors of {n}: {factor} and {n // factor}")

def kangaroo(g, y, p, order):
    def step(x_): return 2**(x_%3)

    t_pos, t_dist = pow(g, 0, p), 0
    w_pos, w_dist = y, 0

    while True:
        print(f"t_pos = {t_pos}, w_pos = {w_pos}")
        # normal kangaroo moves
        s = step(t_pos)
        t_pos = (t_pos * pow(g, s, p)) % p
        t_dist += s

        # wild kangaroo moves
        s = step(w_pos)
        w_pos = (w_pos * pow(g, s, p)) % p
        w_dist += s
        print(f"t_pos = {t_pos}, w_pos = {w_pos}")

        if t_pos == w_pos:
            return (t_dist - w_dist) % order

x = kangaroo(9, 9, 11, 5)
print(x)