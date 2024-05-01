import math
import random
import hashlib

N = None
public_key = None
private_key = None


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Miller-Rabin primality test
    def check_composite(a, s, d, n):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        if check_composite(a, s, d, n):
            return False

    return True


def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        # Ensure the number is odd
        candidate |= 1
        if is_prime(candidate):
            return candidate


def mod_inv(a, m):
    m0, x0, x1 = m, 0, 1

    while a > 1:
        q = a // m
        m, a = a % m, m

        x0, x1 = x1 - q * x0, x0

    if a == 1:
        return x1 % m0
    else:
        return None


def find_co_prime(number):

    while True:
        candidate = random.randrange(number // 2, number)
        # Check if the GCD of the two numbers is 1
        if math.gcd(candidate, number) == 1:
            return candidate


def message_hash(m):
    s = hashlib.sha256()
    s.update(m.encode())
    digest = s.digest()
    return int.from_bytes(digest, byteorder='big')


def blind_message(m, e, N):
    # Find one blind factor from the mid of N
    coprime = find_co_prime(N)
    if coprime is None:
        print("Error: Could not find co-prime pairs.")
        exit()
    
    # Calculate the blind message
    blind_factor = pow(coprime, e, N)
    blind_message = (blind_factor * m) % N
    return blind_message, coprime


def unblind_message(m, coprime, N):
    inv = mod_inv(coprime, N)
    message = (m * inv) % N
    return message


def sign_message(m):
    return pow(m, private_key, N)


def validate_signature(m, sig):
    decrypted = pow(sig, public_key, N)
    
    m_hashed = message_hash(m)
    return m_hashed == decrypted


def init_key_pair():
    global N, public_key, private_key
    # Key Generation
    p = generate_prime(1024)
    q = generate_prime(1024)
    phi_n = (p - 1) * (q - 1)
    N = p * q
    k = 512

    # Generate a random public exponent e (512 bits) with valid modular inverse
    min_e = 2**(k - 1) + 1
    max_e = phi_n - 1
    e = None
    d = None

    while e is None or e == phi_n or d is None:
        e = random.randint(min_e, max_e)
        if math.gcd(e, phi_n) == 1:
            d = mod_inv(e, phi_n)
            if d is not None:
                break

    if e is None or d is None:
        print("Error: Could not find a suitable public exponent and modular inverse.")
        exit()
    
    public_key = e
    private_key = d
    return e, N
