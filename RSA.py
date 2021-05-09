import random
import hashlib
import struct


def pow(x, p):
    res = 1
    while p:
        # p is odd
        if p & 1:
            res *= x
        x *= x
        # p = p/2
        p >>= 1
    return res


# x^y % p
def pow_mod(x, y, p):
    res = 1
    x = x % p
    while y > 0:
        # y is odd
        if y & 1:
            res = (res * x) % p
        # y = y/2
        y >>= 1
        x = (x * x) % p
    return res


def miller_rabin_test(d, n):
    a = 2 + random.randint(1, n - 4)
    x = pow_mod(a, d, n)

    if x == 1 or x == n - 1:
        return True

    while d != n - 1:
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True


def is_prime(n, k=40):
    if n <= 1 or n == 4:
        return False
    if n in (2, 3):
        return True

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for i in range(k):
        if not miller_rabin_test(d, n):
            return False

    return True


def gcd(a, b):
    if a == 0:
        return b
    return gcd(a, a % b)


def lcm(a, b):
    return a * b / gcd(a, b)


def egcd(a, b):
    g, g1 = a, b
    u, u1 = 1, 0
    v, v1 = 0, 1
    while g1:
        q = g // g1
        g, g1 = g1, g - q * g1
        v, v1 = v1, v - q * v1
        u, u1 = u1, u - q * u1
    return g, u, v


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def interval(length):
    a = 2 ** (length - 1)
    b = (2 ** length) - 1
    return a, b


def generate_prime_number(length):
    begin, end = interval(length)
    a = random.randint(begin, end)
    _isPrime = False

    while not _isPrime:
        _isPrime = is_prime(a)
        if a + 1 > end and not _isPrime:
            a = random.randint(begin, end)
        else:
            a += 1
    return a - 1


def chinese_remainder_theorem(d, p, q, c):
    m1 = pow_mod(c, pow_mod(d, 1, p - 1), p)
    m2 = pow_mod(c, pow_mod(d, 1, q - 1), q)

    qinv = modinv(q, p)
    h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    return m


def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def generate_binstring(l):
    r = ""
    for i in range(l):
        temp = str(random.randint(0, 1))
        r += temp
    return r


def hash_case(message, length):
    if length == 256:
        m = hashlib.sha256()
        m.update(message)
        return m.digest()
    elif length == 384:
        m = hashlib.sha384()
        m.update(message)
        return m.digest()
    elif length == 512:
        m = hashlib.sha512()
        m.update(message)
        return m.digest()


def oaep_padding(plaintext, g, h):
    r = bytearray(generate_binstring(h), 'ascii')
    pltx = plaintext
    for i in range((g//8) - len(plaintext)):
        pltx += b'\x00'
    G = xor_bytes(pltx, hash_case(int(r, 2).to_bytes(h // 8, 'big'), g))
    H = xor_bytes(int(r, 2).to_bytes(h // 8, 'big'), hash_case(G, h))
    return G + H, pltx


class RSA:
    def __init__(self, k_length=1024):
        self.key_length = k_length
        self.p = generate_prime_number(self.key_length)
        self.q = generate_prime_number(self.key_length)
        self.public_key, self.private_key = self.generate_keypairs()

    def generate_keypairs(self):
        p = self.p
        q = self.q

        n = p * q

        # Phi is the totient of n
        phi = (p - 1) * (q - 1)

        # Choose an integer e such that e and phi(n) are coprime
        e = random.randrange(1, phi)

        # Use Euclid's Algorithm to verify that e and phi(n) are comprime
        g, _, _ = egcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g, _, _ = egcd(e, phi)

        # Use Extended Euclid's Algorithm to generate the private key
        d = modinv(e, phi)

        # Return public and private keypair
        # Public key is (e, n) and private key is (d, n)
        return (e, n), (d, n)

    def encrypt(self, plaintext, pub_key=None):
        e, n = pub_key if pub_key else self.public_key
        barr = bytearray(plaintext)
        return [pow_mod(b, e, n) for b in barr]

    def decrypt(self, ciphertext, priv_key=None):
        d, n = priv_key if priv_key else self.private_key
        return bytes([chinese_remainder_theorem(d, self.p, self.q, c) for c in ciphertext])

    # def encrypt(self, plaintext):
    #     e, n = self.public_key
    #     barr = bytearray(plaintext)
    #     p_int = int.from_bytes(plaintext, 'big')
    #     return pow_mod(p_int, e, n)
    #
    # def decrypt(self, ciphertext):
    #     d, n = self.private_key
    #     dec = chinese_remainder_theorem(d, self.p, self.q, ciphertext)
    #     return dec.to_bytes(512, 'big')

    def oaep_encrypt(self, plaintext, g, h, pub_key=None):
        plaintext, _ = oaep_padding(plaintext, g, h)
        e, n = pub_key if pub_key else self.public_key
        barr = bytearray(plaintext)
        return [pow_mod(b, e, n) for b in barr]

    def oaep_decrypt(self, ciphertext, g, h, priv_key=None):
        d, n = priv_key if priv_key else self.private_key
        decr = bytes([chinese_remainder_theorem(d, self.p, self.q, c) for c in ciphertext])
        G = decr[:g // 8]
        H = decr[g // 8:]

        r = xor_bytes(H, hash_case(G, h))
        return xor_bytes(hash_case(r, g), G)


import time
def benchmark(msg):
    for i in range(512, 1025, 128):
        print("prime numbers length: {}".format(i))
        start = time.time()
        rsa_obj = RSA(i)
        enc = rsa_obj.encrypt(msg)
        dec = rsa_obj.decrypt(enc)
        stop = time.time()
        if msg == dec:
            print("RSA: {} seconds".format(stop - start))

        g = ((i // 128) // 2) * 128
        h = i - g
        start = time.time()
        rsa_obj1 = RSA(i)
        enc = rsa_obj1.oaep_encrypt(msg, g, h)
        dec = rsa_obj1.oaep_decrypt(enc, g, h)
        stop = time.time()
        print("OAEP RSA: {} seconds".format(stop - start))


if __name__ == '__main__':
    rsa_obj = RSA(1024)
    msg = b'msg'*8
    oaep_enc = rsa_obj.oaep_encrypt(msg, 384, 512)
    oaep_dec = rsa_obj.oaep_decrypt(oaep_enc, 384, 512)
    _, padded = oaep_padding(msg, 384, 512)
    assert padded == oaep_dec
    benchmark(msg)