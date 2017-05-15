'''
Second attempt at RSA algorithm
'''

from fractions import gcd
import random
import time


DEBUG = False


def debug(func):
    if DEBUG:
        def time_and_call(*args, **kwargs):
            print("  +Debug: Entering function `%s`" % func.__name__)
            start_time = time.time()
            ret = func(*args, **kwargs)
            total_time = time.time() - start_time
            print("  -Debug: `%s` completed in %.4f seconds and produced %s" % (func.__name__, total_time, ret))
            return ret
        return time_and_call
    else:
        return func

def gen_prime(start):
    '''
    Generates a prime number starting at a large value and goes up
    :param start: starting point (i.e. generated prime will be the next prime larger than this)
    '''
    n = start
    while not prime(n):
        n += 1
    return n

@debug
def two_large_primes(digits, firstseed=None, secondseed=None):
    '''
    Computes large prime with this many digits or possibly more
    :param digits: number of digits to include
    :return: returns a large prime with that many digits minimum
    '''
    assert digits > 0, "Cannot compute number with zero or negative digits"
    minimum = 10**(digits-1)
    middle = minimum * 5
    maximum = minimum * 10
    
    if firstseed is None:
        first_start = random.randint(minimum, middle)
    else:
        first_start = firstseed
    
    if secondseed is None:
        second_start = random.randint(middle, maximum)
    else:
        second_start = secondseed
    
    first = gen_prime(first_start)
    second = gen_prime(second_start)
    
    if first == second:
        #handle case that they end up being the same by getting next prime
        second = gen_prime(first+1)
    
    return first, second

def prime(n):
    '''
    Determines if n is prime using Fermat's Theorem
    :param n: number to test
    '''
    return pow(2, n-1, n) == 1

def toilent(p, q):
    return (p-1) * (q-1) / gcd(p-1, q-1)

@debug
def encryption_exp(phi, seed=None):
    if seed is None:
        start = random.randint(phi//10, phi)
    else:
        start = seed
    
    x = start
    while gcd(x, phi) != 1 and x > 1:
        x -= 1
    
    if x == 1: print("Failed encryption exponent")
    
    return x

'''
TODO: This function works but is as horribly inefficient as brute force cracking
'''
@debug
def decryption_exp(e, phi_n, digits, seed=None):
    if seed is None:
        least = 10**(digits-1)
        most = least * 10
        start = random.randint(least, most)
    else:
        start = seed
    
    x = start
    while (x * e) % phi_n != 1:
        x += 1
    
    return x

@debug
def keys(digits):
    p, q = two_large_primes(digits)
    n = p * q
    phi = toilent(p, q)
    e = encryption_exp(phi, seed=2**8-1)
    d = decryption_exp(e, phi, digits)
    return (n, e), (n, d)

@debug
def encrypt(message, publickey):
    n, e = publickey
    assert message < n, "Cannot encrypt message larger than modulo"
    return pow(message, e, n)

@debug
def decrypt(encrypted, privatekey):
    n, d = privatekey
    return pow(encrypted, d, n)

@debug
def padded(message, chunk_size=3):
    chunks = []
    i = 0
    while i < len(message):
        chunk = 0
        for j in range(chunk_size):
            if i < len(message):
                character = ord(message[i])
                assert character <= 255, "Cannot handle chars greater than 255"
                chunk_change = character << (8*j)
                chunk += chunk_change #multiply by every other power of two
            else: pass
            i += 1
        chunks.append(chunk)
    return chunks

@debug
def unpadded(chunks):
    msg = ""
    for chunk in chunks:
        msg_chunk = ""
        while chunk > 255:
            msg_chunk += chr(chunk & 0xFF)
            chunk >>= 8
        msg_chunk += chr(chunk)
        msg += msg_chunk
    return msg

def encrypt_message(message, publickey):
    chunked = padded(message)
    return [encrypt(msg_num, publickey) for msg_num in chunked]

def decrypt_message(encrypted, privatekey):
    chunked_msg_num = [decrypt(encrypted_chunk, privatekey) for encrypted_chunk in encrypted]
    return unpadded(chunked_msg_num)

def main():    
    publickey, privatekey = keys(10)
    message = "Your mother was a hamster and you father smelled of elderberries"
    print("message =", message)
    encrypted = encrypt_message(message, publickey)
    print("encrypted =", encrypted)
    decrypted = decrypt_message(encrypted, privatekey)
    print("decrypted =", decrypted)

if __name__ == "__main__":
    main()

