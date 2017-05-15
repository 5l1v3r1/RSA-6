'''
RSA Algorithm implementation
'''

from fractions import gcd
import random
import time


DEBUG = True


def debug(func):
    '''
    If DEBUG is set to true, decorates function so it prints output and time to execute
    :param func: function to be applied to
    :return: returns the function with a timer/debug wrapper around it (used as decorator)
    '''
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
    :return: returns True if n is prime else False
    '''
    return pow(2, n-1, n) == 1

@debug
def encryption_exp(phi_n, seed=None):
    '''
    Finds an encryption exponent e which is relatively prime to phi(n)
    :param phi_n: Euler phi function of n
    :param seed: starting point for detection, uses random number if None
    :return: returns encryption exponent e for use in public key
    '''
    if seed is None:
        start = random.randint(phi_n//10, phi_n)
    else:
        start = seed
    
    x = start
    while gcd(x, phi_n) != 1 and x > 1:
        x -= 1
    
    if x == 1: print("Failed encryption exponent")
    
    return x

@debug
def decryption_exp(e, phi_n):
    '''
    Solves the equation e * x + phi_n * y = 1 for x for decryption
    :param e: encryption exponent
    :param phi_n: Euler phi function of n
    :return: returns decryption exponent for private key
    '''
    coeffs = list(reversed(gcd_terms(e, phi_n)))
    running_sum = [0, 1]
    #TODO check case of len(coeffs) < 3
    for i in range(2, len(coeffs)+1):
        running_sum.append(running_sum[i-1] * coeffs[i-1] + running_sum[i-2])
    factors = running_sum[-2:]
    x = max(factors)
    y = min(factors)
    sanity_check = x * e - y * phi_n
    if sanity_check > 0:
        return x
    else:
        return -x + phi_n * (phi_n // x) #since msg**phi_n = 1 and d must be positive

def gcd_terms(e, phi_n):
    '''
    Calculates the terms involved in calculating the gcd of e, phi(n)
    :param e: encryption exponent
    :param phi_n: Euler phi function of n
    :return: returns list of factors used in the process (for use by `decryption_exp`)
    '''
    coefficients = []
    num = phi_n
    modulus = e
    while modulus != 0:
        coefficients.append(int(num // modulus))
        new_modulus = num % modulus
        num = modulus
        modulus = new_modulus
    return coefficients

@debug
def keys(digits):
    '''
    Generates a set of keys for RSA algorithm
    :param digits: number of decimal digits desired in prime factors (roughly)
    :return: returns publickey, privatekey which is the same as (n, e), (n, d)
        where e and d are encryption and decryption exponents, respectively
    '''
    p, q = two_large_primes(digits)
    n = p * q
    phi = (p-1) * (q-1)
    e = encryption_exp(phi, seed=2**8-1)
    d = decryption_exp(e, phi)
    return (n, e), (n, d)

@debug
def encrypt(message, publickey):
    '''
    Encrypts list of chunks using RSA
    :param message: list of unencrypted chunks to encrypt
    :param publickey: public key produced by `keys`
    '''
    n, e = publickey
    assert message < n, "Cannot encrypt message larger than modulo"
    return pow(message, e, n)

@debug
def decrypt(encrypted, privatekey):
    '''
    Decrypts a list of chunks encrypted by RSA
    :param encrypted: list of encrypted integer chunks
    :param privatekey: private key (n, d) produced by `keys`
    :return: returns unencrypted integer chunks
    '''
    n, d = privatekey
    return pow(encrypted, d, n)

@debug
def padded(message, chunk_size=3):
    '''
    Converts string message to integer by breaking it into chunks and using bitwise math
    :param message: string message to encrypt
    :param chunk_size: letters to include in each individual chunk
    :return: returns list of integers representing string
    '''
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
    '''
    Converts a number to string by analyzing each byte and extracting character
    :param chunks: list of integer chunks to be converted
    :return: returns the original string
    '''
    msg = ""
    for chunk in chunks:
        msg_chunk = ""
        while chunk > 255:
            msg_chunk += chr(chunk & 0xFF)
            chunk >>= 8
        msg_chunk += chr(chunk)
        msg += msg_chunk
    return msg

def encrypt_message(message, publickey, chunk_size=3):
    '''
    Encrypts string message into chunks with padding
    :param message: string message to encrypt
    :param publickey: public key produced by `keys`
    :param chunk_size: letters to include in each individual chunk
    :return: returns list of encrypted chunks as integers
    '''
    chunked = padded(message, chunk_size)
    return [encrypt(msg_num, publickey) for msg_num in chunked]

def decrypt_message(encrypted, privatekey):
    '''
    Decrypts a message and unpads it to be a string
    :param encrypted: list of encrypted chunks
    :param privatekey: private key (n, d) produced by `keys`
    :return: returns the string message which was encrypted
    '''
    chunked_msg_num = [decrypt(encrypted_chunk, privatekey) for encrypted_chunk in encrypted]
    return unpadded(chunked_msg_num)

def main():
    '''
    Main function tests the system with example encryption
    '''
    publickey, privatekey = keys(10)
    message = "This message is complimentary of Ron Rivest, Adi Shamir, and Leonard Adleman"
    print("message =", message)
    encrypted = encrypt_message(message, publickey, chunk_size=5)
    print("encrypted =", encrypted)
    decrypted = decrypt_message(encrypted, privatekey)
    print("decrypted =", decrypted)

if __name__ == "__main__":
    main()

