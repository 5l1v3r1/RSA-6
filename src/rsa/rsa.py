#! /usr/bin/env python

'''
Uses RSA algorithm to encode or decode a message
@author: hdamron1594
'''

import random
import math


def a_k_mod_n(a, k, n):
    '''
    Produces a^k mod n (included to make the process more self-explanatory than exp(a,k,n)
    '''
    return pow(a,k,n)

def gen_prime(start):
    '''
    Generates a prime number starting at a large value and goes up
    :param start: starting point (i.e. generated prime will be the next prime larger than this)
    '''
    n = start
    while not prime(n):
        n += 1
    return n

def prime(n):
    '''
    Determines if n is prime using Fermat's Theorem
    :param n: number to test
    '''
    return a_k_mod_n(2, n-1, n) == 1

def two_large_primes(digits):
    '''
    Computes large prime with this many digits or possibly more
    :param digits: number of digits to include
    :return: returns a large prime with that many digits minimum
    '''
    assert digits > 0, "Cannot compute number with zero or negative digits"
    minimum = 10**(digits-1)
    middle = minimum * 5
    maximum = minimum * 10
    
    first_start = random.randint(minimum, middle)
    second_start = random.randint(middle, maximum)
    
    first = gen_prime(first_start)
    second = gen_prime(second_start)
    
    if first == second:
        #handle case that they end up being the same by getting next prime
        second = gen_prime(first+1)
    
    return first, second

def gen_coprime(number, digits=None):
    if digits is None:
        digits = int(math.log10(number)) + 1
        
    minimum = 10**(digits-1)
    maximum = minimum * 10
    
    n = random.randint(minimum, maximum)
    
    while n % number == 0:
        n += 1
    
    return n

def gen_keys(digits=10):
    '''
    Generates public and private keys for RSA algorithm
    :param digits: decimal digits to be used for p and q
    :return: returns (k, n), (p, q) -> publickey, privatekey
    '''
    p, q = two_large_primes(digits)
    #p, q = 61, 53 #TODO TODO TODO remove - for debugging only
    n = p * q
    phi = (p-1) * (q-1)
    k = gen_coprime(phi) #coprime to phi(n)
    #k = 17 #TODO TODO TODO remove - for debugging only
    d = invmod_power(k, n, phi)
    #d = 413 #TODO TODO TODO remove - for debugging only
    return (n, k), (n, d) #TODO change p to d after calculating d

def encrypt(message, *publickey):
    '''
    Encrypts message according to publickey
    :param message: number message to encrypt
    :param publickey: tuple with (k, n) generated by gen_keys
    :return: returns encrypted message number
    '''
    n, k = publickey
    return a_k_mod_n(message, k, n) #a^k mod n

def invmod_power(invpow, n, phi):
    '''
    Determines power for inverse mod function i.e. to solve num^(1/invpow) mod n using Euler's Theorem
    
    '''
    d = 1
    while (d * invpow) % n != 1:
        #solve for d which satisfies power in inverse equation
        d += 1
    return d

def decrypt(encrpted, *privatekey):
    n, d = privatekey
    return a_k_mod_n(encrpted, d, n) #c^p mod n

def main():    
    publickey, privatekey = gen_keys(digits=4)
    print(publickey, privatekey)
    
    message = 3232
    print(message)
    encrypted = encrypt(message, *publickey)
    print(encrypted)
    new_message = decrypt(encrypted, *privatekey)
    print(new_message)

if __name__ == "__main__":
    main()
