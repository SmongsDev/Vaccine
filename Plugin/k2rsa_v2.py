import base64
import marshal
import random

def extended_euclidean_algorithm(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y

def miller_rabin_test(n):
    composite = 0
    inconclusive = 0

    def get_kq(num):
        sub_k = 0

        sub_t = num - 1
        b_t = bin(sub_t)

        for sub_i in range(len(b_t) - 1, -1, -1):
            if b_t[sub_i] == '0':
                sub_k += 1
            else:
                break
        
        sub_q = sub_t >> sub_k
        return sub_k, sub_q
    
    k, q = get_kq(n)
    if k == 0:
        return 0
    
    for _ in range(10):
        a = random.randint(2, n-1)
        if pow(a, q, n) == 1:
            inconclusive += 1
            continue

        t = 0
        for j in range(k):
            if pow(a, (2 * j * q), n) == n - 1:
                inconclusive += 1
                t = 1

        if t == 0:
            composite += 1

    if inconclusive >= 6:
        return 1

def generate_odd_number(bit_length):
    return random.randrange(2**(bit_length-1)+1, 2**bit_length, 2)

def generate_prime_number(bit_length):
    while True:
        p = generate_odd_number(bit_length)
        if miller_rabin_test(p) == 1:
            return p

def generate_key_pair(public_key_filename, private_key_filename, debug):
    p = generate_prime_number(128)
    q = generate_prime_number(128)

    n = p * q

    totient_n = (p - 1) * (q - 1)

    e, d, _ = extended_euclidean_algorithm(random.randint(2, 1000), totient_n)

    public_key = (e, n)
    private_key = (d, n)

    public_key_data = base64.b64encode(marshal.dumps(public_key))
    private_key_data = base64.b64encode(marshal.dumps(private_key))

    try:
        with open(public_key_filename, 'wb') as f:
            f.write(public_key_data)
        with open(private_key_filename, 'wb') as f:
            f.write(private_key_data)
    except IOError:
        return False
    
    if debug:
        print('[*] Key Pair Generated: {}, {}'.format(public_key_filename, private_key_filename))
    print('Key pair created successfully!')
    return True

def read_key(key_filename):
    try:
        with open(key_filename, 'rb') as f:
            key_data = base64.b64decode(f.read())
            key = marshal.loads(key_data)
        return key
    except IOError:
        return None

def crypt(buf, key):
    plantext_ord = 0
    for i in range(len(buf)):
        if isinstance(buf[i], int):
            plantext_ord |= buf[i] << (i * 8)
        else:
            plantext_ord |= ord(buf[i]) << (i * 8)

    val = pow(plantext_ord, key[0], key[1])

    ret = ''
    for _ in range(32):
        b = val & 0xff
        val >>= 8

        ret += chr(b)

        if val == 0:
            break

    return ret
