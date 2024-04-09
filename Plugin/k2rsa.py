import base64
import marshal
import random

def __ext_euclid(a,b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


# rsa 알고리즘
def __mr(n):
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
        a = int(random.uniform(2, n))
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
    

# bit 수에 해당하는 홀수 생성
def __gen_number(gen_bit):
    random.seed()

    b = ''
    for _ in range(gen_bit - 1):
        b += str(int(random.uniform(1, 10)) % 2)
    b += '1'
    
    return int(b, 2)


# bit 수에 해당하는 소수 생성
def __gen_prime(gen_bit):
    while 1:
        p = __gen_number(gen_bit)
        if __mr(p) == 1:
            return p
        

# 확장 유클리드 호제법 이용 ( d * e / n 으로 나눴을때 나머지가 1인 정수 d 찾기)
def __get_ed(n):
    while 1:
        t = int(random.uniform(2, 1000))
        d, x, y = __ext_euclid(t, n)
        if d == 1:
            return t, x
        
# 숫자 -> 문자열 (암호화를 쉽게 하기 위함)
def __value_to_string(val):
    ret = ''
    for _ in range(32):
        b = val & 0xff
        val >>= 8

        ret += chr(b)

        if val == 0:
            break

    return ret

# 문자열 -> 숫자 ( 암호화를 쉽게 하기 위함 )
def __string_to_value(buf):
    plantext_ord = 0
    for i in range(len(buf)):
        plantext_ord |= ord(buf[i]) << (i * 8)

    return plantext_ord


# rsa 키 생성
def create_key(pu_fname='key.prk', pr_fname='key.str', debug=False):
    p = __gen_prime(128)
    q = __gen_prime(128)

    n = p * q

    qn = (p - 1) * (q - 1)
    e, d = __get_ed(qn)

    pu = [e,n]
    pr = [d,n]

    pu_data = base64.b64encode(marshal.dumps(pu))
    pr_data = base64.b64encode(marshal.dumps(pr))

    try:
        with open(pu_fname, 'wb') as f:
            f.write(pu_data)
        with open(pr_fname, 'wb') as f:
            f.write(pr_data)
    except IOError:
        return False
    
    if debug:
        print('[*] Make Key : {}, {}'.format(pu_fname, pr_fname))
    print('create!!')
    return True


# key 파일 읽어 rsa 키로 변환
def read_key(key_filename):
    try:
        with open(key_filename, 'rt') as fp:
            b = fp.read()
            s = base64.b64decode(b)
            key = marshal.loads(s)

        return key
    except IOError:
        return None
    
# 주어진 버퍼와 rsa 키를 이용해 암/복호화
def crypt(buf, key):
    plantext_ord = __string_to_value(buf)

    val = pow(plantext_ord, key[0], key[1])

    return __value_to_string(val)