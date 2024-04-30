import marshal
import random
import math
import base64

class RSA:
    def __init__(self):
        self.pu_key = None
        self.pr_key = None

    def __ext_euclid(self, a, b):
        """
        확장 유클리드 호제법을 사용하여 정수 a, b의 최대공약수와 해를 찾습니다.
        """
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = self.__ext_euclid(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    def __mr(self, n):
        """
        밀러-라빈 소수판별법을 사용하여 주어진 숫자가 소수인지를 판별합니다.
        소수일 경우 1을 반환하고, 아닐 경우 0을 반환합니다.
        """
        if n <= 1:
            return 0
        if n <= 3:
            return 1
        if n % 2 == 0:
            return 0
        k = 0
        m = n - 1
        while m % 2 == 0:
            k += 1
            m //= 2
        a = random.randint(2, n - 2)
        b = pow(a, m, n)
        if b == 1 or b == n - 1:
            return 1
        for _ in range(k - 1):
            b = pow(b, 2, n)
            if b == n - 1:
                return 1
        return 0

    def __gen_number(self, gen_bit):
        """
        주어진 비트 수에 해당하는 홀수를 생성합니다.
        """
        while True:
            num = random.getrandbits(gen_bit)
            if num % 2 != 0:
                return num

    def __gen_prime(self, gen_bit):
        """
        주어진 비트 수에 해당하는 소수를 생성합니다.
        """
        while True:
            num = self.__gen_number(gen_bit)
            if self.__mr(num):
                return num

    def __gen_ed(self, n):
        """
        주어진 n보다 작고, n과 서로소인 정수 e를 찾습니다.
        확장 유클리드 호제법을 사용하여 d * e ≡ 1 (mod n)을 만족하는 d를 찾습니다.
        """
        e = 65537  # 일반적으로 사용되는 e 값
        gcd, x, y = self.__ext_euclid(n, e)
        while gcd != 1:
            e = random.randint(2, n - 1)
            gcd, x, y = self.__ext_euclid(n, e)
        if x < 0:
            x += n
        return e, x

    def __value_to_string(self, val):
        """
        숫자를 문자열로 변환합니다.
        """
        return str(val)

    def __string_to_value(self, buf):
        """
        문자열을 숫자로 변환합니다.
        """
        return int(buf)
    
    def __bytes_to_value(self, buf):
        """
        바이트열을 정수로 변환합니다.
        """
        return int.from_bytes(buf, byteorder='big')

    def create_key(self, pu_fname='key.prk', pr_fname='key.skr', debug=False):
        """
        RSA 키를 생성합니다. 공개키 파일 이름과 개인키 파일 이름을 지정할 수 있습니다.
        """
        gen_bit = 2048  # 키 길이
        p = self.__gen_prime(gen_bit // 2)
        q = self.__gen_prime(gen_bit // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e, d = self.__gen_ed(phi)
        if debug:
            print("p:", p)
            print("q:", q)
            print("n:", n)
            print("e:", e)
            print("d:", d)
        self.pu_key = (n, e)
        self.pr_key = (n, d)

        with open(pu_fname, 'w') as f:
            n_b64 = base64.b64encode(self.__value_to_string(n).encode()).decode()
            e_b64 = base64.b64encode(self.__value_to_string(e).encode()).decode()
            f.write(f"{n_b64}\n{e_b64}")

        # 개인키를 base64로 인코딩하여 파일에 쓰기
        with open(pr_fname, 'w') as f:
            n_b64 = base64.b64encode(self.__value_to_string(n).encode()).decode()
            d_b64 = base64.b64encode(self.__value_to_string(d).encode()).decode()
            f.write(f"{n_b64}\n{d_b64}")
        return True

    def read_key(self, key_filename):
        """
        주어진 키 파일을 읽어 RSA 키로 변환합니다.
        """
        with open(key_filename, 'r') as f:
            key_data = f.read().strip().split('\n')
            print(key_data)
            if len(key_data) != 2:
                raise ValueError("Key file should contain exactly 2 lines")

            n_decoded = base64.b64decode(key_data[0].strip()).decode()
            d_decoded = base64.b64decode(key_data[1].strip()).decode()

            n = self.__string_to_value(n_decoded)
            d = self.__string_to_value(d_decoded)
            return n, d
        #     b = f.read()
        #     s = base64.b64decode(b)
        #     key = marshal.loads(s)
        # return key

    def crypt(self, buf, key):
        """
        주어진 버퍼와 RSA 키를 사용하여 암/복호화를 수행합니다.
        """
        n, k = key
        print('test2')
        buf = self.__bytes_to_value(buf)
        print('okay')
        result = pow(buf, k, n)
        return self.__value_to_string(result)