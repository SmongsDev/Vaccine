# RC4 클래스
# rc4.set_key : 암호 문자열 정의
# rc4.crypt   : 주어진 버퍼 암/복호화

class RC4:
    # 초기화
    def __init__(self):
        self.__S = []
        self.__T = []
        self.__Key = []
        self.__K_i = 0
        self.__K_j = 0

    # 암호 설정
    def set_key(self, password):
        for i in range(len(password)):
            self.__Key.append(ord(password[i]))
        self.__init_rc4()

    # 데이터 암/복호화
    def crypt(self, data):
        t_str = []

        for i in range(len(data)):
            if isinstance(data[i], int):
                t_str.append(data[i])
            else:
                t_str.append(ord(data[i]))

        for i in range(len(t_str)):
            t_str[i] = chr(t_str[i] ^ self.__gen_k())

        ret_s = ''
        for val in t_str:
            ret_s += val

        return ret_s
    

    # rc4의 테이블 초기화
    def __init_rc4(self):
        for i in range(256):
            self.__S.append(i)
            self.__T.append(self.__Key[i % len(self.__Key)])

        j = 0
        for i in range(256):
            j = (j + self.__S[i] + self.__T[i]) % 256
            self.__swap(i, j)

    
    def __swap(self, i, j):
        self.__S[i], self.__S[j] = self.__S[j], self.__S[i]

    
    def __gen_k(self):
        i = self.__K_i
        j = self.__K_j

        i = (i + 1) % 256
        j = (j + self.__S[i]) % 256
        self.__swap(i, j)
        t = (self.__S[i] + self.__S[j]) % 256

        self.__K_i = i
        self.__K_j = j

        return self.__S[t]