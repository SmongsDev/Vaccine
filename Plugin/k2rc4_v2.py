class RC4:
    def __init__(self):
        self.S = list(range(256))
        self.T = []

    def set_key(self, password):
        """
        주어진 암호를 사용하여 키 설정
        """
        if isinstance(password, str):  # 문자열인지 확인
            key = [ord(c) for c in password]
        else:  # 문자열이 아니라면 문자열로 변환하여 처리
            key = [ord(c) for c in str(password)]
        self.__init_rc4()
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.__swap(i, j)

    def crypt(self, data):
        """
        주어진 데이터를 암/복호화
        """
        if not isinstance(data, bytes):  # 데이터가 바이트열인지 확인
            raise TypeError("Data must be bytes.")

        output = bytearray()
        i = j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.__swap(i, j)
            t = (self.S[i] + self.S[j]) % 256
            k = self.S[t]
            output.append(byte ^ k)
        return bytes(output)

    def __init_rc4(self):
        """
        RC4 알고리즘에 필요한 테이블 초기화
        """
        self.T = [self.S[i % len(self.S)] for i in range(256)]

    def __swap(self, i, j):
        """
        주어진 두 인덱스의 데이터 교환
        """
        self.S[i], self.S[j] = self.S[j], self.S[i]

    def __gen_k(self):
        """
        암/복호화에 필요한 스트림 생성
        """
        i = j = 0
        while True:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.__swap(i, j)
            t = (self.S[i] + self.S[j]) % 256
            k = self.S[t]
            yield k