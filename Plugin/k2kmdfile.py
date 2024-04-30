import hashlib, os, py_compile, random, shutil, struct, sys, zlib, k2rc4, k2rsa, k2timelib

# rsa 개인키를 이용해 파일 암호화 -> KMD 파일 생성
def make(src_fname, debug=False):
    fname = src_fname

    if fname.split('.')[1] == 'py':
        py_compile.compile(fname)
        pyc_name = fname + 'c'
    else:
        pyc_name = fname.split('.')[0] + '.pyc'
        shutil.copy(fname, pyc_name)

    rsa_pu = k2rsa.read_key('key.pkr')
    rsa_pr = k2rsa.read_key('key.skr')
    
    # 공개키 로딩
    if not (rsa_pr and rsa_pu):
        if debug:
            print('ERROR : Cannot find the Key files!')
        return False
    
    # KMD 파일 생성
    kmd_data = b'KAVM'

    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    reserved_buf = val_date + val_time + bytes([0] * 28)

    kmd_data += reserved_buf

    random.seed()

    while True:
        tmp_kmd_data = b''

        # RC4 알고리즘에 사용할 128bit 랜덤키 생성
        key = bytes([random.randint(0, 0xff) for _ in range(16)])

        e_key = k2rsa.crypt(key, rsa_pr)
        if len(e_key) != 32:
            continue

        d_key = k2rsa.crypt(e_key, rsa_pu)
        # print(key, ":", d_key.encode())
        
        buf3 = b''
        if key == d_key and len(key) == len(d_key):
            tmp_kmd_data += e_key

            buf1 = open(pyc_name, 'rb').read()
            buf2 = zlib.compress(buf1)

            e_rc4 = k2rc4.RC4()
            e_rc4.set_key(key)

            buf3 = e_rc4.crypt(buf2)

            e_rc4 = k2rc4.RC4()
            e_rc4.set_key(key)

            if e_rc4.crypt(buf3) != buf2:
                continue

        tmp_kmd_data += buf3

        md5 = hashlib.md5()
        md5hashlib = kmd_data + tmp_kmd_data

        for _ in range(3):
            md5.update(md5hashlib)

        m = md5.digest()

        e_md5 = k2rsa.crypt(m, rsa_pr)
        if len(e_md5) != 32:
            continue

        d_md5 = k2rsa.crypt(e_md5, rsa_pu)


        # print(m, ";", d_md5.encode())
        if m == d_md5:
            kmd_data += tmp_kmd_data + e_md5
            break

    # KMD 파일 생성
    ext = fname.find('.')
    kmd_name = fname[0:ext] + '.kmd'

    try:
        if kmd_data:
            open(kmd_name, 'wb').write(kmd_data)

            os.remove(pyc_name)

            if debug:
                print('Success : {} -> {}'.format(fname, kmd_name))
            return True
        else:
            raise IOError
    except IOError:
        if debug:
            print('Fail : {}'.format(fname))
        return False
# 복호화 

# MD5 해시 결과 리턴
def ntimes_md5(buf, ntimes):
    md5 = hashlib.md5()
    md5hash = buf
    for _ in range(ntimes):
        md5.update(md5hash)
        md5hash = md5.hexdigest()

    return md5hash

# KMD 오류 정의
class KMDFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
    
# KMD 관련 상수
class KMDConstants:
    KMD_SIGNATURE = b'KAVM'

    KMD_DATE_OFFSET = 4 # 날짜 위치
    KMD_DATE_LENGTH = 2 # 날짜 크기
    KMD_TIME_OFFSET = 6 # 시간 위치
    KMD_TIME_LENGTH = 2 # 시간 크기

    KMD_RESERVED_OFFSET = 8 # 예약 영역 위치
    KMD_RESERVED_LENGTH = 28 # 예약 영역 크기

    KMD_RC4_KEY_OFFSET = 36 # RC4 Key 위치
    KMD_RC4_KEY_LENGTH = 32 # RC4 Key 길이

    KMD_MD5_OFFSET = -32 # MD5 위치

# KMD 클래스
class KMD(KMDConstants):
    # 클래스 초기화
    def __init__(self, fname, pu):
        self.filename = fname
        self.date = None
        self.time = None
        self.body = None

        self.__kmd_data = None
        self.__rsa_pu = pu
        self.__rc4_key = None
        if self.filename:
            self.__decrypt(self.filename)

    # KMD 파일 복호화
    def __decrypt(self, fname, debug=False):
        print(fname)
        current_directory = os.getcwd()
        print("Current working directory:", current_directory)

        try:
            with open(fname, 'rb') as fp:
                print(fp.read(4), self.KMD_SIGNATURE)
                if fp.read(4) == self.KMD_SIGNATURE:
                    self.__kmd_data = self.KMD_SIGNATURE + fp.read()
                else:
                    raise KMDFormatError('KMD Header magic not found.')
            
            tmp = self.__kmd_data[self.KMD_DATE_OFFSET:self.KMD_TIME_OFFSET + self.KMD_TIME_LENGTH]
            self.date = k2timelib.covert_date(struct.unpack('<H', tmp)[0])

            e_md5hash = self.__get_md5()
            md5hash = self.__kmd_data[self.KMD_MD5_OFFSET:]
            if e_md5hash != md5hash:
                raise KMDFormatError('Invalid KMD MD5 hash.')

            self.__rc4_key = self.__get_rc4_key()
            e_kmd_data = self.__get_body()
            self.body = zlib.decompress(e_kmd_data)

        except FileNotFoundError:
            print('파일이 존재하지 않습니다.')
        except PermissionError:
            print("파일을 열 권한이 없습니다.")
        except Exception:
            print('파일을 열 수 없습니다.')
            
        

    # KMD 파일의 RC4 키 얻기
    def __get_rc4_key(self):
        e_key = self.__kmd_data[self.KMD_RC4_KEY_OFFSET: self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH]
        return k2rsa.crypt(e_key, self.__rsa_pu)
    
    # KMD 파일의 body 얻기
    def __get_body(self):
        e_kmd_data = self.__kmd_data[self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH:self.KMD_MD5_OFFSET]

        r = k2rc4.RC4()
        r.set_key(self.__rc4_key)
        return r.crypt(e_kmd_data)
    
    # kmd 파일의 md5 얻기
    def __get_md5(self):
        e_md5 = self.__kmd_data[self.KMD_MD5_OFFSET:]
        return k2rsa.crypt(e_md5, self.__rsa_pu)