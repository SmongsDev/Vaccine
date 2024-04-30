import marshal
import os
import hashlib
import base64
import struct
import k2rsa_v3
import k2rc4_v2
import zlib
import k2timelib_v2
import datetime
import py_compile
import shutil

class KMDTool:
    def __init__(self):
        self.rsa = k2rsa_v3.RSA()
        self.rc4 = k2rc4_v2.RC4()
        
    def make(self, src_fname, debug=False):
        """
        RSA 개인키를 사용하여 주어진 파일을 암호화하여 KMD 파일을 생성합니다.
        """
        # 암호화 대상 파일을 읽기
        # with open(src_fname, 'rb') as f:
        #     data = f.read()

        fname = src_fname
        if fname.split('.')[1] == 'py':
            py_compile.compile(fname)
            pyc_name = fname + 'c'
        else:
            pyc_name = fname.split('.')[0] + '.pyc'
            shutil.copy(fname, pyc_name)

        # 공개키와 개인키 로딩
        pu_key = self.rsa.read_key('key.pkr')
        pr_key = self.rsa.read_key('key.skr')

        # Header 생성
        header = b'KAMV'
        
        now = datetime.datetime.now()
        reserved_area = k2timelib_v2.get_now_date(now) << 11 | k2timelib_v2.get_now_time(now)

        header += reserved_area.to_bytes(4, 'big')
        # RC4 키 생성
        rc4_key = os.urandom(16)  # 16바이트 랜덤 키 생성

        # RC4로 데이터 암호화
        self.rc4.set_key(rc4_key)
        # encrypted_data = k2rc4_v2.crypt(zlib.compress(data))
        buf = open(pyc_name, 'rb').read()
        encrypted_data = self.rc4.crypt(zlib.compress(buf))

        # 개인키로 RC4 키 암호화
        encrypted_rc4_key = self.rsa.crypt(rc4_key, pr_key)

        # Body 생성
        # print(encrypted_data)
        # print(encrypted_rc4_key)
        body = encrypted_rc4_key.encode() + encrypted_data

        # Tailer 생성
        tailer_data = header + body
        md5 = hashlib.md5(tailer_data).digest()
        for _ in range(3):
            md5 = hashlib.md5(md5).digest()
        encrypted_md5 = self.rsa.crypt(md5, pr_key)

        # KMD 파일 생성
        kmd_fname = src_fname.split('.')[0] + '.kmd'
        with open(kmd_fname, 'wb') as f:
            f.write(header)
            f.write(body)
            f.write(encrypted_md5.encode())

        os.remove(pyc_name)
        
        if debug:
            print(f"KMD 파일 생성 완료: {kmd_fname}")

        return True


# 복호화
def ntimes_md5(buf, ntimes):
    """
    주어진 버퍼에 대해 n회 반복해서 MD5 해시 결과를 리턴합니다.
    """
    hashed_buf = buf
    for _ in range(ntimes):
        hashed_buf = hashlib.md5(hashed_buf).digest()
    return hashed_buf

class KMDFormatError(Exception):
    """
    KMD 오류 메시지를 정의하는 예외 클래스입니다.
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class KMDConstants:
    """
    KMD 파일 관련 상수를 정의하는 클래스입니다.
    """
    KMD_SIGNATURE = b'KAVM'

    KMD_DATE_OFFSET = 4
    KMD_DATE_LENGTH = 2
    KMD_TIME_OFFSET = 6
    KMD_TIME_LENGTH = 2

    KMD_RESERVED_OFFSET = 8
    KMD_RESERVED_LENGTH = 28

    KMD_RC4_KEY_OFFSET = 36
    KMD_RC4_KEY_LENGTH = 32

    KMD_MD5_OFFSET = -32

class KMD(KMDConstants):
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
            self.date = k2timelib_v2.covert_date(struct.unpack('<H', tmp)[0])

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
            
        
    # def __decrypt(self, fname, debuf=False):
    #     with open(fname, 'rb') as f:
    #         signature = f.read(len(self.KMD_SIGNATURE))
    #         if signature != self.KMD_SIGNATURE:
    #             raise KMDFormatError("Invalid KMD file signature")

    #         # 2. KMD 파일 날짜 읽기
    #         f.seek(self.KMD_DATE_OFFSET)
    #         date = f.read(self.KMD_DATE_LENGTH)

    #         # 3. KMD 파일 시간 읽기
    #         f.seek(self.KMD_TIME_OFFSET)
    #         time = f.read(self.KMD_TIME_LENGTH)

    #         # 4. KMD 파일에서 MD5 읽기
    #         f.seek(self.KMD_MD5_OFFSET)
    #         md5 = f.read()

    #         # 5. 무결성 체크
    #         body_start = len(self.KMD_SIGNATURE) + self.KMD_DATE_LENGTH + self.KMD_TIME_LENGTH + self.KMD_RESERVED_LENGTH
    #         f.seek(body_start)
    #         body = f.read(self.KMD_RC4_KEY_OFFSET - body_start)
    #         computed_md5 = hashlib.md5(body).digest()
    #         if computed_md5 != md5:
    #             raise KMDFormatError("MD5 mismatch")

    #         # 6. KMD 파일에서 RC4 키 읽기
    #         f.seek(self.KMD_RC4_KEY_OFFSET)
    #         rc4_key = f.read(self.KMD_RC4_KEY_LENGTH)

    #         # 7. KMD 파일에서 본문 읽기
    #         f.seek(self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH)
    #         compressed_body = f.read()

    #     # 8. 입축 해제하기
    #     decrypted_body = zlib.decompress(rc4_key + compressed_body)
    #     return decrypted_body

    def __get_rc4_key(self):
        e_key = self.__kmd_data[self.KMD_RC4_KEY_OFFSET:self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH]
        return k2rsa_v3.crypt(e_key, self.__rsa_pu)

    def __get_body(self):
        e_kmd_data = self.__kmd_data[self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH:self.KMD_MD5_OFFSET]

        r = k2rc4_v2.RC4()
        r.set_key(self.__rc4_key)
        return r.crypt(e_kmd_data)

    def __get_md5(self):
        e_md5 = self.__kmd_data[self.KMD_MD5_OFFSET:]
        return k2rsa_v3.crypt(e_md5, self.__rsa_pu)
