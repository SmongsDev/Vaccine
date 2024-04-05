# DB 작성 

# 특정 문자열 위치
# 악성코드 진단 함수(ScanMD5):악성코드 파일 크기:MD5 해시:악성코드 이름

import sys, os, zlib, hashlib

def main():
    if len(sys.argv) != 2:
        print('Usage: kmake.py [file]')
        fname = input()
        if fname == '': return
    else:
        fname = sys.argv[1]
    
    tname = fname
    fp = open(tname, 'rb')
    buf = fp.read()
    fp.close()

    buf2 = zlib.compress(buf)

    buf3 = b''
    for c in buf2:
        buf3 += bytes([c ^ 0xFF])

    buf4 = b'KAVM' + buf3

    f = buf4
    for _ in range(3):
        md5 = hashlib.md5()
        md5.update(f)
        f = md5.hexdigest().encode('utf-8')
    
    buf4 += f

    kmd_name = fname.split('.')[0] + '.kmd'
    fp = open(kmd_name, 'wb')
    fp.write(buf4)
    fp.close()

    print('{} -> {}'.format(fname, kmd_name))


if __name__ == '__main__':
    main()