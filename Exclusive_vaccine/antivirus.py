# -*-coding:utf-8 -*-
import hashlib, sys, os, zlib
from io import BytesIO
import scanmod
import curemod

import imp

VirusDB = []
vdb = []
vsize = []

sdb = [] # 특정 위치 검색용

# KMD 파일 복호화
def DecodeKMD(fname):
    try:
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()
        
        buf2 = buf[4:-32]
        fmd5 = buf[-32:]

        f = b'KAVM' + buf2
        for _ in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest().encode('utf-8')
        
        if f != fmd5:
            raise SystemError
        
        buf3 = b''
        for c in buf2:
            buf3 += bytes([c ^ 0xFF])
            
        buf4 = zlib.decompress(buf3)
        return buf4
    except Exception as e:
        print("Error:", e)
        return None

def LoadVirusDB():
    buf = DecodeKMD('virus.kmd')
    fp = BytesIO(buf)

    while True:
        line = fp.readline()
        if not line: break
    
        line = line.strip().decode('utf-8')
        VirusDB.append(line)
    
    print(VirusDB)
    fp.close()

def MakeVirusDB():
    for pattern in VirusDB:
        tmp = []
        v = pattern.split(':')

        scan_func = v[0]
        cure_func = v[1]

        if scan_func == 'ScanMD5':
            tmp.append(v[3])
            tmp.append(v[4])
            vdb.append(tmp)

            size = int(v[2])
            if vsize.count(size) == 0:
                vsize.append(size)

        elif scan_func == 'ScanStr':
            tmp.append(int(v[2]))
            tmp.append(v[3])
            tmp.append(v[4])
            sdb.append(tmp)

if __name__ == '__main__':
    LoadVirusDB()
    MakeVirusDB()

    if len(sys.argv) != 2:
        print('Usage : antivirus.py [file]')
        print('Enter the file name you want to check')
        fname = input()
    else:
        fname = sys.argv[1]
        
    try:
        m = 'scanmod'
        f, filename, desc = imp.find_module(m, [''])
        module = imp.load_module(m, f, filename, desc)

        cmd = 'ret, vname = module.ScanVirus(vdb, vsize, sdb, fname)'
        exec(cmd)
    except ImportError:
        ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)

    # ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)
    if ret == True:
        print('{} : {}'.format(fname, vname))
        curemod.CureDelete(fname)
    else:
        print('{} : ok'.format(fname))