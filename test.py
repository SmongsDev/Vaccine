# -*-coding:utf-8 -*-
import hashlib
import sys
import os
import Virus_db

vdb = []
def MakeVirusDB():
    for pattern in Virus_db.VirusDB:
        tmp = []
        v = pattern.split(':')
        print(v)
        tmp.append(v[0])
        tmp.append(v[1])
        vdb.append(tmp)

def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5:
            return True, t[1]
    return False, ''

if __name__ == '__main__':
    MakeVirusDB()

    if len(sys.argv) != 2:
        print('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1]
    fp = open('eicar.txt', 'rb')
    fbuf = fp.read()
    fp.close()

    m = hashlib.md5()
    m.update(fbuf)
    fmd5 = m.hexdigest()

    ret, vname = SearchVDB(fmd5)
    if ret == True:
        print('%s : %s'.format(fname, vname))
        print('remove? (y/n): ',end='')
        if 'y' == input():
            os.remove('eicar.txt')
        else:
            print('okay')
    else:
        print('%s : ok'.format(fname))