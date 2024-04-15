def ScanStr(fp, offset, mal_str):
    size = len(mal_str)

    fp.seek(offset)
    buf = fp.read(size)
    
    if buf.decode('utf-8') == mal_str:
        return True
    else:
        return False
    

fp = open('eicar.txt', 'rb')
print(ScanStr(fp, 0, 'X5O'))
fp.close()