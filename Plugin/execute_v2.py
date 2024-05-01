import os
import k2rsa_v3
import k2kmdfile_v2
# RSA 키 생성
rsa = k2rsa_v3.RSA()
rsa.create_key('key.pkr', 'key.skr')

# 테스트용 텍스트 파일 생성
with open('test.txt', 'w') as f:
    f.write('This is a sample text for testing KMD file creation and decryption.')

# KMD 파일 생성
k2kmdfile_v2.KMDTool().make('test.txt', True)

# KMD 파일 복호화 및 출력
pu_key = rsa.read_key('key.pkr')
kmd = k2kmdfile_v2.KMD('test.kmd', pu_key)
print("Decrypted data:")
print(kmd.body)