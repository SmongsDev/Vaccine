import k2rsa
import k2kmdfile

# with open('readme.txt', 'w') as f:
#     f.write('This is a sample text for readme.txt file.')

k2rsa.create_key('key.pkr','key.skr')

ret = k2kmdfile.make('readme.txt')
if ret:
    pu = k2rsa.read_key('key.pkr')
    k = k2kmdfile.KMD('readme.kmd', pu)
    print(k.body)