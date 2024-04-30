import sys
import k2rsa_v3

if __name__ == '__main__':
    pu_fname = 'key.pkr'
    pr_fname = 'key.skr'

    if len(sys.argv) == 3:
        pu_fname = sys.argv[1]
        pr_fname = sys.argv[2]
    elif len(sys.argv) != 1:
        print('Usage: mkkey.py [[PU filename] [PR filename]]')
        exit(0)

    rsa = k2rsa_v3.RSA()
    rsa.create_key(pu_fname, pr_fname, True)