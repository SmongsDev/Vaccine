import os, sys
import k2kmdfile

if __name__ == '__main__':
    name = ''
    if len(sys.argv) != 2:
        print('Uasge : kmake.py [python source]')
        # exit()
        print('Enter fname : ', end='')
        name = input()
    else:
        name = sys.argv[1]
    
    k2kmdfile.make(name, True)