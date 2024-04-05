import os

def CureDelete(fname):
    print('remove? (y/n): ',end='')
    if 'y' == input():
        return os.remove(fname)
    else:
        return print('okay~')