import os
import sys
from k2kmdfile_v2 import KMDTool

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage : kmake.py [python source]')
        print('Enter fname : ', end='')
        name = input()
    else:
        name = sys.argv[1]

    # 파일이 존재하는지 확인
    if not os.path.exists(name):
        print(f"Error: File '{name}' not found.")
        sys.exit(1)

    # KMDTool 객체 생성
    kmd_tool = KMDTool()

    # KMD 파일 생성
    if kmd_tool.make(name, True):
        print(f"KMD file '{name.split('.')[0]}.kmd' successfully created.")
    else:
        print("Error occurred while creating KMD file.")