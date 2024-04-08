import os, hashlib

class KavMain:
    # 플러그인 엔진 초기화
    # 인자값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    def init(self, plugins_path):
        self.virus_name = 'Dummy-Test-File (not a virus)'
        self.dummy_pattern = 'Dummy Engine test file - KICOM Anti-Virus Project'

        return 0
    
    # 플러그인 엔진 종료
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    def uninit(self):
        del self.virus_name # 메모리 해제
        del self.dummy_pattern # 메모리 해제

        return 0
    
    # 악성코드 검사
    # 인자값 : filehandle - 파일 핸들
    #         filename - 파일 이름
    # 리턴값 : 악성코드 발견 여부, 악성코드 이름, 악성코드 ID 등등
    def scan(self, filehandle, filename):
        try:
            fp = open(filename)
            buf = fp.read(len(self.dummy_pattern))
            fp.close()

            # 다른 방식
            # with open(filename) as fp:
            #     buf = fp.read(len(self.dummy_pattern))

            if buf == self.dummy_pattern:
                return True, self.virus_name, 0
        except IOError:
            pass

        return False, '', -1
    
    # 악성코드 치료
    # 인자값 : filename - 파일 이름
    #        malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    def disinfect(self, filename, malware_id):
        try:
            if malware_id == 0:
                os.remove(filename)
                return True
        except IOError:
            pass
        return False
    

    # 진단/치료 가능한 악성코드의 목록
    # 리턴값 : 악성코드 목록
    def listvirus(self):
        vlist = list()
        vlist.append(self.virus_name)

        return vlist
    
    # 플러그인 엔진의 주요 정보
    # 리턴값 : 플로그인 엔진 정보
    def getinfo(self):
        info = dict()

        info['author'] = 'SMONGS' # 제작자
        info['version'] = '1.0' # 버전
        info['title'] = 'Virus Scan Engine' # 엔진 설명
        info['kmd_name'] = 'dummy' # 엔진 파일 이름
        
        return info