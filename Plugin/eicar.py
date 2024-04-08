import os, hashlib

class KavMain:
    # 플러그인 엔진 초기화
    # 인자값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    def init(self, plugins_path):
        return 0
    
    # 플러그인 엔진 종료
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    def uninit(self):
        return 0
    
    # 악성코드 검사
    # 인자값 : filehandle - 파일 핸들
    #         filename - 파일 이름
    # 리턴값 : 악성코드 발견 여부, 악성코드 이름, 악성코드 ID 등등
    def scan(self, filehandle, filename):
        try:
            mm = filehandle
            
            size = os.path.getsize(filename)
            if size == 68:
                m = hashlib.md5()
                m.update(mm[:68])
                fmd5 = m.hexdigest()

                if fmd5 == '44d88612fea8a8f36de82e1278abb02f':
                    return True
                
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
        vlist.append('EICAR-Test-File (not a virus)')

        return vlist
    
    # 플러그인 엔진의 주요 정보
    # 리턴값 : 플로그인 엔진 정보
    def getinfo(self):
        info = dict()

        info['author'] = 'SMONGS' # 제작자
        info['version'] = '1.0' # 버전
        info['title'] = 'Virus Scan Engine' # 엔진 설명
        info['kmd_name'] = 'eicar' # 엔진 파일 이름

        return info
        