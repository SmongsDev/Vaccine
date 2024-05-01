import datetime

def convert_date(self, t):
    """
    주어진 정수에서 날짜를 얻어 리턴합니다.
    """
    year = (t >> 9) & 0x7F
    month = (t >> 5) & 0x0F
    day = t & 0x1F
    return year, month, day

def convert_time(self, t):
    """
    주어진 정수에서 시간을 얻어 리턴합니다.
    """
    hour = (t >> 11) & 0x1F
    minute = (t >> 5) & 0x3F
    second = (t & 0x1F) * 2
    return hour, minute, second

def get_now_date(self, now=None):
    """
    현재 날짜를 2byte 날짜 값으로 변환합니다.
    """
    if now is None:
        now = datetime.datetime.now()
    year = now.year - 2000
    month = now.month
    day = now.day
    print(year, month, day)
    return (year << 9) | (month << 5) | day

def get_now_time(self, now=None):
    """
    현재 시간을 2byte 시간 값으로 변환합니다.
    """
    if now is None:
        now = datetime.datetime.now()
    hour = now.hour
    minute = now.minute
    second = now.second // 2
    return (hour << 11) | (minute << 5) | second