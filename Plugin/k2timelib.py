import time

# 날짜 리턴
def convert_date(t):
    y = ((t & 0xFE00) >> 9) + 1980
    m = (t & 0x01E0) >> 5
    d = (t & 0x001F)

    print('{}-{}-{}'.format(y,m,d))
    return y, m, d

# 시간 리턴
def convert_time(t):
    h = (t & 0xF800) >> 11
    m = (t & 0x07E0) >> 5
    s = (t & 0x001F) * 2

    print('{}:{}:{}'.format(h,m,s))
    return h, m, s

# 현재 날짜 2byte 날짜 값으로 변환
def get_now_date(now=None):
    if not now:
        now = time.gmtime()

    t_y = now.tm_year - 1980
    t_y = (t_y << 9) & 0xFE00
    t_m = (now.tm_mon << 5) & 0x01E0
    t_d = now.tm_mday & 0x001F

    return (t_y | t_m | t_d) & 0xFFFF
    
# 현재 시간을 2byte 시간 값으로 변환
def get_now_time(now=None):
    if not now:
        now = time.gmtime()

    t_h = (now.tm_hour << 11) & 0xF800
    t_m = (now.tm_min << 5) & 0x07E0
    t_s = int(now.tm_sec / 2) & 0x001F

    return (t_h | t_m | t_s) & 0xFFFF