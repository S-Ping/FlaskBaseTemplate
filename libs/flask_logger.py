__author__ = 'SPing'
import json
import time
import logging
import os
from logging.handlers import RotatingFileHandler

from flask import g, Response, request, _request_ctx_stack


def register_logger(name):
    APP_LOG_FP = 'logs/app.log'
    logger = logging.getLogger(name)
    dir_name, _ = os.path.split(APP_LOG_FP)
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)
    logger.setLevel(logging.INFO)
    # 指定logger输出格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)-2s[%(name)s]: %(message)s')
    # 文件日志
    file_handler = RotatingFileHandler(APP_LOG_FP, maxBytes=10 * 1024 * 1024, backupCount=7)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    file_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    # 控制台日志
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.formatter = formatter  # 也可以直接给formatter赋值
    # 为logger添加的日志处理器，可以自定义日志处理器让其输出到其他地方
    # logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    # 指定日志的最低输出级别，默认为WARN级别
    # logger.setLevel(logging.DEBUG)
    return logger


REG_XP = r'[{](.*?)[}]'
OBJECTS = ['user', 'response', 'request']


# 记录每次请求的性能
def apply_request_log(app):
    @app.before_request
    def request_cost_time():
        g.request_start_time = time.time()
        g.request_time = lambda: "%.5f" % (time.time() - g.request_start_time)

    @app.after_request
    def log_response(res):
        message = '[%s] -> [%s] from:%s costs:%.3f ms' % (
            request.method,
            request.path,
            request.remote_addr,
            float(g.request_time()) * 1000
        )
        req_body = request.get_json() if request.get_json() else {}
        data = {
            'path': _request_ctx_stack.top.request.view_args,
            'query': request.args,
            'body': req_body
        }
        message += '\n\"data\": ' + json.dumps(data, indent=4, ensure_ascii=False)
        # 设置颜色开始(至多3类参数，以m结束)：\033[显示方式;前景色;背景色m
        print('\033[0;34m')
        if request.method in ('GET', 'POST', 'PUT', 'DELETE'):
            print(message)
        print('\033[0m')  # 终端颜色恢复
        return res


# 记录用户的登录日志
def record_login_log(uid, message=''):
    '''
    :param uid: 用户id
    :param msg: 提示消息
    :return:
    '''
    # user = User.get_or_404(id=uid)
    # remote_addr, user_agent = request.remote_addr, request.user_agent
    # location = parse_location_by_ip(ip=remote_addr)
    #
    # LoginLog.create(user_id=user.id, user_name=user.username,
    #                 ip_addr=remote_addr, location=location, browser=user_agent.browser,
    #                 os=user_agent.platform, message=message, status=True)


# 基于ip解析真实地址
def parse_location_by_ip(ip: str):
    '''
    :param ip: ip地址
    :return: ip所在的省市
    '''
    if ip == '127.0.0.1' or ip.startswith('192.168.'):
        return "内网IP"
    from common.http_util import HTTP
    try:
        url = 'http://whois.pconline.com.cn/ipJson.jsp?{0}&json=true'.format(ip)
        json_data = HTTP.get(url)
        return '{0} {1}'.format(json_data['pro'], json_data['city'])
    except Exception:
        return '获取地理位置异常 {ip}'.format(ip=ip)
