__author__ = 'SPing'

import os
import string

from flask import Flask
from flask_jwt_extended import JWTManager
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import IntegrityError
from hashids import Hashids
from dotenv import load_dotenv, find_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import db
from libs.flask_logger import apply_request_log
from config import config
from common import pretty_result, http_code
from libs.flask_logger import register_logger
from libs.redis_cli import redis_store

hash_ids = Hashids(salt='hvwptlmj129d5quf', min_length=8, alphabet=string.ascii_lowercase + string.digits)


def create_app(config_name):
    app = Flask(__name__)

    # 加载配置文件
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    load_dotenv(find_dotenv())

    # 加载蓝图
    register_blueprint(app)

    # 加载插件
    register_plugin(app)

    return app


def register_blueprint(app):
    '''注册蓝图'''
    from routes import api_v1
    app.register_blueprint(api_v1, url_prefix='/api/v1')


def register_plugin(app):
    apply_json_encoder(app)  # JSON序列化
    apply_cors(app)  # 应用跨域扩展，使项目支持请求跨域
    handle_error(app)  # 统一处理异常
    db.init_app(app)  # 数据库初始化
    register_logger(__name__)  # 初始化日志
    redis_store.init_app(app)  # 初始化redis
    register_jwt(app)  # 初始化jwt
    register_limiter(app)  # 初始化频率限制

    if app.config['DEBUG']:
        apply_request_log(app)  # 打印请求日志


def apply_json_encoder(app):
    from libs.json_encoder import JSONEncoder
    app.json_encoder = JSONEncoder


def register_jwt(app):
    jwt = JWTManager(app)
    jwt.unauthorized_loader(missing_token_callback)
    jwt.expired_token_loader(expired_token_callback)
    jwt.invalid_token_loader(invalid_token_callback)


def missing_token_callback(error):
    return pretty_result(http_code.AUTHORIZATION_ERROR, 'Unauthorized')


def expired_token_callback(error):
    return pretty_result(http_code.AUTHORIZATION_ERROR, 'Expired token')


def invalid_token_callback(error):
    return pretty_result(http_code.AUTHORIZATION_ERROR, 'Invalid token')


def apply_cors(app):
    from flask_cors import CORS
    cors = CORS()
    cors.init_app(app, resources={"/*": {"origins": "*"}})


def register_limiter(app):
    limiter = Limiter(
        app,
        default_limits=['100/day'],
        key_func=get_remote_address
    )



def _access_control(response):
    """
    解决跨域请求
    """
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,HEAD,PUT,PATCH,POST,DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Max-Age'] = 86400
    return response


def handle_error(app):
    @app.errorhandler(429)
    def ratelimit_error(e):
        return pretty_result(http_code.RATELIMIT_ERROR)

    @app.errorhandler(400)
    def param_error(e):
        return pretty_result(http_code.PARAM_ERROR)

    @app.errorhandler(Exception)
    def framework_error(e):
        if not app.config['DEBUG']:
            return pretty_result(http_code.UNKNOWN_ERROR)  # 未知错误(统一为服务端异常)
        else:
            raise e
