import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or 'MPk2WlUArcLeeU_iohzT'

    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    # 分页
    FLASKY_POSTS_PER_PAGE = 10
    # 上传图片
    UPLOADED_IMAGES_DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/images')
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    # 邮件服务器设置
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    # 163不支持STARTTLS
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = ('别院牧志', os.getenv('MAIL_USERNAME'))
    # redis 配置
    # REDIS_URL = "redis://:password@localhost:6379/0"
    REDIS_URL = "redis://localhost:6379/0"

    def __init__(self):
        pass

    @staticmethod
    def init_app(app):
        pass


class MySQLConfig:
    MYSQL_USERNAME = os.getenv('MYSQL_USER')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
    MYSQL_DB = os.getenv('MYSQL_DB')
    MYSQL_HOST = 'localhost:3306'
    MYSQL_CHARSET = 'utf8mb4'  # 为了支持 emoji 显示，需要设置为 utf8mb4 编码


class DevelopmentConfig(Config):
    DEBUG = True
    database = MySQLConfig.MYSQL_DB or 'iyblog_dev'
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MySQLConfig.MYSQL_USERNAME}:{MySQLConfig.MYSQL_PASSWORD}' \
                              f'@{MySQLConfig.MYSQL_HOST}/{database}?charset={MySQLConfig.MYSQL_CHARSET}'


class TestingConfig(Config):
    TESTING = True
    database = MySQLConfig.MYSQL_DB or 'iyblog_test'
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MySQLConfig.MYSQL_USERNAME}:{MySQLConfig.MYSQL_PASSWORD}' \
                              f'@{MySQLConfig.MYSQL_HOST}/{database}?charset={MySQLConfig.MYSQL_CHARSET}'


class ProductionConfig(Config):
    database = MySQLConfig.MYSQL_DB or 'iyblog_product'
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MySQLConfig.MYSQL_USERNAME}:{MySQLConfig.MYSQL_PASSWORD}' \
                              f'@{MySQLConfig.MYSQL_HOST}/{database}?charset={MySQLConfig.MYSQL_CHARSET}'


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
