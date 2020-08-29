__author__ = 'SPing'

from enum import Enum


class ClientTypeEnum(Enum):
    '''客户端登录方式类型
    站内: 手机号mobile 邮箱email 用户名username
    第三方应用: 微信weixin 腾讯qq 微博weibo
    '''
    USERNAME = 100  # 用户名
    EMAIL = 101  # 邮箱登录
    MOBILE = 102  # 手机登录
    # 微信
    WX_MINA = 200  # 微信小程序(该小程序的openid)
    WX_MINA_UNIONID = 201  # 微信唯一ID(全网所有))
    WX_OPEN = 202  # 微信第三方登录(Web端)
    WX_ACCOUNT = 203  # 微信第三方登录(公众号H5端)

    # 腾讯QQ
    QQ = 300  # QQ登录


class ScopeEnum(Enum):
    '''
    用法：ScopeEnum(1) == ScopeEnum.COMMON # True
    '''
    COMMON = 1  # 普通用户
    ADMIN = 2  # 管理员


class ArticleTypeEnum(Enum):
    '''文章类型'''
    TECH = 1  # 技术文章
    LIFE = 2  # 生活随笔
    SOUP = 3  # 鸡汤文章
    METTING = 4  # 会议
    RELAX = 5  # 放松一下
    ABOUT = 6  # 关于我们


class OperTyepEnum(Enum):
    '''操作日志类型'''
    OTHER = 0 # 其他
    CREATE = 1  # 新增
    UPDATE = 2  # 修改
    DELETE = 3  # 删除
    GRANT = 4  # 授权
    EXPORT = 5  # 导出
    IMPORT = 6  # 导入
    FORCE = 7  # 强退
    GEN_CODE = 8  # 生成代码
    CLEAN = 9  # 清空数据
