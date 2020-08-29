__author__ = 'SPing'


from datetime import date, datetime
from flask.json import JSONEncoder as _JSONEncoder


class JSONEncoder(_JSONEncoder):
    def default(self, obj):
        # 如果o是时间戳
        # datetime.now() ==> datetime.datetime(2020, 4, 8, 9, 4, 57, 26881)
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%SZ')
        # date.today() ==> datetime.date(2020, 4, 8)
        if isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        return super(JSONEncoder).default(obj)
