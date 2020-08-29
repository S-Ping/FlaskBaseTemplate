__author__ = 'SPing'


import datetime


class DateTime:
    @staticmethod
    def is_datetime(time_obj):
        assert isinstance(time_obj, datetime.datetime)

    def make_strftime(self, time_obj):
        """
        make to str
        :param time_obj:
        :return:
        """
        self.is_datetime(time_obj)
        return time_obj.strftime('%Y-%m-%d %H:%M:%S')

    def year(self, time_obj):
        if time_obj:
            self.is_datetime(time_obj)
            return time_obj.year
