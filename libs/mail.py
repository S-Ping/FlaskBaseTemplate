__author__ = 'SPing'


from flask_mail import Mail, Message


mail = Mail()


class MailSender:
    """
    发送邮件
    """
    @staticmethod
    def send_mail(subject, to, body):
        message = Message(subject, recipients=[to], body=body)
        mail.send(message)
        return 0
