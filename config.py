import os

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:////' + os.path.join(basedir, 'telegramBot.db')
BOT_TOKEN = "807595377:AAEQAN0nVHrGRwqKZhsRatXIqgEPSsYQQ9I"
JWT_SECRET_KEY = 'telegramBot'

WEBHOOK_HOST = '185.251.89.190'
WEBHOOK_PORT = 8443
WEBHOOK_LISTEN = '0.0.0.0'

WEBHOOK_SSL_CERT = os.path.join(basedir, 'webhook_cert.pem')
WEBHOOK_SSL_PRIV = os.path.join(basedir, 'webhook_pkey.pem')

WEBHOOK_URL_BASE = "https://%s:%s" % (WEBHOOK_HOST, WEBHOOK_PORT)
WEBHOOK_URL_PATH = "/bot%s/" % (BOT_TOKEN)

REST_API_HOST = '0.0.0.0'
REST_API_PORT = 5000
REST_API = "http://%s:%s" % (REST_API_HOST, REST_API_PORT)


COMMANDS = """\n\nUse commands in the format: \n\n/register <code> <telegram_id> - register user in the system, code length - 8
/login - login user in the system
/logout - logout user from the system
/confirm <code> - confirm users registration in the system"""

NOT_REG = """Not registered in the system:
Ask <a href="tg://user?id=122473548">Ksenia</a> to register you."""

NOT_SU = 'Not authorized for this command'
NOT_AUTH = "Not authorized"
NOT_FORMAT = "Command does not match format"

AUTH = 'Successfully authorized'
LOGOUT = 'Logout successful'
LOGOUT_NOT = "Not completed"
REG_EXIST = 'User already registered in the system'
ERROR = 'Error occurred, try later'
CONF = 'Waiting users confirmation for 5 minutes'
CONF_OK = 'Confirmation completed'
CONF_EXP = 'Not completed, code expired'
CONF_WRONG = 'Not completed, wrong code'
