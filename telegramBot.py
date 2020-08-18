from flask import Flask, jsonify, request
from flask_restful import Resource, Api
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token
)
from requests import put, get, post, delete
from db_setup import setup, User
import logging
import telebot
import config
import redis

app = Flask(__name__)
api = Api(app)

app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY
jwt = JWTManager(app)

bot = telebot.TeleBot(config.BOT_TOKEN)

redis = redis.Redis()

DBSession = setup()

logger = telebot.logger
telebot.logger.setLevel(logging.INFO)


class SetWebhook(Resource):
    """SetWebhook class allows to set webhook with GET request"""

    def get(self):
        bot.remove_webhook()
        bot.set_webhook(url=config.WEBHOOK_URL_BASE + config.WEBHOOK_URL_PATH, certificate=open(config.WEBHOOK_SSL_CERT, 'r'))
        return jsonify(status=200)


class Users(Resource):
    """Users class represents CRUD of user objects"""

    def get(self, tg_id):
        try:
            session = DBSession()
            user = session.query(User).filter_by(telegram_id=tg_id).first()
            user = user.as_dict()
            user['status'] = 200
            return jsonify(user)
        except Exception:
            return jsonify(status=404)

    def put(self, tg_id):
        try:
            session = DBSession()
            user = session.query(User).filter_by(telegram_id=tg_id).first()
            user.token = create_access_token(identity=tg_id)
            session.commit()
            return jsonify(status=200)
        except Exception:
            return jsonify(status=404)

    def delete(self, tg_id):
        try:
            session = DBSession()
            user = session.query(User).filter_by(telegram_id=tg_id).first()
            user.token = None
            session.commit()
            return jsonify(status=200)
        except Exception:
            return jsonify(status=404)

    def post(self, tg_id):
        session = DBSession()
        code = request.form['code']
        name = request.form['name']
        redis_code = redis.get(tg_id)
        print(redis_code)
        if redis_code is None:
            return jsonify(status=404)
        if redis_code.decode("utf-8") == code:
            user = User(telegram_id=tg_id, super_user=False, name=name)
            session.add(user)
            session.commit()
            return jsonify(status=201)
        else:
            return jsonify(status=400)


class Redis(Resource):
    """Redis class process register with POST request"""

    @jwt_required
    def post(self):
        code = request.form['code']
        telegram_id = request.form['telegram_id']
        user = get('{0}/users/{1}'.format(config.REST_API, telegram_id)).json()
        if user['status'] == 404:
            redis.set(name=telegram_id, value=code, ex=300)
            return jsonify(status=200)
        else:
            return jsonify(status=400)


class Webhook(Resource):
    """Webhook class process webhook calls with POST request"""

    def post(self):
        bot.process_new_updates([telebot.types.Update.de_json(request.stream.read().decode("utf-8"))])
        return jsonify(status=200)


api.add_resource(SetWebhook, '/set_webhook')
api.add_resource(Users, '/users/<int:tg_id>')
api.add_resource(Webhook, config.WEBHOOK_URL_PATH)
api.add_resource(Redis, '/redis')


@bot.message_handler(commands=['start'])
def start(message):
    """command /start - return list of available commands"""
    bot.send_message(message.from_user.id, "ID:{0} ".format(message.from_user.id) + config.COMMANDS)


@bot.message_handler(commands=['login'])
def login(message):
    """command /login - login user in the system"""
    try:
        telegram_id = message.from_user.id
        response = put('{0}/users/{1}'.format(config.REST_API, telegram_id)).json()
        if response['status'] == 200:
            text_message = config.AUTH
        elif response['status'] == 404:
            text_message = config.NOT_REG
        else:
            text_message = config.NOT_AUTH
    except Exception:
        text_message = config.NOT_FORMAT
    finally:
        bot.send_message(message.from_user.id, text_message, parse_mode="HTML")


@bot.message_handler(commands=['logout'])
def logout(message):
    """command /logout - logout user from the system"""
    telegram_id = message.from_user.id
    response = delete('{0}/users/{1}'.format(config.REST_API, telegram_id)).json()
    if response['status'] == 200:
        text_message = config.LOGOUT
    else:
        text_message = config.LOGOUT_NOT
    bot.send_message(message.from_user.id, text_message)


@bot.message_handler(commands=['register'])
def register(message):
    """command /register <code> <telegram_id> - register user in the system, code length - 8"""
    try:
        user_id = message.from_user.id
        user = get('{0}/users/{1}'.format(config.REST_API, user_id)).json()

        if not user['super_user']:
            raise Exception(config.NOT_SU)

        headers = {
            'Authorization': 'Bearer {}'.format(user['token'])
        }

        params = message.text[9:].split()
        if len(params[0]) == 8 and params[0].isdigit() and params[1].isdigit():
            code = params[0]
            telegram_id = params[1]
        else:
            raise Exception(config.NOT_FORMAT)
        try:
            response = post('{0}/redis'.format(config.REST_API),
                            data={'code': code, 'telegram_id': telegram_id},
                            headers=headers).json()

            if response['status'] == 200:
                text_message = config.CONF
            elif response['status'] == 400:
                text_message = config.REG_EXIST
            else:
                text_message = config.ERROR
        except Exception:
            text_message = config.NOT_AUTH
    except Exception as e:
        if e == config.NOT_SU:
           text_message = e
        elif e == "'status'":
           text_message = config.NOT_AUTH
        else:
           text_message = config.NOT_FORMAT
    finally:
        bot.send_message(message.from_user.id, text_message)


@bot.message_handler(commands=['confirm'])
def confirm(message):
    """command /confirm <code> - confirm users registration in the system"""
    try:
        telegram_id = message.from_user.id
        code = message.text[8:].strip()
        name = message.from_user.first_name
        response = post('{0}/users/{1}'.format(config.REST_API, telegram_id), data={'name': name, 'code': code}).json()
        if response['status'] == 201:
            text_message = config.CONF_OK
        elif response['status'] == 404:
            text_message = config.CONF_EXP
        else:
            text_message = config.CONF_WRONG
    except Exception:
        text_message = config.NOT_FORMAT
    finally:
        bot.send_message(message.from_user.id, text_message)


# bot.polling()

if __name__ == '__main__':
    app.run(host=config.WEBHOOK_LISTEN,
            port=config.WEBHOOK_PORT,
            ssl_context=(config.WEBHOOK_SSL_CERT, config.WEBHOOK_SSL_PRIV),
            debug=True)
