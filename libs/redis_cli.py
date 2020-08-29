from flask_redis import FlaskRedis

from redis import StrictRedis

redis_store = FlaskRedis.from_custom_provider(StrictRedis)
