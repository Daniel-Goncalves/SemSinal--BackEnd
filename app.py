# Tornado Web Server
import tornado.ioloop
import tornado.web
import tornado.httpserver
import motor
import sys
import logging
import os
import time
import redis

from handlers.ConfigHandler import ConfigHandler
from handlers.HexagonHandler import HexagonHandler
from handlers.AvailableHandler import AvailableHandler, AvailableCarrierHandler, AvailableTechHandler, AvailableDevicesHandler
from handlers.ParametersHandler import ParametersHandler
from handlers.CalculatorHandler import HexagonCalculatorHandler
from handlers.CalculatorHandler import PowerCalculatorHandler
from handlers.StatisticsHandler import AverageSstrHandler
from handlers.StatisticsHandler import RankingHandler
from handlers.DummyHandler import DummyHandler
from handlers.PointHandler import PointHandler
from handlers.UserHandler import UserHandler
from handlers.UserHandler import LoginHandler
from handlers.ErbsHandler import ErbsHandler
from handlers.TileHandler import TileHandler

def create_web_server():

    # Diretorio onde sao salvos os conteudos estaticos
    static_path = os.path.join(os.path.dirname(__file__), "static")

    # Roteamento para as diferentes URIs
    handlers = [
        (r"/hexagon", HexagonHandler),
        (r"/available", AvailableHandler),
        (r"/parameters", ParametersHandler),
        (r"/calculator/hexagon", HexagonCalculatorHandler),
        (r"/calculator/power", PowerCalculatorHandler),
        (r"/available/carriers", AvailableCarrierHandler),
        (r"/available/tech", AvailableTechHandler),
        (r"/devices", AvailableDevicesHandler),
        (r"/available/devices", AvailableDevicesHandler),
        (r"/avgsstr", AverageSstrHandler),
        (r"/statistics/avgsstr", AverageSstrHandler),
        (r"/ranking", RankingHandler),
        (r"/statistics/ranking", RankingHandler),
        (r"/dummy", DummyHandler),
        (r"/point", PointHandler),
        (r"/users/new", UserHandler),
        (r"/users/login", LoginHandler),
        (r"/erbs", ErbsHandler),
        (r"/tiles/.*", TileHandler),
        (r"/(.*)", tornado.web.StaticFileHandler, {'path': static_path, "default_filename": "index.html"})
    ]

    return tornado.web.Application(handlers)

def __configure_logging():
    log_level = ConfigHandler.log_level
    numeric_level = getattr(logging, log_level.upper(), None)
    logging.basicConfig(level=numeric_level, filename=ConfigHandler.log_file)

if __name__ == '__main__':

    # Le a porta a ser usada a partir da configuracao lida
    http_listen_port = sys.argv[1]

    web_app = create_web_server()
    ioloop = tornado.ioloop.IOLoop.instance()

    # Pool do Motor (MongoDB)
    mongo_dsn = 'mongodb://' \
                + ConfigHandler.mongodb_user + ':' \
                + ConfigHandler.mongodb_password + '@' \
                + ConfigHandler.mongodb_address + '/' \
                + ConfigHandler.mongodb_db_name

    web_app.mongodb = motor.motor_tornado.MotorClient(
        host=mongo_dsn,
        minPoolSize=ConfigHandler.mongodb_min_pool_size,
        connect=True,
        appname="SemSinalBackend"
    )[ConfigHandler.mongodb_db_name]

    web_app.redis_client = redis.Redis(host=ConfigHandler.config["database"]["redis"]["host"],\
                                       port=int(ConfigHandler.config["database"]["redis"]["port"]),\
                                       db=int(ConfigHandler.config["database"]["redis"]["db"]),\
                                       socket_connect_timeout=int(ConfigHandler.config["database"]["redis"]["socket_connection_timeout"]))

    __configure_logging()

    web_app.listen(http_listen_port)
    logging.debug('Started application on port %d', int(http_listen_port))

    ioloop.start()