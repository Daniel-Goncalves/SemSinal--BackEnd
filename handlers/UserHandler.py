import hashlib
import binascii
import base64
import logging
import json
import tornado.web
from tornado import gen
import jwt
import motor.motor_tornado
import os
import scrypt
import datetime
from handlers.ConfigHandler import ConfigHandler

class UserHandler(tornado.web.RequestHandler):

    @gen.coroutine
    def __generate_hash(self, pwd_string,salt,maxtime=0.5):
        hashed_pass = scrypt.encrypt(pwd_string,salt,maxtime)
        encoded = base64.b64encode(hashed_pass)
        return encoded.decode('utf-8')

    @gen.coroutine
    def __get_db_collection(self):
        #client = motor.motor_tornado.MotorClient()
        #client = motor.motor_tornado.MotorClient('localhost', 27017)
        #db = client['UsersDB']
        return self.application.mongodb.Users#db['users']
       
    @gen.coroutine
    def __check_user_and_pw(self, user,pw):
        if user == "" or user == None or pw == "" or pw == None:
            return False
        elif len(pw) < 9:
            return False
        else:
            return True

    @gen.coroutine
    def post(self):
		
        try:
            post_data = tornado.escape.json_decode(self.request.body)
        except:
            response = {
                'error': 'incorrect json'
            }
            self.set_status(400)  # http 200 ok
            self.write(response)  # sets application/json header
            self.finish()
            return

        logging.debug('New User post_data')
        logging.debug(post_data)

        user = post_data["user"]
        pw = post_data["pwd"]

        if not (yield self.__check_user_and_pw(user, pw)):
            response = {
                "status": "error",
                "result": "one of the fields is not valid"
            }
            self.set_status(400)  # http 200 ok
            self.write(response)  # sets application/json header
            self.finish()
            return
        else:
            # Verifica se o usuario ja existe
            query_object = {
                "user": user
            }

            
            collection = yield self.__get_db_collection()

            cursor = yield collection.find_one(query_object)

            #cursor = self.application.mongodb.Users.find_one(query_object)

            result = bool(cursor)        #True se encontrado usuario
            #result = yield cursor.to_list(length=1)
				
            logging.debug('found on database user: ')
            logging.debug(cursor)
            #logging.debug(result[0])

            if result:
                response = {
                    "status" : "error",
                    "result" : "user already exists"
                }
                self.set_status(403)  # http 403 forbidden
                self.write(response)  # sets application/json header
                self.finish()
                return

            #Verificar HASH
            else:
                datalength = 64
                salt = os.urandom(datalength)
                hashed_pw = yield self.__generate_hash(pw,salt)
                new_object = {
                    "user": user,
                    "pwdHash": hashed_pw,
                    "salt": salt
                }
                #future = collection.insert_one(new_object)
                #future = self.application.mongodb.users.insert_one(new_object)
                #result = yield future
                _id = yield collection.insert(new_object)

                logging.debug('created id:')
                logging.debug(_id)
    
                response = {
                    "status": "ok",
                    "result": "user created",
                    "id": str(_id),
                    "JWT": str(encoded)
                }
                self.set_status(200)  # http 200 ok
                self.write(response)  # sets application/json header
                self.finish()
                return



class LoginHandler(tornado.web.RequestHandler):

    @gen.coroutine
    def __decode_hash(self, pwd_string,salt,maxtime=0.5):
        decoded = base64.b64decode(pwd_string.encode('utf-8'))
        return scrypt.decrypt(decoded,salt,maxtime)

    @gen.coroutine
    def __get_db_collection(self):
        client = motor.motor_tornado.MotorClient()
        client = motor.motor_tornado.MotorClient('localhost', 27017)
        db = client['UsersDB']
        return db['users']   

    @gen.coroutine
    def __login_unauthorized(self):
        response = {
                "status": "error",
                "result": "unauthorized"
        }
        logging.debug('unauthorized')
        self.set_status(401)  # http 401 unauthorized
        self.write(response)  # sets application/json header
        self.finish()

    @gen.coroutine
    def __generate_jwt(self,user):
            payload = {
                'iss': user,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
                'nbf': datetime.datetime.utcnow(),
                'iat': datetime.datetime.utcnow()
            }

            headers = {
                "alg": "HS256",
                "typ": "JWT"
            }

            key = ConfigHandler.jwt_token
            encoded = jwt.encode(payload, key, headers=headers)
            return encoded



    @gen.coroutine
    def post(self):

        try:
            post_data = tornado.escape.json_decode(self.request.body)
        except:
            response = {
                'error': 'incorrect json'
            }
            self.set_status(400)  # http 200 ok
            self.write(response)  # sets application/json header
            self.finish()
            return

        logging.debug('login user post_data: {0}'.format(post_data))

        user = post_data["user"]
        pw = post_data["pwd"]#.encode('utf8')

        logging.debug('pw: ')
        logging.debug(pw)

        #pwd_hash = yield self.__generate_hash(pw)

        query_object = {
            "user":user
            #"pwdHash": str(pwd_hash.decode('utf8'))    #Ao inves de usar o hash de novo e comparar, recupera o hash do DB e usa decrypt

        }

        logging.debug('login user query_object: {0}'.format(query_object))

        #result = yield self.application.mongodb.users.find_one(query_object)
        collection = yield self.__get_db_collection()
        result = yield collection.find_one(query_object)

        logging.debug('login result: {0}'.format(result))

        if result == None or len(result) == 0:
            # unauthorized
            self.__login_unauthorized()
            return

        #Usuario existe na database
        #Próximo passo: verificar senha
        db_pw = result["pwdHash"]   #Hash no Banco de dados
        salt = result["salt"]
        db_pw = yield self.__decode_hash(db_pw,salt)

        if pw != db_pw:
            # unauthorized
            self.__login_unauthorized()
            return
            
        else:
            jwt = self.__generate_jwt(result["user"])
            #token = base64.b64encode(jwt).decode('utf-8')
            response = {
                "id": str(result["_id"]),
                "user": result["user"],
                "token": str(jwt)
           	}
            logging.debug(response)
            self.set_status(200)  # http 200 ok
            self.write(response)  # sets application/json header
            self.finish()
            return


