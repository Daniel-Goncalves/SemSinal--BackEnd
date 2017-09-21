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

class UserHandler(tornado.web.RequestHandler):

    @gen.coroutine
    def __generate_hash(self, pwd_string,salt,maxtime=0.5):
        hashed_pass = scrypt.encrypt(pwd_string,salt,maxtime)
        encoded = base64.b64encode(hashed_pass)
        return encoded.decode('utf-8')

    @gen.coroutine
    def __get_db_collection(self):
        client = motor.motor_tornado.MotorClient()
        client = motor.motor_tornado.MotorClient('localhost', 27017)
        db = client['UsersDB']
        return db['users']

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

            #Código referente a JWT

            options = {
               'verify_signature': True,
               'verify_exp': True,         #expiration time
               'verify_nbf': True,         #not before time
               'verify_iat': True,         #issued at
               'verify_aud': True,         #audience
               'require_exp': False,
               'require_iat': False,
               'require_nbf': False
            }

            encoded = jwt.encode( {'some': 'payload'}, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'})
            logging.debug('Hash = ')
            logging.debug(encoded)
            try:
                payload = jwt.decode(encoded, 'secret', algorithms=['HS256'],options=options) 
            except jwt.InvalidTokenError:
                pass  # do something sensible here, e.g. return HTTP 403 status code
                logging.debug("Invalid TOKEN: ")
                logging.debug(InvalidTokenError)
            except jwt.ExpiredSignatureError:
                pass
                #Do something    


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
                self.set_status(403)  # http 200 ok
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
        self.set_status(401)  # http 200 ok
        self.write(response)  # sets application/json header
        self.finish()

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
            #"pwdHash": str(pwd_hash.decode('utf8'))
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
            response = {
                "id": str(result["_id"]),
                "user": result["user"]
            }
            logging.debug(response)
            self.set_status(200)  # http 200 ok
            self.write(response)  # sets application/json header
            self.finish()
            return
