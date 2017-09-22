import jwt
import json

<<<<<<< HEAD
def __generate_jwt(self,user):
            

            payload = {
                'iss': user,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),#utc_timestamp() + 15,
                'nbf': datetime.datetime.utcnow(),
                'iat': datetime.datetime.utcnow()
            }

            headers = {
                "alg": "HS256",
                "typ": "JWT"
            }

  
            encoded = jwt.encode(payload, key, headers=headers)


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

            key='secret'
            try:
                payload = jwt.decode(encoded, key, algorithms=['HS256'],options=options) 
            except jwt.InvalidTokenError:
                pass  # do something sensible here, e.g. return HTTP 403 status code
                logging.debug("Invalid TOKEN: ")
                logging.debug(InvalidTokenError)
            except jwt.ExpiredSignatureError:
                pass
                logging.debug("Expiration Time ")
                
=======
encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
jwt.decode(encoded, 'secret', algorithms=['HS256'])
>>>>>>> a37ff0346dca6d5215403077de7096b28dbdfc37



"""
#header
{
	"typ":"JWT",
	"alg":"HS256"
}
<<<<<<< HEAD
=======

>>>>>>> a37ff0346dca6d5215403077de7096b28dbdfc37
#payload - Dados
{
  "iss": "localhost", #Origem do token
  "sub": "1234567890", #id do usuario
  "exp": 1300819380, #timestamp de quando o token expira
  "user": "Daniel",
  "admin": true
<<<<<<< HEAD
}
=======

}

>>>>>>> a37ff0346dca6d5215403077de7096b28dbdfc37
#VERIFY SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret 
)
<<<<<<< HEAD
encodedString = base64UrlEncode(header) + "." + base64UrlEncode(payload); + "." +
HMACSHA256(encodedString, 'secret');
"""
=======

encodedString = base64UrlEncode(header) + "." + base64UrlEncode(payload); + "." +
HMACSHA256(encodedString, 'secret');
"""

>>>>>>> a37ff0346dca6d5215403077de7096b28dbdfc37
