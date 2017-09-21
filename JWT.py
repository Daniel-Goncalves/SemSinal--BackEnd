import jwt
import json

encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
jwt.decode(encoded, 'secret', algorithms=['HS256'])



"""
#header
{
	"typ":"JWT",
	"alg":"HS256"
}

#payload - Dados
{
  "iss": "localhost", #Origem do token
  "sub": "1234567890", #id do usuario
  "exp": 1300819380, #timestamp de quando o token expira
  "user": "Daniel",
  "admin": true

}

#VERIFY SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret 
)

encodedString = base64UrlEncode(header) + "." + base64UrlEncode(payload); + "." +
HMACSHA256(encodedString, 'secret');
"""

