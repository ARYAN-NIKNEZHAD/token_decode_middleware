
import jwt
from django.contrib.auth.models import User

from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from your_core_prject.settings import SECRET_KEY
from rest_framework import status











class TokenDecodeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        token = auth_header
        if token:
            try:
                decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                token_type = decoded_token.get("type")
                if token_type == "refresh":
                    raise jwt.InvalidTokenError
                
                user = User.objects.filter(pk=decoded_token.get("id")).first()
                if user:
                    # user now is authenticated
                    request.user = user

            except jwt.InvalidSignatureError:
                response = Response({"Error": "Signature of this jwt token is invalid !!"}, status=status.HTTP_401_UNAUTHORIZED)
                response.accepted_renderer = JSONRenderer()
                response.accepted_media_type = "application/json"
                response.renderer_context = {}
                response.render()
                return response

            except jwt.DecodeError:
                response = Response({"Error": "this jwt token is invalid!!"}, status=status.HTTP_401_UNAUTHORIZED)
                response.accepted_renderer = JSONRenderer()
                response.accepted_media_type = "application/json"
                response.renderer_context = {}
                response.render()
                return response
            
            except jwt.ExpiredSignatureError:
                response = Response({"Error": "this jwt token is Expired!!"}, status=status.HTTP_401_UNAUTHORIZED)
                response.accepted_renderer = JSONRenderer()
                response.accepted_media_type = "application/json"
                response.renderer_context = {}
                response.render()
                return response
            
            except jwt.InvalidTokenError:
                response = Response({"Error": "this jwt token is invalid!!"}, status=status.HTTP_401_UNAUTHORIZED)
                response.accepted_renderer = JSONRenderer()
                response.accepted_media_type = "application/json"
                response.renderer_context = {}
                response.render()
                return response
        
        response = self.get_response(request)
        
        return response