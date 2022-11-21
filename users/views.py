from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
import jwt, datetime

# relative imports
from .models import User
from .serializers import UserSerializer

# Create your views here.

# api/register
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# api/login
class LoginView(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]
        
        user = User.objects.filter(email=email).first()
        
        if user is None:
            raise AuthenticationFailed("User Not Found")
        
        if not user.check_password(password):
            raise AuthenticationFailed("Invalid Credentials")
        
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }
        
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        response = Response()
        response.set_cookie(key="jwt", value=token, httponly=True)
        response.data  = {
            'jwt': token
        }
        
        return response
    
# api/user
class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get("jwt")
        
        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        
        return Response(serializer.data)
    
# api/logout
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logout successful'
        }
        return response
    
