from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.models import AuthToken
from rest_framework.permissions import IsAuthenticated
from .serializers import RegisterSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from django.http import HttpResponse


@api_view(['GET'])
def home(request):
    return HttpResponse("""
        <html>
            <head>
                <title>Admin Dashboard</title>
            </head>
            <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
                <h1>Welcome to the Auth Backend</h1>
                <p>This is a custom admin landing page.</p>
                <p><a href="/admin/">Go to Django Admin</a></p>
            </body>
        </html>
    """)


@api_view(['POST'])
def login_api(request):
    serializer = AuthTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data['user']
    _, token = AuthToken.objects.create(user)

    print("Token created for:", user.username)
    print("Token:", token)
 
    return Response({
        'user_info':{
            'id' : user.id,
            'username' : user.username,
            'email' : user.email
            },
        'token' : token
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_data(request):
    user = request.user

    if user.is_authenticated:
        return Response({
        'user_info':{
            'id' : user.id,
            'username' : user.username,
            'email' : user.email,
            'first_name' : user.first_name,
            'last_name' : user.last_name,
            },
        })
    
    return Response({'error' : 'not authenticated'}, status=400)



@api_view(['POST'])
def register_api(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()
    _, token = AuthToken.objects.create(user)

    return Response({
        'user_info' : {
            'id' : user.id,
            'username' : user.username,
            'email' : user.email
            },
        'token' : token
    })
    


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete(request):
    user = request.user
    user.delete()

    return Response({"message": "Account deleted successfully."}, status=200)



@api_view(['POST'])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    reset_link = serializer.save()
    return Response({"message": "Password reset link sent (check console in dev)", "link": reset_link})




@api_view(['POST'])
def reset_password(request):
    serializer = ResetPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"message": "Password has been reset successfully."})
