from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.response import Response
from django.contrib.auth.models import User
from usermanagement_app.decorators import *
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import Group
from django.http import HttpResponse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode 
from django.utils.encoding import force_bytes
from .serializers import UserSerializer  # Adjust the import based on your project structure
from .models import *
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken


# Create your views here.
@api_view(['GET'])
def getRoutes(request):
    routes = [
        {
        "endpoints": "endpoints",
        "api token" : '/api/token',
        "api refresh":'/api/token/refresh',
        "sign up":"api/signup",
        "sign up":"api/login",
        'user_list':"user_list",
        'forget password': 'forget_password',
        'user profile': 'user_profile',
        'update profile': 'update_profile',
        "add new user": "addnew_user",
        "change password": "change_password",
        "delete user": "delete_user",
        "deactivate user": "deactivate_user",
        'reset password': "reset_password"
        }
    ]
    return Response(routes)


@api_view(['POST'])
def signuppage(request):
    if request.method=="POST":

        headers = request.data
        print()
        print(headers)
        
        Username=headers['Username']
        Email = headers['Email']
        Password = headers['Password']
       
        #ConfirmPassword = headers['confirm_password']
        try:
            
            user=User.objects.create_user(username=Username, email=Email, password=Password)
            group = Group.objects.get(name='normal_users')
            user.groups.add(group)
            return Response([{"message":Username + " added successfully"}])
        except:
            return Response([{"message":Username + " Your account already exist!"}])
            
    return Response([{"status":1}])


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def lists_of_user(request):
    print("###################################3333")
    print(request.user.id)
    print("###########################3")
    di=[]
    users=User.objects.all()
    for j in users:
        d={}
        d["username"]=j.username
        d["email"]=j.email
        di.append(d)
    return Response(di)

    
@api_view(['POST'])
def user_login(request):
    if request.method != "POST":
        return HttpResponse("This view only handles POST requests.", status=400)

    headers = request.data
    username = headers.get('Username')
    password = headers.get('Password')
    print(headers)
    if not username or not password:
        return Response("Username and password are required.", status=400)

    user = authenticate(request, username=username, password=password)

    if user is not None and user.is_active:
        login(request, user)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            "userRole": "normal_users" if "normal_users" in [group.name for group in user.groups.all()] else "Admin",
            "message":"Successfully logged in!"
        })
    else:
        return Response("Invalid login credentials.", status=401)


@api_view(['POST'])
def forget_password(request):
    if request.method == "POST":
        headers = request.data
        
        print(headers)
        email = headers.get('Email')  # Assuming the key is 'email' in the received data

        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            password_reset_url = f"http://localhost:3000/changepassword/{uid}/{token}"
            
            print(password_reset_url)
            send_mail(
                'Password Reset Request',
                f'Please click on the link to reset your password: {password_reset_url}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            return Response({'message': 'Password reset link sent to your email'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Only POST method is allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['POST'])
def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            # Assuming new password is sent in request.data
            new_password = request.data.get('new_password')
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password has been reset.'})
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            # Assuming new password is sent in request.data
            new_password = request.data.get('new_password')
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password has been reset.'})
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def user_profile(request):
    if request.method == "GET":
        #headers = request.data
        username = request.user

        try:
            user = User.objects.get(username=username)
            
            if user.is_authenticated:
                
                serializer = UserSerializer(user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def update_profile(request):
    if request.method == "POST":
        user = request.user
        if user is not None:

            data = request.data

            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            gender = data.get('gender')
            phone = data.get('phone')
            photo = data.get('photo')  # Handling file upload requires additional setup

            # Update User model fields
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()

            # Update or create UserProfile
            User_Profile.objects.update_or_create(
                user=user,
                defaults={
                    'gender': gender,
                    'phone': phone,
                    'photo': photo  # Ensure you handle file uploads correctly
                }
            )

            return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)
        else: 
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

    else:
        return Response({'error': 'Only POST method is allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET'])
def user_list(request):
    search_query = request.data.get('search', '')  # Get the search parameter from the request data

    try:
        admin_group = Group.objects.get(name='admins')
    except Group.DoesNotExist:
        return Response({'error': 'Admin group not found'}, status=status.HTTP_404_NOT_FOUND)

    users = User.objects.exclude(groups=admin_group)

    # Apply search filter if search_query is not empty
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) | Q(email__icontains=search_query)
        )

    serializer = UserSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def addnew_user(request):

    return redirect('signup')

@api_view(['POST'])
def change_password(request):
    user = request.user
    data = request.data
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return Response({'error': 'Both old and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the old password is correct
    if not user.check_password(old_password):
        return Response({'error': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

    # Set the new password
    user.set_password(new_password)
    user.save()

    return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)


@api_view(['delete'])

def delete_user(request,id):
    # Assuming id is used as an identifier
    #username = request.data.get('Usersname')
    user = User.objects.get(id=id)
    print("hhhhhhhhhhhhhhhhhhhhhh", user)
    """     if request.user.username != username and not request.user.is_staff:
            # Prevents users from deleting other users unless they are staff
            return Response({'error': 'You do not have permission to delete this user.'}, status=status.HTTP_403_FORBIDDEN)
    """

    try:
        user = User.objects.get(id=id)
        name = user.username
        print(name)
        user.delete()
        return Response({'message': '{name} User deleted successfully.'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    

@api_view(['GET'])
#@permission_classes([IsAuthenticated])
def deactivate_user(request, id):
    # Assuming username is used as an identifier
    #username = request.data.get('username')

    user = User.objects.get(id=id)
    print("hhhhhhhhhhhhhhhhhhhhhh", user)
    """     if request.user.username != username and not request.user.is_staff:
            # Prevents users from deactivating other users unless they are staff
            return Response({'error': 'You do not have permission to deactivate this user.'}, status=status.HTTP_403_FORBIDDEN)
    """

    try:
        user = User.objects.get(id=id)
        print(user.is_active)
        if user.is_active == False:
            user.is_active = True
            user.save()
        else: 
            user.is_active = False
            user.save()
        print(user.is_active)
        return Response({'message': '{username} deactivated successfully.'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

