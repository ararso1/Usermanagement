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
from .serializers import *  # Adjust the import based on your project structure
from .models import *
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken
from login_history.models import LoginHistory
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType



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
        'reset password': "reset_password",
        'get_user_activity': 'get_user_activity',
        'user_profile_by_admin':'user_profile_by_admin'
        }
    ]
    return Response(routes)


@api_view(['POST'])
def signuppage(request):
    if request.method=="POST":

        headers = request.data
        print()
        print(headers)
        
        Username=headers['Email']
        Password = headers['Password']
       
        #ConfirmPassword = headers['confirm_password']
        try:
            
            user=User.objects.create_user(username=Username, password=Password)
            group = Group.objects.get(name='normal_users')
            user.groups.add(group)
            refresh = RefreshToken.for_user(user)

            print(refresh)
            return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            "userRole": "normal_users" if "normal_users" in [group.name for group in user.groups.all()] else "Admin",
            "message":Username + " added successfully"})
            
        except:
            return Response([{"message":Username + " Your account already exist!"}])
            
    return Response([{"status":1}])


""" @api_view(['GET'])
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
    return Response(di) """


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

    # Retrieve the user's profile to check the is_deleted field
    try:
        user_profile = User_Profile.objects.get(user=user)
    except User_Profile.DoesNotExist:
        user_profile = None

    if user is not None and user.is_active and not (user_profile and user_profile.is_deleted):
        login(request, user)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            "userRole": "normal_users" if "normal_users" in [group.name for group in user.groups.all()] else "Admin",
            "message": "Successfully logged in!"
        })
    else:
        return Response("Invalid login credentials or account is deleted.", status=401)


@api_view(['POST'])
def forget_password(request):
    if request.method == "POST":
        headers = request.data

        print(headers)
        email = headers.get('Email')  # Assuming the key is 'email' in the received data

        try:
            user = User.objects.get(email=email)
            user_profile = User_Profile.objects.get(user=user)
            if user is not None and user.is_active and not (user_profile and user_profile.is_deleted):
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                password_reset_url = f"http://localhost:3000/changepassword/{uid}/{token}"
                
                print(password_reset_url)
                send_mail(
                    'Password Reset Request',
                    f'Please click on the link to reset your password: <a>{password_reset_url}</a>',
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
def reset_password(request):
    uidb64 = request.data.get("userId")
    token = request.data.get("token")
    
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            # Assuming new password is sent in request.data
            new_password = request.data.get('newPassword')
            user.set_password(new_password)
            user.save()
            print("doneeeeeeeeeeeeeeee")
            return Response({'message': 'Password has been reset.'})
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    # Using Token Authentication to authenticate user based on the access key

    if request.method == "GET":
        try:
            # The user should be already authenticated by the TokenAuthentication
            user = request.user
            print()

            serializer = UserSerializer(user)
            print(serializer.data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile_by_admin(request, user_id):
    # Fetch the user or return 404 if not found
    user = get_object_or_404(User, id=user_id)
    print(user, 'jjjjjjjjjjjjjjjjjjjjjjjjjj')
    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        data = request.data
        username = data.get('Username')
        password = data.get('Password')
        email = data.get('Email')

        user.username = username if username else user.username
        user.email = email if email else user.email
        if password:
            user.password = make_password(password)  # Hash the new password

        user.save()

        return Response({'message': 'User updated successfully'}, status=status.HTTP_200_OK)


User = get_user_model()

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    user = request.user

    if not user.is_authenticated:
        return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Non-file fields are in request.data
    first_name = request.data.get('firstName')
    last_name = request.data.get('lastName')
    location = request.data.get('location')
    gender = request.data.get('gender')
    phone = request.data.get('phone')
    birth_date = request.data.get('date')
    email = request.data.get('email')
    
    # File fields should be in request.FILES
    photo = request.FILES.get('image')

    if email:
        user.email = email
    user.first_name = first_name
    user.last_name = last_name
    user.save()

    try:

        user_profile, created = User_Profile.objects.update_or_create(
            user=user,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'gender': gender,
                'phone': phone,
                'location': location,
                'birth_date': birth_date,
                'photo': photo  # Here, Django handles the file storage
            }
        )
        return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_list(request):
    search_query = request.data.get('search', '')  # Get the search parameter from the request data

    try:
        admin_group = Group.objects.get(name='admins')
    except Group.DoesNotExist:
        return Response({'error': 'Admin group not found'}, status=status.HTTP_404_NOT_FOUND)

    users = User.objects.exclude(groups=admin_group).filter(userprofile__is_deleted=False)

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


@api_view(['DELETE'])
def delete_user(request, id):
    try:
        # Fetch the User instance
        user = User.objects.get(id=id)
        
        # Assuming there is a OneToOne relationship between User and UserProfile
        user_profile, created = User_Profile.objects.get_or_create(user=user)
        user_profile.is_deleted = True
        user_profile.save()

        return Response({'message': f'{user.username} User marked as deleted successfully.'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def deactivate_user(request, id):
    # Assuming username is used as an identifier
    #username = request.data.get('username')

    user = User.objects.get(id=id)
    print("hhhhhhhhhhhhhhhhhhhhhh", user)

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



User = get_user_model()

@api_view(['GET'])
#@permission_classes([IsAuthenticated])
def get_user_activity(request, user_id):
    user_content_type = ContentType.objects.get_for_model(User)
    user_login_history = LogEntry.objects.filter(
        content_type=user_content_type, object_id=user_id
    )
    serializer = LogEntrySerializer(user_login_history, many=True)
    print(serializer.data)
    return Response(serializer.data, content_type="application/json")




