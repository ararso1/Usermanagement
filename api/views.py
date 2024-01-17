from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from usermanagement_app.decorators import *
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import Group
from django.http import HttpResponse

# Create your views here.
@api_view(['GET'])
def getRoutes(request):
    routes = [
        {
        "api token" : '/api/token',
        "api refresh":'/api/token/refresh',
        "sign up":"api/signup",
        "sign up":"api/login",
        'list_of_user':"listofusers"
        }
    ]
    return Response(routes)

@api_view(['POST'])
@unauthenticated_user
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
def lists_of_user(reques):
    di=[]
    users=User.objects.all()
    for j in users:
        d={}
        d["username"]=j.username
        d["email"]=j.email
        di.append(d)
    return Response(di)

@unauthenticated_user
@api_view(['POST'])
def user_login(request):
    if request.method != "POST":
        # Handle non-POST requests, maybe return an error or redirect
        return HttpResponse("This view only handles POST requests.", status=400)

    headers = request.data
    print(headers)
    username = headers.get('Username')
    password = headers.get('Password')

    if not username or not password:
        # Handle the case where username or password is not provided
        return HttpResponse("Username and password are required.", status=400)

    print(username, password)
    user = authenticate(request, username=username, password=password)

    if user is not None:
        login(request, user)
        groups = request.user.groups.all()
        if groups:
            group = groups[0].name
            if group == "normal_users":
                return Response("Successfully logged in!")
    else:
        # Handle the case where authentication fails
        return Response("Invalid login credentials.")
