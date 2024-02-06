from django.shortcuts import render,redirect
from .forms import *
from .models import *
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required
from .decorators import *
from django.contrib.auth.decorators import login_required, user_passes_test
from .serializers import *
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.db.models import Q

# Create your views here.


def index(request):
    return render(request, 'user_template/index.html')

@unauthenticated_user
def registration(request):
    form = CreateUserForm()
    
    if request.method == "POST":
        form = CreateUserForm(request.POST)
        #customerform=CustomerForm(request.POST)
        if form.is_valid():
            user=form.save()
            
            group = Group.objects.get(name='normal_users')
            user.groups.add(group)
            return redirect('login')
    context = {'form':form}  
    return render(request, 'user_template/registration.html', context)


@unauthenticated_user
def user_login(request):
    if request.method =="POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username = username, password = password)
        
        if user is not None:
            login(request, user)
            group = request.user.groups.all()[0].name
            if group == "normal_users":
                
                return redirect('user_page')
            else:
                return redirect('admin_page')
            
    return render(request, 'user_template/login.html')

def logoutUser(request):
    logout(request)
    return redirect('login')

#user task

@login_required(login_url='login')
@allowed_users(allowed_roles=['normal_users'])
def user_page(request):
    return render(request, 'user_template/User/user_page.html')

@login_required(login_url='login')
@allowed_users(allowed_roles=['normal_users'])
def view_profile(request):

    return render(request, 'user_template/User/user_page.html')


@login_required(login_url='login')
@allowed_users(allowed_roles=['normal_users'])
def edit_profile(request):

    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        user_email = request.POST.get('user_email')
        photo = request.FILES.get('photo')
        print(photo)
        # ... get other fields ...

        profile=create_or_update_user_profile(request.user, first_name, last_name, user_email, photo)
        return redirect('user_page')  # Redirect to a confirmation page or back to the form

    #context = {'users':users, 'profileform':profileform}
    return render(request, 'user_template/User/edit_profile.html')

def create_or_update_user_profile(user, first_name, last_name, user_email, photo=None):
    profile, created = UserProfile.objects.get_or_create(user=user)
    profile.first_name = first_name
    profile.last_name= last_name
    profile.user_email = user_email
    print(photo)
    if photo:
        profile.photo = photo
    
    profile.save()

    return profile



@login_required(login_url='login')
@allowed_users(allowed_roles=['admins'])
def deactivate_user(request, userdeact_id):
    user = CustomUser.objects.get(pk=userdeact_id)
    user.is_active = False
    user.save()
    return redirect('admin_page')

#admin task

@login_required(login_url='login')
@allowed_users(allowed_roles=['admins'])
def admin_page(request):
    search_query = request.GET.get('search', '')  # Get the search parameter from the URL
    admin_group = Group.objects.get(name='admins')
    users = CustomUser.objects.exclude(groups=admin_group).filter(is_active=True)

    # Apply search filter if search_query is not empty
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) | Q(email__icontains=search_query)
        )

    return render(request, 'user_template/Admin/admin_page.html', {'users': users, 'search_query': search_query})


""" @login_required(login_url='login')
@allowed_users(allowed_roles=['admins'])
@api_view(['GET', 'POST'])
def admin_page(request):
    if request.method == 'GET':
        data = User.objects.all()

        serializer = UserSerializer(data, context={'request': request}, many=True)

        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) """

@login_required(login_url='login')
@allowed_users(allowed_roles=['admins'])
def delete_user(request, user_id):
    user=CustomUser.objects.get(id=user_id)
    user.delete()
    return render(request, 'user_template/Admin/admin_page.html')

