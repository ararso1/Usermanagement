from . import views
from django.urls import path
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('signup/', views.signuppage, name='signup'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('endpoints', views.getRoutes, name='endpoints'),
    path('login', views.user_login, name='login'),
    path('listofusers', views.lists_of_user, name='listofusers'),
    
]

