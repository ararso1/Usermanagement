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
    
    path('forget_password', views.forget_password, name='forget_password'),
    path('user_profile', views.user_profile, name='user_profile'),
    path('update_profile', views.update_profile, name='update_profile'),
    path('user_list', views.user_list, name='user_list'),
    path('addnew_user', views.addnew_user, name='addnew_user'),
    path('change_password', views.change_password, name='change_password'),
    path('delete_user/<str:id>/', views.delete_user, name='delete_user'),
    path('deactivate_user/<str:id>/', views.deactivate_user, name='deactivate_user'),
    path('reset_password', views.reset_password, name='reset_password'),    
    path('get_user_activity/<str:user_id>', views.get_user_activity, name='get_user_activity'),
    path('user_profile_by_admin/<str:user_id>', views.user_profile_by_admin, name='user_profile_by_admin'),
]

