from . import views
from django.urls import path
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.index, name='index'),
    path('registration', views.registration, name='registration'),
    path('login', views.user_login, name='login'),
    path('user_page', views.user_page, name='user_page'),
    path('admin_page', views.admin_page, name='admin_page'),
    path('edit_profile', views.edit_profile, name='edit_profile'),
    path('logout', views.logoutUser, name='logout'),

    #password management
    path('reset_password/', auth_views.PasswordResetView.as_view(template_name="user_template/password_reset.html"), name="reset_password"),
    #path('password_change/', auth_views.PasswordChangeView.as_view(), name='password_change'),
    #path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(), name='password_change_done'),
    #path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),

    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(template_name="user_template/password_reset_sent.html"), name="password_reset_done"),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="user_template/password_reset_form.html"), name="password_reset_confirm"),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(template_name="user_template/password_reset_done.html"), name="password_reset_complete"),

    path('password_change/', auth_views.PasswordChangeView.as_view(template_name="user_template/password_change.html"), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='user_template/password_change_success.html'), name='password_change_done'),
    
    # ... other URL patterns ...
    path('users/deactivate/<str:userdeact_id>/', views.deactivate_user, name='deactivate_user'),
    path('users/delete/<str:user_id>/', views.delete_user, name='delete_user'),

]

