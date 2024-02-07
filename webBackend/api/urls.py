from django.urls import path
from .views import signup_and_send_data, signin_and_check_email_verification, reset_password


urlpatterns = [
    path('signup_and_send_data/', signup_and_send_data, name='signup_and_send_data'),
    path('signin_and_check_email_verification/', signin_and_check_email_verification, name='signin_and_check_email_verification'),
    path('reset_password/', reset_password, name='reset_password'),
]