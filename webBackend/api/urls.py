from django.urls import path
from .views import signup_and_send_data

urlpatterns = [
    path('signup_and_send_data/', signup_and_send_data, name='signup_and_send_data'),
]