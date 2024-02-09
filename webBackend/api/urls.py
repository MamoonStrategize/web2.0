from django.urls import path
from .views import signup_and_send_data, signin_and_check_email_verification, reset_password, delete_account, add_cohort, remove_cohort, get_all_cohorts

urlpatterns = [
    path('signup_and_send_data/', signup_and_send_data, name='signup_and_send_data'),
    path('signin_and_check_email_verification/', signin_and_check_email_verification, name='signin_and_check_email_verification'),
    path('reset_password/', reset_password, name='reset_password'),
    path('delete_account/', delete_account, name='delete_account'),
    path('add_cohort/', add_cohort, name='add_cohort'),
    path('remove_cohort/', remove_cohort, name='remove_cohort'),
    path('get_all_cohorts/', get_all_cohorts, name='get_all_cohorts'),
]