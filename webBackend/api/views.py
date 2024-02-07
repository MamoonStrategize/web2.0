from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests
import json

@csrf_exempt
def signup_and_send_data(request):
    # Data for signing up
    signup_data = {
        "email": "user@example.com",
        "password": "user_password",
        "returnSecureToken": True
    }

    # Make request to signup API
    signup_response = requests.post(
        'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyAQqyuapYy8sHV5U5En6rgmNhT3s8WP12c',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(signup_data)
    )

    # Check if signup was successful
    if signup_response.status_code == 200:
        # Data for firestore
        firestore_data = {
            "fields": {
                "firstname": {"stringValue": "UserFirstName"},
                "lastname": {"stringValue": "UserLastName"},
                "email": {"stringValue": "user@example.com"},
                "institute": {"stringValue": "UserInstitute"},
                "country": {"stringValue": "UserCountry"},
                "cohort": {"stringValue": "A2B7C4D8E2"},
                "status": {"stringValue": "Active"},
                "type": {"stringValue": "student"},
                "tracks": {"integerValue": 3},
                "marketCap": {"integerValue": 67898767897678767}
            }
        }

        # Make request to Firestore API
        firestore_response = requests.post(
            'https://firestore.googleapis.com/v1/projects/userdata-b8c6a/databases/(default)/documents/regUser?documentId=FnPqFvzuxwaB0PIqDXLlLKvb6pt1',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(signup_response.json().get('idToken'))
            },
            data=json.dumps(firestore_data)
        )

        # Data for email verification
        email_verification_data = {
            "requestType": "VERIFY_EMAIL",
            "idToken": signup_response.json().get('idToken')
        }

        # Make request to email verification API
        email_verification_response = requests.post(
            'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=AIzaSyAQqyuapYy8sHV5U5En6rgmNhT3s8WP12c',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(email_verification_data)
        )

        return JsonResponse({'message': 'Successfully signed up and sent data.'})

    else:
        return JsonResponse({'error': 'Failed to sign up.'}, status=signup_response.status_code)
