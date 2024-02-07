import os
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests
import json

@csrf_exempt
def signup_and_send_data(request):
    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    print(request.POST.get('email'))

    # Receive email and password from request body
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        firstname = data.get('firstname')
        lastname = data.get('lastname')
        institute = data.get('institute')
        country = data.get('country')
        cohort = data.get('cohort')
        status = data.get('status')
        acType = data.get('acType')
        tracks = 0
        marketCap = 0
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body.'}, status=400)

    if not (email and password and firstname and lastname and institute and country and cohort and status and acType):
        return JsonResponse({'error': 'Email or password missing in request.'}, status=400)

    # Data for signing up
    signup_data = {
        "email": email,
        "password": password,
    }

    # Make request to signup API
    signup_response = requests.post(
        f'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(signup_data)
    )
    print(signup_response)

    # Check if signup was successful
    if signup_response.status_code == 200:
        # Data for firestore
        firestore_data = {
            "fields": {
                "firstname": {"stringValue": firstname},
                "lastname": {"stringValue": lastname},
                "email": {"stringValue": email},
                "institute": {"stringValue": institute},
                "country": {"stringValue": country},
                "cohort": {"stringValue": cohort},
                "status": {"stringValue": status},
                "type": {"stringValue": acType},
                "tracks": {"integerValue": tracks},
                "marketCap": {"integerValue": marketCap}
            }
        }

        # Make request to Firestore API
        doc_ID = signup_response.json().get('localId')
        firestore_response = requests.post(
            f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser?documentId={doc_ID}',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(signup_response.json().get('idToken'))
            },
            data=json.dumps(firestore_data)
        )
        
        print(firestore_response)   
        
        # Data for email verification
        email_verification_data = {
            "requestType": "VERIFY_EMAIL",
            "idToken": signup_response.json().get('idToken')
        }

        # Make request to email verification API
        email_verification_response = requests.post(
            f'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(email_verification_data)
        )

        print(email_verification_response)

        return JsonResponse({'message': 'Successfully signed up and sent data.'})

    else:
        return JsonResponse({'error': 'Failed to sign up.'}, status=signup_response.status_code)
