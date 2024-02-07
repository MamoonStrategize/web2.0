import os
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import asyncio
import requests
import json


doc_ID = None
user_id_token = None

@csrf_exempt
def signup_and_send_data(request):
    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

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

        return JsonResponse({'message': 'Successfully signed up and sent data.'})

    else:
        return JsonResponse({'error': 'Failed to sign up.'}, status=signup_response.status_code)


@csrf_exempt
def signin_and_check_email_verification(request):
    global doc_ID
    global user_id_token
    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    # Receive email and password from request body
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body.'}, status=400)

    if not (email and password):
        return JsonResponse({'error': 'Email or password missing in request.'}, status=400)

    # Sign in user
    signin_data = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    signin_response = requests.post(
        f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(signin_data)
    )

    if not signin_response.ok:
        return JsonResponse({'error': 'Failed to sign in.'}, status=signin_response.status_code)

    user_id_token = signin_response.json().get('idToken')
    doc_ID = signin_response.json().get('localId')
    
    # Check if email is verified
    check_verification_data = {
        "idToken": user_id_token
    }

    check_verification_response = requests.post(
        f'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(check_verification_data)
    )

    if not check_verification_response.ok:
        return JsonResponse({'error': 'Failed to check email verification.'}, status=check_verification_response.status_code)

    user_info = check_verification_response.json().get('users', [])[0]
    email_verified = user_info.get('emailVerified', False)

    if not email_verified:
        # Send email verification
        email_verification_data = {
            "requestType": "VERIFY_EMAIL",
            "idToken": user_id_token
        }

        email_verification_response = requests.post(
            f'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(email_verification_data)
        )

        if not email_verification_response.ok:
            return JsonResponse({'error': 'Failed to send email verification.'}, status=email_verification_response.status_code)

        return JsonResponse({'message': 'Email not verified. Verification email sent.'})

        # -----------------------
    # Check status of the account in Firestore
    firestore_response = requests.get(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser/{doc_ID}',
        headers={'Authorization': f'Bearer {user_id_token}'}
    )

    if not firestore_response.ok:
        return JsonResponse({'error': 'Failed to check account status in Firestore.'}, status=firestore_response.status_code)

    status = firestore_response.json().get('fields', {}).get('status', {}).get('stringValue')
    localACtype = firestore_response.json().get('fields', {}).get('type', {}).get('stringValue')
    
    if status != 'Active':
        return JsonResponse({'error': 'Account is not active.'}, status=400)

    return JsonResponse({'message': 'Email verified. Account is active.',
                         'type': localACtype})



@csrf_exempt
def reset_password(request):
    api_key = os.environ.get('FIREBASE_API_KEY')

    if not api_key:
        return JsonResponse({'error': 'Firebase API key not configured.'}, status=500)

    # Receive email from request body
    try:
        data = json.loads(request.body)
        email = data.get('email')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body.'}, status=400)

    if not email:
        return JsonResponse({'error': 'Email missing in request.'}, status=400)

    # Reset password
    reset_data = {
        "requestType": "PASSWORD_RESET",
        "email": email
    }

    reset_response = requests.post(
        f'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}',
        headers={'Content-Type': 'application/json'},
        json=reset_data
    )

    if not reset_response.ok:
        return JsonResponse({'error': 'Failed to reset password.'}, status=reset_response.status_code)

    return JsonResponse({'message': 'Password reset email sent.'})


@csrf_exempt
def delete_account(request):
    global doc_ID
    global user_id_token
    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    # Delete user account from Firebase Authentication
    auth_delete_data = {
        "idToken": user_id_token
    }

    auth_delete_response = requests.post(
        f'https://identitytoolkit.googleapis.com/v1/accounts:delete?key={api_key}',
        headers={'Content-Type': 'application/json'},
        json=auth_delete_data
    )

    if not auth_delete_response.ok:
        return JsonResponse({'error': 'Failed to delete account from Firebase Authentication.'}, status=auth_delete_response.status_code)

    # Delete document from Firestore
    firestore_delete_response = requests.delete(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser/{doc_ID}',
        headers={'Content-Type': 'application/json'}
    )

    if not firestore_delete_response.ok:
        return JsonResponse({'error': 'Failed to delete document from Firestore.'}, status=firestore_delete_response.status_code)

    return JsonResponse({'message': 'Account and document deleted successfully.'})

