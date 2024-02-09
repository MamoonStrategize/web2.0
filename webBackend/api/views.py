import os
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests
import json
from django.contrib.sessions.models import Session
import secrets


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

    # Create a new session or get the existing session
    session_key = request.session.session_key
    if not session_key:
        request.session.save()

    # Assign values to the session
    request.session['user_id_token'] = signin_response.json().get('idToken')
    request.session['doc_ID'] = signin_response.json().get('localId')

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
    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    user_id_token = request.session.get('user_id_token')
    doc_ID = request.session.get('doc_ID')

    if not (user_id_token and doc_ID):
        return JsonResponse({'error': 'Missing session data.'}, status=400)

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

@csrf_exempt
def add_cohort(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=405)

    user_id_token = request.session.get('user_id_token')
    doc_ID = request.session.get('doc_ID')

    if not (user_id_token and doc_ID):
        return JsonResponse({'error': 'Missing session data.'}, status=400)

    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    # Keep generating new cohort numbers until one doesn't exist
    while True:
        cohort_number = generate_cohort_number()

        # Check if cohort number already exists
        firestore_get_response = requests.get(
            f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort',
            headers={'Content-Type': 'application/json'}
        )

        if not firestore_get_response.ok:
            return JsonResponse({'error': 'Failed to fetch document from Firestore.'}, status=firestore_get_response.status_code)

        user_data = firestore_get_response.json()
        cohort_exists = False
        for document in user_data.get('documents', []):
            cohort_numbers = document.get('fields', {}).get('cohort', {}).get('stringValue', '').split(',')
            if cohort_number in cohort_numbers:
                cohort_exists = True
                break

        if not cohort_exists:
            break

    # Get existing cohort numbers from Firestore
    firestore_get_response = requests.get(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort/{doc_ID}',
        headers={'Content-Type': 'application/json'}
    )
    
    
    if firestore_get_response.status_code == 404:
        # Document not found, generate a new cohort number
        # Update document in Firestore
        firestore_update_data = {
            "fields": {
                "cohort": {
                    "stringValue": cohort_number
                }
            }
        }

        firestore_update_response = requests.post(
                f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort?documentId={doc_ID}',
                headers={'Content-Type': 'application/json'},
                json=firestore_update_data
            )

        if not firestore_update_response.ok:
            return JsonResponse({'error': 'Failed to create document in Firestore.'}, status=firestore_update_response.status_code)

        return JsonResponse({'message': 'Document Created & Cohort number added successfully.'})
    elif not firestore_get_response.ok:
        # Other error occurred while fetching document
        return JsonResponse({'error': 'Failed to fetch document from Firestore.'}, status=firestore_get_response.status_code)
    else:
        # Document found, extract existing cohort numbers
        existing_cohorts = firestore_get_response.json().get('fields', {}).get('cohort', {}).get('stringValue', '')
        # Append new cohort number after existing ones
        new_cohorts = ','.join([existing_cohorts, cohort_number]) if existing_cohorts else cohort_number

        # Update document in Firestore
        firestore_update_data = {
            "fields": {
                "cohort": {
                    "stringValue": new_cohorts
                }
            }
        }

        firestore_update_response = requests.patch(
            f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort/{doc_ID}',
            headers={'Content-Type': 'application/json'},
            json=firestore_update_data
        )

        if not firestore_update_response.ok:
            return JsonResponse({'error': 'Failed to update document in Firestore.'}, status=firestore_update_response.status_code)

        return JsonResponse({'message': 'Cohort number added successfully.'})

def generate_cohort_number():
    return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(10))

@csrf_exempt
def remove_cohort(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=405)

    user_id_token = request.session.get('user_id_token')
    doc_ID = request.session.get('doc_ID')

    if not (user_id_token and doc_ID):
        return JsonResponse({'error': 'Missing session data.'}, status=400)

    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not project_id:
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    try:
        data = json.loads(request.body)
        cohort_to_remove = data.get('cohort_to_remove')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Cohort to remove not provided.'}, status=400)

    # Get existing cohort numbers from Firestore
    firestore_get_response = requests.get(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort/{doc_ID}',
        headers={'Content-Type': 'application/json'}
    )

    if not firestore_get_response.ok:
        return JsonResponse({'error': 'Failed to fetch document from Firestore.'}, status=firestore_get_response.status_code)

    existing_cohorts_data = firestore_get_response.json()
    existing_cohorts = existing_cohorts_data.get('fields', {}).get('cohort', {}).get('stringValue', '').split(',')

    if cohort_to_remove not in existing_cohorts:
        return JsonResponse({'error': 'Cohort to remove not found in existing cohorts.'}, status=400)

    # Remove the cohort to be removed
    existing_cohorts.remove(cohort_to_remove)

    # Update document in Firestore with modified cohort data
    firestore_update_data = {
        "fields": {
            "cohort": {
                "stringValue": ','.join(existing_cohorts)
            }
        }
    }

    firestore_update_response = requests.patch(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort/{doc_ID}',
        headers={'Content-Type': 'application/json'},
        json=firestore_update_data
    )

    if not firestore_update_response.ok:
        return JsonResponse({'error': 'Failed to update document in Firestore.'}, status=firestore_update_response.status_code)

    return JsonResponse({'message': 'Cohort removed successfully.'})

@csrf_exempt
def get_all_cohorts(request):
    doc_ID = request.session.get('doc_ID')

    if not doc_ID:
        return JsonResponse({'error': 'Missing session data.'}, status=400)

    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not project_id:
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    # Get existing cohort numbers from Firestore
    firestore_get_response = requests.get(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/cohort/{doc_ID}',
        headers={'Content-Type': 'application/json'}
    )

    if not firestore_get_response.ok:
        return JsonResponse({'error': 'Failed to fetch document from Firestore.'}, status=firestore_get_response.status_code)

    existing_cohorts_data = firestore_get_response.json()
    cohort_string = existing_cohorts_data.get('fields', {}).get('cohort', {}).get('stringValue', '')
    existing_cohorts = cohort_string.split(',')
        
    cohort_counts = []
    
    # Count how many entries in /regUser/ contain each cohort number
    for cohort_number in existing_cohorts:

        firestore_update_data = {
            "structuredQuery": {
                "from": [{"collectionId": "regUser"}],
                "where": {
                    "fieldFilter": {
                        "field": {"fieldPath": "cohort"},
                        "op": "EQUAL",
                        "value": {"stringValue": cohort_number}
                    }
                }
            }
        }

        firestore_query_response = requests.post(
            f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents:runQuery',
            headers={'Content-Type': 'application/json'},
            json=firestore_update_data
        )

        if firestore_query_response.ok:
            json_response = firestore_query_response.json()
            cohort_count = len(json_response)
        else:
            cohort_count = 0

        cohort_counts.append(str(cohort_count))

    return JsonResponse({'cohort': ','.join(existing_cohorts), 'entries': ','.join(cohort_counts)})

@csrf_exempt
def suspend_student(request):
    project_id = os.environ.get('FIREBASE_PROJECT_ID')

    if not project_id:
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    # Receive newStatis and studentID from request body
    try:
        data = json.loads(request.body)
        newStatus = data.get('status')
        studentID = data.get('id_new')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body.'}, status=400)

    if not (newStatus and studentID):
        return JsonResponse({'error': 'Email or password missing in request.'}, status=400)

    firestore_response_get = requests.get(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser/{studentID}',
        headers={'Content-Type': 'application/json'})
        # Handle response from Firestore API
    if firestore_response_get.ok:
        # Extract existing data and update status
        print(firestore_response_get.json())
        existing_data = firestore_response_get.json().get('fields', {})
        existing_data['status'] = {'stringValue': newStatus}

        # Prepare data for update
        update_data = {'fields': existing_data}

        # Make request to Firestore API
        firestore_response = requests.patch(
            f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser/{studentID}',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(update_data)
        )
                
        if firestore_response.ok:
            return JsonResponse({'message': 'Successfully suspended student'})
        else:
            return JsonResponse({'error': 'Failed to suspend student.'}, status=firestore_response.status_code)
    else:
        return JsonResponse({'error': 'Failed to fetch student data from Firestore.'}, status=firestore_response_get.status_code)

@csrf_exempt
def invitation_teacher(request):
    api_key = os.environ.get('FIREBASE_API_KEY')
    project_id = os.environ.get('FIREBASE_PROJECT_ID')
    doc_ID = request.session.get('doc_ID')
    user_id_token = request.session.get('user_id_token')


    if not (api_key and project_id):
        return JsonResponse({'error': 'Firebase credentials not configured.'}, status=500)

    # Receive email and password from request body
    try:
        data = json.loads(request.body)
        email = data.get('email')
        firstname = data.get('firstname')
        lastname = data.get('lastname')
        cohort = data.get('cohort')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body.'}, status=400)

    if not (email and firstname and lastname and cohort):
        return JsonResponse({'error': 'Email or password missing in request.'}, status=400)

    # Data for signing up
    signup_data = {
        "email": email,
        "password": generate_cohort_number(),
    }

    # Make request to signup API
    signup_response = requests.post(
        f'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}',
        headers={'Content-Type': 'application/json'},
        data=json.dumps(signup_data)
    )
    
    #make request to teacher's data
    firestore_response_get = requests.get(
        f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser/{doc_ID}',
        headers={'Content-Type': 'application/json'})
        # Handle response from Firestore API
    if firestore_response_get.ok:
        institute = firestore_response_get.json().get('fields', {}).get('institute', {}).get('stringValue', '')
        country = firestore_response_get.json().get('fields', {}).get('country', {}).get('stringValue', '')

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
                    "status": {"stringValue": "Active"},
                    "type": {"stringValue": "student"},
                    "tracks": {"integerValue": 0},
                    "marketCap": {"integerValue": 0}
                }
            }

            # Make request to Firestore API
            std_doc_ID = signup_response.json().get('localId')
            firestore_response = requests.post(
                f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/regUser?documentId={std_doc_ID}',
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
                headers={
                    'Content-Type': 'application/json',
                },
                data=json.dumps(email_verification_data)
            )
            if not email_verification_response.ok:
                return JsonResponse({'error': "Failed to send invitation", 'response': email_verification_response.json()})

            # Data for email RESET
            email_RESET_data = {
                "requestType": "PASSWORD_RESET",
                "email": email
            }

            # Make request to email RESET API
            email_RESET_response = requests.post(
                f'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}',
                headers={'Content-Type': 'application/json'},
                data=json.dumps(email_RESET_data)
            )
            if not email_RESET_response.ok:
                return JsonResponse({'error': "Failed to send password reset email"})

            return JsonResponse({'message': 'Successfully signed up and sent data : invitation: rest'})
        else:
            return JsonResponse({'error': 'Failed to invite.'}, status=signup_response.status_code)
