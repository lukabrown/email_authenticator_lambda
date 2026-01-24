import os
import requests

API_KEY = os.environ["api_secret"]
TURNSTILE_SECRET = os.environ["turnstile_secret"]

def lambda_handler(event, context):
    print(event)

    api_token = event['headers']['x-api-key']
    turnstile_token = event['headers']['x-turnstile-token']

    # check api token
    if api_token != API_KEY:
        print('ERROR: wrong API key')
        return generateDeny(event['methodArn'])

    # check turnstile token
    response = validate_turnstile(turnstile_token, TURNSTILE_SECRET)
    if response['success'] is not True:
        print('ERROR: turnstile validation failed', response.get('error-codes', []))
        return generateDeny(event['methodArn'])

    if response['hostname'] != "www.luka-brown.com":
        print('ERROR: invalid hostname in turnstile response', response['hostname'])
        return generateDeny(event['methodArn'])

    print('authorized')
    return generateAllow(event['methodArn'])

def generatePolicy(effect, resource):
    authResponse = {}
    authResponse['principalId'] = 'me'

    policyDocument = {}
    policyDocument['Version'] = '2012-10-17'
    policyDocument['Statement'] = []

    statementOne = {}
    statementOne['Action'] = 'execute-api:Invoke'
    statementOne['Effect'] = effect
    statementOne['Resource'] = resource

    policyDocument['Statement'] = [statementOne]
    authResponse['policyDocument'] = policyDocument
    authResponse['usageIdentifierKey'] = API_KEY

    authResponse['context'] = {}

    return authResponse

def generateAllow(resource):
    return generatePolicy('Allow', resource)

def generateDeny(resource):
    return generatePolicy('Deny', resource)

def validate_turnstile(token, secret, remoteip=None):
    url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

    data = {
        'secret': secret,
        'response': token
    }

    if remoteip:
        data['remoteip'] = remoteip

    try:
        response = requests.post(url, data=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Turnstile validation error: {e}")
        return {'success': False, 'error-codes': ['internal-error']}
