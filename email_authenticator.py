import os

API_KEY = os.environ["api_secret"]

def lambda_handler(event, context):
    print(event)
    token = event['headers']['x-api-key']
    if token != API_KEY:
        print('ERROR: wrong API key')
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
