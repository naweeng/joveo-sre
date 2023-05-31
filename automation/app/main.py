from fastapi import FastAPI, HTTPException
import boto3
import uvicorn
from pymongo import MongoClient
from .config import *
from .helper import *

app = FastAPI()    
    
@app.get('/aws/get_users')
def getting_all_users(profile: Stack):
    try:
        allusers = []
        session = boto3.Session(profile_name=profile.value)
        client = session.client('iam')
        users = client.get_paginator('list_users')
        for response in users.paginate():
            for user in response['Users']:
                allusers.append(user['UserName'])
        return allusers
    except Exception as e:  
        raise HTTPException(status_code=500,detail=str(e))

@app.post('/aws/create_user') #to validate email of requester
def create_user(request: UserRequest, profile: Stack):
    usernames = request.usernames

    # Creating user
    session = boto3.Session(profile_name=profile.value)
    iam = session.client('iam')
    try:
        for username in usernames:
            password = generate_random_password()
            response = iam.create_user(UserName=username)
            #if Joveo in stack then add to joveo iam group
            if 'JOVEO' in profile.name:
                iam.add_user_to_group(GroupName='Joveo', UserName=username)
            # if JOBCLOUD in stack, add user to below iam groups
            elif 'JOBCLOUD' in profile.name:
                iam.add_user_to_group(GroupName='readonly', UserName=username)
                iam.add_user_to_group(GroupName='securityCompliance', UserName=username)
                
            iam.create_login_profile(
                UserName=username,
                Password=password,
                PasswordResetRequired=True
            )

             #send login details via email
            msg = f"Hi {username.split('@')[0]},\n\nYour IAM user credentials for {profile.name}, are as follows:\n\nUsername: {username}\nPassword: {password}\n\nPlease use the following link to log in to the AWS Management Console: {get_aws_account_url(profile)}\n"
            sending_mail(username, msg, profile)
        return f"Users {', '.join(usernames)} created successfully for {profile.name}. Login details shared over email."
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete('/aws/delete_user')
def delete_user(request: UserRequest, profile: Stack):
    usernames = request.usernames
    session = boto3.Session(profile_name=profile.value)
    iam = session.client('iam')
    try:
        for username in usernames:
            #deleting user's password/creds
            iam.delete_login_profile(UserName=username)
            # Remove MFA devices of the user
            response = iam.list_mfa_devices(UserName=username)
            mfa_devices = response['MFADevices']
            for mfa_device in mfa_devices:
                serial_number = mfa_device['SerialNumber']
                iam.deactivate_mfa_device(UserName=username, SerialNumber=serial_number)
                iam.delete_virtual_mfa_device(SerialNumber=serial_number)

            # Delete IAM access keys of the user
            response = iam.list_access_keys(UserName=username)
            access_keys = response['AccessKeyMetadata']
            for access_key in access_keys:
                access_key_id = access_key['AccessKeyId']
                iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)

            attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                iam.detach_user_policy(UserName=username, PolicyArn=policy_arn)

            inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline_policies:
                iam.delete_user_policy(UserName=username, PolicyName=policy_name)

            response = iam.list_groups_for_user(UserName=username)
            groups = response['Groups']
            for group in groups:
                group_name = group['GroupName']
                iam.remove_user_from_group(GroupName=group_name, UserName=username)
            #delete the user
            iam.delete_user(UserName=username)

        return f"Users {', '.join(usernames)} deleted successfully from {profile.name}."
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/mongo/create_user') 
def create_mongodb_user(request: MongoUserRequest, profile: MONGO):
    # Establish a connection to MongoDB
    connection_string = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
    print(connection_string)
    database = 'admin'
    username = request.username
    client = MongoClient(connection_string)
    try:
        db = client[database]
        # Determine if the username contains "@joveo.com"
        is_joveo_user = "@joveo.com" in username
        if is_joveo_user:
            password = generate_random_password()
        else:
            password = os.getenv("DEFAULT_MONGO_PASS")
        # Creating the user
        db.command('createUser', username, pwd=password, roles=[{"role": "readAnyDatabase", "db": "admin"}])

        if is_joveo_user:
            # Send login details to the user's email
            msg = f"Hi {username.split('@')[0]},\n\nYour MongoDB user credentials are as follows for {profile.name}:\n\nUsername: {username}\nPassword: {password}\n"
            sending_mail(username, msg, profile)
            return f"User '{username}' created successfully in {profile.name}. Login details have been sent to the email address."
        else:
            return f"User '{username}' created successfully in {profile.name}. Login details: Username: {username}, Password: {password}"

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        client.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80)
