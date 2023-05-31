from fastapi import FastAPI, HTTPException
import boto3
import uvicorn
import smtplib
from email.mime.text import MIMEText
from pymongo import MongoClient
import secrets
import string
from pydantic import BaseModel
from enum import Enum
from typing import List

app = FastAPI()    
    
# config.py


class UserRequest(BaseModel):
    usernames: List[str]
    
class MongoUserRequest(BaseModel):
    username : str

class Stack(Enum):
    JOVEO_PROD = "aws-prod-joveo"
    JOVEO_STAGE = "aws-stage-joveo"
    JOVEO_MGMT = "aws-mgmt-joveo"
    JOBCLOUD_PROD = "aws-prod-jc"
    JOBCLOUD_STAGE = "aws-stage-jc"
    JOBCLOUD_MGMT = "aws-mgmt-jc"

class MONGO(Enum):
    PROD_MONGO = "prod-mongo"
    RULES_MONGO_PROD = "rules-mongo"
    APPLY_MONGO_PROD = "apply-mongo"
    FNA_HEIMDALL_MONGO_PROD = "heimdall-mongo"
    FNA_PUBMAN_MONGO_PROD = "pubman-mongo"
    DS_MONGO_PROD = "ds-mongo"
    TRACKING_DMA_MONGO_PROD = "trk-dma-mongo"
    TRACKING_CG_MONGO_PROD = "trk-cg-mongo"

def get_aws_account_url(profile: Stack):
    aws_urls = {
        Stack.JOVEO_PROD: "https://joveo-prod.signin.aws.amazon.com/console",
        Stack.JOVEO_STAGE: "https://joveo-dev.signin.aws.amazon.com/console",
        Stack.JOVEO_MGMT: "https://joveo-mgmt.signin.aws.amazon.com/console",
        Stack.JOBCLOUD_MGMT: "https://jobcloud-mgmt.signin.aws.amazon.com/console",
        Stack.JOBCLOUD_PROD: "https://jobcloud-prod.signin.aws.amazon.com/console",
        Stack.JOBCLOUD_STAGE: "https://jobcloud-stage.signin.aws.amazon.com/console"
    }
    if profile in aws_urls:
        return aws_urls[profile]
    raise Exception("Unknown environment")

def get_mongo_url(profile: MONGO):
    mongo_urls = {
        MONGO.PROD_MONGO : "prod-mongo-url",
        MONGO.RULES_MONGO_PROD : "rules-mongo-url",
        MONGO.APPLY_MONGO_PROD : "apply-mongo-url",
        MONGO.FNA_HEIMDALL_MONGO_PROD : "heimdall-mongo-url",
        MONGO.FNA_PUBMAN_MONGO_PROD : "pubman-mongo-url",
        MONGO.DS_MONGO_PROD : "ds-mongo-url",
        MONGO.TRACKING_DMA_MONGO_PROD : "trk-dma-mongo-url",
        MONGO.TRACKING_CG_MONGO_PROD : "trk-dma-cg-mongo-2.prod.joveo.com:27017"
    }
    if profile in mongo_urls:
        return mongo_urls[profile]
    raise Exception("Unknown environment")


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

             # Generate and send login details via email
            # sending_mail(username, password, profile)
        return f"Users {', '.join(usernames)} created successfully for {profile.name}. Login details shared over email."
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#helper.py

def generate_random_password():
    length = 16
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if any(char.isdigit() for char in password):
            return password

def create_iam_user_email_body(username, password, profile: Stack):
    return f"Hi {username.split('@')[0]},\n\nYour IAM user credentials for {profile.name}, are as follows:\n\nUsername: {username}\nPassword: {password}\n\nPlease use the following link to log in to the AWS Management Console: {get_aws_account_url(profile)}\n"

def create_mongo_user_email_body(username, password, profile: MONGO):
    return f"Hi {username.split('@')[0]},\n\nYour MongoDB user credentials are as follows for {profile.name}:\n\nUsername: {username}\nPassword: {password}\n"

# # def sending_mail(username, password, profile):
# #     if profile in [Stack.JOVEO_PROD, Stack.JOVEO_STAGE, Stack.JOVEO_MGMT, Stack.JOBCLOUD_PROD, Stack.JOBCLOUD_STAGE, Stack.JOBCLOUD_MGMT]:
# #         email_body = create_iam_user_email_body(username, password, profile)
# #     elif profile in [MONGO.TRACKING_CG_MONGO_PROD]:
# #         email_body = create_mongo_user_email_body(username, password, profile)
# #     else:
# #         raise Exception("Unknown profile")
    
# #     
# #     
# #     receiver_email = "manish.kumar@joveo.com"  #f"{user}" #f"{user}@example.com"
# #     subject = f'[{profile.name}] User Credentials'
# #     message = MIMEText(email_body)
# #     message['From'] = sender_email
# #     message['To'] = receiver_email
# #     message['Subject'] = subject

#     # Send the email
#     server = smtplib.SMTP('smtp.gmail.com', 587)
#     server.starttls()
#     server.login(sender_email, sender_password)
#     server.sendmail(sender_email, receiver_email, message.as_string())
#     server.quit()

def get_mongo_connection(hostname, user, passwd):
    mongoclient = MongoClient(hostname, username=user, password=passwd)
    db = mongoclient.admin
    return db




@app.delete('/aws/delete_user')
def delete_user(request: UserRequest, profile: Stack):
    usernames = request.usernames
    session = boto3.Session(profile_name=profile.value)
    iam = session.client('iam')
    try:
        for username in usernames:
            #deleting user's password/creds
            iam.delete_login_profile(UserName=username)
            # Remove MFA devices associated with the user
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

            # Detach user policies
            attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                iam.detach_user_policy(UserName=username, PolicyArn=policy_arn)

            # Delete inline policies
            inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline_policies:
                iam.delete_user_policy(UserName=username, PolicyName=policy_name)

            # Remove the users from attached groups
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

@app.post('/mongo/create_user') #
def create_mongodb_user(request: MongoUserRequest, profile: MONGO):
    # Establish a connection to MongoDB
    connection_string = f'mongodb://root:Joveo%40152022@{get_mongo_url(profile)}/admin'
    print(connection_string)
    database = 'admin'
    username = request.username
    client = MongoClient(connection_string)

    try:
        # Access the desired database
        db = client[database]

        # Determine if the username contains "@joveo.com"
        is_joveo_user = "@joveo.com" in username

        # Generate a random password or choose a fixed password
        if is_joveo_user:
            password = generate_random_password()
        else:
            password = "fixedpassword"

        # Create the user
        db.command('createUser', username, pwd=password, roles=[{"role": "readAnyDatabase", "db": "admin"}])

        if is_joveo_user:
            # Send login details to the user's email
            # sending_mail(username, password, profile)
            return f"User '{username}' created successfully in {profile.name}. Login details have been sent to the email address."
        else:
            return f"User '{username}' created successfully in MongoDB. Login details: Username: {username}, Password: {password}"

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # Close the MongoDB connection
        client.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80)