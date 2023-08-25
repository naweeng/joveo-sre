import uvicorn
import boto3
import os
from typing import Optional
import time
import requests
import httpx
import json
from .config import *
from .helper import *
from typing import Optional
from fastapi import FastAPI, Depends, Request, HTTPException, Form, Cookie
from datetime import datetime

from starlette.config import Config
from starlette.requests import Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from authlib.integrations.starlette_client import OAuth, OAuthError
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
import googleapiclient.discovery
root = os.path.dirname(os.path.abspath(__file__))


# app = FastAPI(docs_url=None, redoc_url=None)
# app.add_middleware(SessionMiddleware, secret_key='!secret')






app = FastAPI()
GOOGLE_CLIENT_ID = get_secret()["GOOGLE_CLIENT_ID"] or None
GOOGLE_CLIENT_SECRET = get_secret()["GOOGLE_CLIENT_SECRET"] or None
if GOOGLE_CLIENT_ID is None or GOOGLE_CLIENT_SECRET is None:
    raise BaseException('Missing env variables')

# Set up oauth
config_data = {'GOOGLE_CLIENT_ID': GOOGLE_CLIENT_ID, 'GOOGLE_CLIENT_SECRET': GOOGLE_CLIENT_SECRET}
starlette_config = Config(environ=config_data)
oauth = OAuth(starlette_config)
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

SECRET_KEY = get_secret()["SECRET_KEY"] or None
if SECRET_KEY is None:
    raise 'Missing SECRET_KEY'




app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=3600)
admin_emails = get_admin_emails()
db_roles = ["root", "dbAdmin", "userAdmin", "dbOwner", "clusterManager", "clusterAdmin", "readWriteAnyDatabase", "userAdminAnyDatabase", "dbAdminAnyDatabase"]




@app.get("/")
async def home(request: Request):
    user = request.session.get('user')
    # print(user)
    if user is not None:
        email = user['email']
        given_name = user['given_name']

        # Fetch the user's email groups using Gmail API
        # email_groups = get_email_groups(user['access_token'])

        html = (
            f'<pre>Hi: {given_name}\nEmail: {email}\n</pre><br>'
            '<a href="/docs">docs</a><br>'
            '<a href="/logout">logout</a>'
        )
        return HTMLResponse(html)

    with open(os.path.join(root, 'login.html')) as fh:
        data = fh.read()
    return HTMLResponse(content=data, media_type="text/html")




@app.get('/login')  
async def login(request: Request):
    # Redirect Google OAuth back to our application
    redirect_uri = request.url_for('token')

    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.route('/token')
async def token(request: Request):
    # Perform Google OAuth
    token = await oauth.google.authorize_access_token(request)
    user = request.session.get('user')
    user = token['userinfo']
    email = user['email']
    request.session['user'] = dict(user)
    logging.info(f"User {email} logged in.")
    return RedirectResponse(url='/docs')


@app.get('/logout')
async def logout(request: Request):
    # Remove the user
    request.session.pop('user', None)

    return RedirectResponse(url='/')


@app.get("/health")
async def health_check():
    return JSONResponse(content={"status": "ok"})


# Try to get the logged in user
async def get_user(request: Request) -> Optional[dict]:
    user = request.session.get('user')
    if user is not None:
        return user
    else:
        raise HTTPException(status_code=403, detail='Your session has expired. Please log in again.')
    return None



# Call the function to get the user's groups


# @app.route('/openapi.json')
# async def get_open_api_endpoint(request: Request, user: Optional[dict] = Depends(get_user)):  # This dependency protects our endpoint!
#     response = JSONResponse(get_openapi(title='FastAPI', version=1, routes=app.routes))
#     return response


# @app.get('/docs', tags=['documentation'])  # Tag it as "documentation" for our docs
# async def get_documentation(request: Request, user: Optional[dict] = Depends(get_user)):  # This dependency protects our endpoint!
#     response = get_swagger_ui_html(openapi_url='/openapi.json', title='Documentation')
#     return response


@app.post('/joveo/user_onboarding', tags=["Onboard / Offboard"], description="Endpoint for user onboarding. This will create user in all AWS ENVs, Grafana and Joveo Github right now.")
async def create_user_everywhere(username: str, github_username: Optional[str] = None, request: dict = Depends(get_user)):
        if username != request['email'] and request['email'] not in admin_emails:
            detail = (f"You are not allowed to create a user with a different email. Please use your email")
            raise HTTPException(status_code=403, detail=detail)
        try:

            for stack in Stack:
                session = boto3.Session(profile_name=stack.value)
                # print(stack, loggeduser)
                onboard_user(username, stack, session)
                return f"User {username} created successfully in AWS Prod stack. Login details have been sent over email."

            msg = f"User {username} created successfully in applicable AWS stacks. Login details have been sent over email."

            if github_username:
                invite_github_user(github_username)
                msg = f"User {username} created successfully in applicable AWS stacks and Github. AWS Login details have been sent over email."
            
            for grafanaenv in GrafanaENV:
                invite_grafana_user(username, grafanaenv)
                # print(grafanaenv, grafanaenv.value)
                msg = f"User {username} created successfully in applicable AWS stacks, Grafana and Github(if provided). AWS Login details have been sent over email."

            return msg
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

@app.get('/aws/get_users', tags=["AWS"], description="You can use this to list all the users in an AWS Account.")
async def getting_all_users(profile: Stack):
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
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500,detail=str(e))


@app.post('/aws/create_user', tags=["AWS"], description="use this to create a user or provide a list of users to be created in an AWS account")
async def create_user(username: str, profile: Stack, request: dict = Depends(get_user)):
    # Check if the current user is trying to create a user with their own email
    # print(request)
    if username != request['email'] and request['email'] not in admin_emails:
        raise HTTPException(status_code=403, detail="You are not allowed to create user with a different email.")
    
    session = boto3.Session(profile_name=profile.value)
    try:
        # Continue with user creation
        created = onboard_user(username, profile, session)
        if created:
            return f"{username} created successfully for {profile.name}. Login details shared over email."
        else:
            return f"User {username} already exists in {profile.name}"
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    


@app.delete('/aws/delete_user', tags=["AWS"], description="use this to delete a user or provide a list of users to be created in a AWS account")
async def delete_user(username: str, profile: Stack, request: dict = Depends(get_user)):
    if request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to delete a user.")
    session = boto3.Session(profile_name=profile.value)
    try:
        deleted = offboard_user(username, profile, session)
        if deleted:
            return f"User {username} deleted successfully from {profile.name}."
        else:
            return f"User {username} not found in {profile.name}."
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
    
@app.patch('/aws/reset_password', tags=["AWS"], description="use this to reset creds in AWS account")
async def reset_user_creds(username: str, profile: Stack, request: dict = Depends(get_user)):
    if username != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to reset creds of a different user.")
    session = boto3.Session(profile_name=profile.value)
    try:
        iam = session.client('iam')
        password = generate_random_password()
        iam.update_login_profile(
            UserName=username,
            Password=password,
            PasswordResetRequired=True
        )
        msg = f"Hi {username.split('@')[0]},\n\nPassword has been reset for {profile.name}, details are as follows:\n\nUsername: {username}\nPassword: {password}\n\nPlease use the following link to log in to the AWS Management Console: {get_aws_account_url(profile)}\n"
        
        sending_mail(username, msg, profile)
        logging.info(f"Password reset successful for {username} in {profile.name} account")
        return f"Password reset successful for {username} in {profile.name} account. Login details sent over email"
    except Exception as e:
        logging.error(f"ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    

@app.post('/aws/remove_mfa', tags=["AWS"], description="use this to reset MFA in AWS account")
def remove_mfa(username: str, profile: Stack, request: dict = Depends(get_user)):
    if username != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to remove MFA of a different user.")
    session = boto3.Session(profile_name=profile.value)
    iam = session.client('iam')
    try:
        # Get the user's MFA devices
        response = iam.list_mfa_devices(UserName=username)
        mfa_devices = response['MFADevices']

        if not mfa_devices:
            return {"message": f"IAM user {username} does not have MFA devices."}

        # Deactivate and delete MFA devices
        for device in mfa_devices:
            iam.deactivate_mfa_device(UserName=username, SerialNumber=device['SerialNumber'])
            iam.delete_virtual_mfa_device(SerialNumber=device['SerialNumber'])

        logging.info(f"MFA devices removed for IAM user {username} in {profile.name}.")
        return {"message": f"MFA device reset done for {username} in {profile.name}"}

    except iam.exceptions.NoSuchEntityException:
        raise Exception(f"IAM user {username} not found.")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise Exception(str(e))


@app.delete('/joveo/user_offboarding', tags=["Onboard / Offboard"], description="Endpoint for user offboarding. This will delete user from all AWS ENVs, Grafana and Joveo Github right now.")   
def delete_user_from_everywhere(username: str, github_username: Optional[str] = None, request: dict = Depends(get_user)):
    if request['email'] not in admin_emails:
        raise HTTPException(status_code=403, detail="You are not allowed to delete a user.")
    try:
        for stack in Stack:
            session = boto3.Session(profile_name=stack.value)
            offboard_user(username, stack, session)
            # print(f"created {username} in {stack.value} account")
        msg = f"User {username} deleted successfully in applicable AWS stacks."
        if github_username:
            remove_github_user(github_username)
            msg = f"User {username} deleted successfully in applicable AWS stacks and Github."

        for grafanaenv in GrafanaENV:
            delete_user_grafana(username, stack=grafanaenv.value)
            # print(grafanaenv, grafanaenv.value)
            msg = f"User {username} Deleted successfully in applicable AWS stacks, Grafana and Github(if provided). AWS Login details have been sent over email."

        return msg
    except Exception as e:  
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))





@app.get("/mongo/show_dbs", tags=["MONGO"], description="use this to to list all the dbs in a mongo. equavelent to show dbs in mongo")
def show_databases(profile: MONGO):
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            database_names = client.list_database_names()
            return {"databases": database_names}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}

@app.get("/mongo/show_collections/{db_on}", tags=["MONGO"])
def show_collections(profile: MONGO, db_on: str):
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            db = client[db_on]
            collection_names = db.list_collection_names()
            return {"collections": collection_names}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}

@app.get("/mongo/show_users", tags=["MONGO"])
def show_users(profile: MONGO):
    mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
    with MongoClient(mongo_uri) as client:
        db = client["admin"]
        command_result = db.command("usersInfo")
        users = command_result["users"]
        user_list = []
        for user in users:
            user_info = {
                "username": user["user"],
                "roles": user["roles"]
            }
            user_list.append(user_info)

        return {"users": user_list}


@app.post('/mongo/create_user', tags=["MONGO"], description="use this to create a user in a mongo.") 
def create_mongodb_user(username: str, profile: MONGO, role: MONGO_ROLES, request: dict = Depends(get_user) ):
    if username != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to create a user with a different email.")
    # Establish a connection to MongoDB
    connection_string = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'

    # connection_string = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
    database = 'admin'
    client = MongoClient(connection_string)
    try:
        db = client[database]
        password = generate_random_password()
        command = {
            'createUser': username,
            'pwd': password,
            'roles': [{"role": role.value, "db": database}]
        }
        db.command(command)

        # Send login details to the user's email
        msg = f"Hi {username.split('@')[0]},\n\nYour MongoDB user credentials are as follows for {profile.name}:\n\nUsername: {username}\nPassword: {password}\n"
        sending_mail(username, msg, profile)
        logging.info(f"created {username} on {profile.name}")
        return f"User '{username}' created successfully in {profile.name}. Login details have been sent to the email address."
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        client.close()

@app.delete("/mongo/delete_user", tags=["MONGO"], description="use this to delete a user from a mongo.")
def delete_mongodb_user(username:str, profile: MONGO, request: dict = Depends(get_user)):
    if request['email'] not in admin_emails:
        raise HTTPException(status_code=403, detail="You are not allowed to delete a user.")
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            database = client['admin']
            database.command('dropUser', username)
            logging.info(f"deleted {username} on {profile.name}")
            return {"message": f"User '{username}' deleted from database '{profile.name}'"}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}



@app.post('/mongo/create_application_user', tags=["MONGO"], description="use this to create a user for your app in a MongoDB. Your email is required to send login details of this app user back to you") 
def create_mongodb_application_user(your_email: str, app_username: str, profile: MONGO, request: dict = Depends(get_user) ):
    if your_email != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to create a user with a different email.")
        
    if "@joveo.com" in app_username:
        raise HTTPException(status_code=403, detail="You are not allowed to create a user with @joveo.com. Please use this endpoint to create an application user only.")
    # Establish a connection to MongoDB
    connection_string = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'

    # connection_string = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
    database = 'admin'
    client = MongoClient(connection_string)
    try:
        db = client[database]
        password = generate_random_password()
        command = {
            'createUser': app_username,
            'pwd': password,
            'roles': [{"role": "readWriteAnyDatabase", "db": database}]
        }
        db.command(command)

        # Send login details to the user's email
        msg = f"Hi {your_email.split('@')[0]},\n\nMongoDB credentials for {app_username} are as follows for {profile.name}:\n\nUsername: {app_username}\nPassword: {password}\n"
        sending_mail(your_email, msg, profile)
        logging.info(f"created {app_username} on {profile.name}")
        return f"User '{app_username}' created successfully in {profile.name}. Login details have been sent to the your email address."
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        client.close()

    
@app.get("/mongo/show_roles", tags=["MONGO"])
def show_roles(profile: MONGO, on_which_db: str):
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        # mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            db = client[on_which_db]

            roles = db.command('rolesInfo')
            role_names = [role['role'] for role in roles['roles']]
            
            return {"roles": role_names}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}
    finally:
        client.close()

@app.post("/mongo/create_role", tags=["MONGO"])
def create_role(profile: MONGO, role_name: str, db: str, collection: str):
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        client = MongoClient(mongo_uri)
        database = client["admin"]

        # Create a custom role
        database.command("createRole", role_name,
                        privileges=[{"resource": {"db": db, "collection": collection},
                                    "actions": ["insert", "update", "remove"]}],
                        roles=[])

        client.close()
        logging.info(f"created {role_name} on {profile.name}")
        return {"role": role_name, "message": f"Role {role_name} has been created on {str(db)}"}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}



@app.post("/mongo/grant_role_user", tags=["MONGO"], description="use this to grant a role to a user. You can also use this to assign mongo build-in role to your user.")
def grant_role_to_user(username: str, profile: MONGO, role_name: str, db: str, request: dict = Depends(get_user)):
    if username != request['email'] and request['email'] not in admin_emails:
        raise HTTPException(status_code=403, detail="You are not allowed to grant a role to a different user.")
    if role_name in db_roles:
        raise HTTPException(status_code=403, detail="You are not allowed to grant this role.")
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        # mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            database = client['admin']
            database.command("grantRolesToUser", username, roles=[{'role': role_name, 'db': db}])
            logging.info(f"added {role_name} to {username} on {profile.name}")
            return {"message": f"added {role_name} to User '{username}' in '{profile.name}'"}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}

@app.patch("/mongo/reset_password", tags=["MONGO"], description="use this to reset your personal user's mongo password")
def reset_mongodb_personal_user_password(username: str, profile: MONGO, request: dict = Depends(get_user)):
    if username != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to reset creds of a different user.")
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            password = generate_random_password()     
            database = client['admin']
            database.command('updateUser', username, pwd=password)
                # Send login details to the user's email
            msg = f"Hi {username.split('@')[0]},\n\nPassword reset for user {username} in {profile.name}:\n\n\nNew Password: {password}\n"
            sending_mail(username, msg, profile)
            logging.info(f"Reset password for {username} done for {profile.name}")
            return f"User '{username}' Password reset successfully on {profile.name}. Login details have been sent to the email address."
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}

@app.patch("/mongo/reset_application_user_password", tags=["MONGO"], description="use this to reset application user's mongo password. Your email is required to send new password of this app user back to you")
def reset_application_user_password(your_email: str,app_username: str, profile: MONGO, request: dict = Depends(get_user)):
    if your_email != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to reset creds of a different user.")
        
    if "@joveo.com" in app_username:
        raise HTTPException(status_code=403, detail="You are not allowed to reset creds for users from @joveo.com. Please use this endpoint to reset creds of an application user only.")
        
    try:
        mongo_uri = f'mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            password = generate_random_password()     
            database = client['admin']
            database.command('updateUser', app_username, pwd=password)
                # Send login details to the user's email
            msg = f"Hi {your_email.split('@')[0]},\n\nPassword reset for user {app_username} in {profile.name}:\n\n\nNew Password: {password}\n"
            sending_mail(your_email, msg, profile)
            logging.info(f"Reset password for {app_username} done for {profile.name}")
            return f"User '{app_username}' Password reset successfully on {profile.name}. Login details have been sent to your email address."
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"error": str(e)}
    


@app.post("/joveo/invite_github_user/{github_username}", tags=["Github"])
def invite_github_user_directly(github_username: str):
    invite_github_user(github_username)
    return {"message": f"{github_username} has been successfully added to Joveo GitHub repository."}



@app.delete("/joveo/remove_github_user/{github_username}", tags=["Github"])
def remove_github_user_directly(github_username: str, request: dict = Depends(get_user)):
    if request['email'] not in admin_emails  :
        raise HTTPException(status_code=403, detail="You are not allowed to remove a user.")
    remove_github_user(github_username)
    return {"message": f"{github_username} has been removed from Joveo GitHub repository."}


@app.post("/grafana/invite_user/{username}", tags=["Grafana"])
def invite_user_to_grafana(username: str, GrafanaStack: GrafanaENV, request: dict = Depends(get_user)):
    if username != request['email'] and request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to invite a different user than yours.")
    invite_grafana_user(username, GrafanaStack)
    return {"message": f"{username} has been invited to {GrafanaStack.value} Grafana."}


@app.delete("/grafana/delete_user/{username}", tags=["Grafana"])
def delete_user_from_grafana(username: str, GrafanaStack: GrafanaENV, request: dict = Depends(get_user)):
    if request['email'] not in admin_emails :
        raise HTTPException(status_code=403, detail="You are not allowed to remove a user.")
    try:
        if GrafanaStack ==GrafanaENV.Joveo:
            response = delete_user_grafana(username, stack="joveo")
        elif GrafanaStack == GrafanaENV.Jobcloud:
            response = delete_user_grafana(username, stack="jobcloudprogrammatic")
        else:
            raise HTTPException(status_code=400, detail="Invalid Grafana stack provided.")

        if response is None:
            return {"message": f"{username} has been removed from {GrafanaStack.value} Grafana."}
        else:
            return response

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise Exception(f"An error occurred: {str(e)}")



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80)
