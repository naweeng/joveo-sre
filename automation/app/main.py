from fastapi import FastAPI, HTTPException
import boto3
import os
from typing import Optional
import uvicorn
from pymongo import MongoClient
from .config import *
from .helper import *

app = FastAPI()    
    


@app.post('/joveo/user_onboarding', tags=["Onboard / Offboard"], description="Endpoint for user onboarding. This will create a user in all AWS ENVs and Joveo Github right now.")
def create_user_everywhere(username: str, role: Role, github_username: Optional[str] = None):
    try:
        if role == Role.SRE:
            for stack in Stack:
                session = boto3.Session(profile_name=stack.value)
                onboard_user(username, stack, session)

        elif role == Role.Engineering:
            for stack in Stack:
                if stack not in [Stack.JOVEO_MGMT, Stack.JOBCLOUD_MGMT]:
                    session = boto3.Session(profile_name=stack.value)
                    onboard_user(username, stack, session)

        elif role == Role.Others:
            session = boto3.Session(profile_name=Stack.JOVEO_PROD.value)
            onboard_user(username, Stack.JOVEO_PROD, session)
            # return f"User {username} created successfully in AWS Prod stack. Login details have been sent over email."

        msg = f"User {username} created successfully in applicable AWS stacks. Login details have been sent over email."

        if github_username:
            invite_github_user(github_username)
            msg = f"User {username} created successfully in applicable AWS stacks and Github. AWS Login details have been sent over email."

        return msg

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete('/joveo/user_offboarding', tags=["Onboard / Offboard"], description="Endpoint for user offboarding. This will delete the user from all AWS ENVs and Joveo Github right now.")   
def delete_user_from_everywhere(username: str, github_username: Optional[str] = None):
    try:
        for stack in Stack:
            session = boto3.Session(profile_name=stack.value)
            offboard_user(username, stack, session)
            # print(f"created {username} in {stack.value} account")
        msg = f"User {username} deleted successfully in applicable AWS stacks."
        if github_username:
            remove_github_user(github_username)
            msg = f"User {username} deleted successfully in applicable AWS stacks and Github."

        return msg
    except Exception as e:  
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/aws/get_users', tags=["AWS"], description="You can use this to list all the users in an AWS Account.")
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
    

@app.post('/aws/create_user', tags=["AWS"], description="use this to create a user or provide a list of users to be created in a AWS account") #to validate email of requester
def create_user(request: UserRequest, profile: Stack):
    usernames = request.usernames

    # Creating user
    session = boto3.Session(profile_name=profile.value)
    try:
        for username in usernames:
            onboard_user(username, profile, session)
        return f"Users {', '.join(usernames)} created successfully for {profile.name}. Login details shared over email."
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete('/aws/delete_user', tags=["AWS"], description="use this to delete a user or provide a list of users to be created in a AWS account")
def delete_user(request: UserRequest, profile: Stack):
    usernames = request.usernames
    session = boto3.Session(profile_name=profile.value)
    try:
        for username in usernames:
            offboard_user(username, profile, session)
        return f"Users {', '.join(usernames)} deleted successfully from {profile.name}."
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mongo/show_dbs", tags=["MONGO"], description="use this to to list all the dbs in a mongo. equavelent to show dbs in mongo")
def show_databases(profile: MONGO):
    try:
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            database_names = client.list_database_names()
            return {"databases": database_names}
    except Exception as e:
        return {"error": str(e)}

@app.get("/mongo/show_collections/{db_on}", tags=["MONGO"])
def show_collections(profile: MONGO, db_on: str):
    try:
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            db = client[db_on]
            collection_names = db.list_collection_names()
            return {"collections": collection_names}
    except Exception as e:
        return {"error": str(e)}

@app.get("/mongo/show_users", tags=["MONGO"])
def show_users(profile: MONGO):
    mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
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
def create_mongodb_user(request: MongoUserRequest, profile: MONGO, role: MONGO_ROLES ):
    # Establish a connection to MongoDB
    connection_string = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'

    # connection_string = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
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
            password = "manishtest123" #os.getenv("DEFAULT_MONGO_PASS")
        command = {
            'createUser': username,
            'pwd': password,
            'roles': [{"role": role.value, "db": database}]
        }
        db.command(command)

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

@app.delete("/mongo/delete_user", tags=["MONGO"], description="use this to delete a user from a mongo.")
def delete_mongodb_user(request:MongoUserRequest, profile: MONGO ):
    try:
        username = request.username
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            database = client['admin']
            database.command('dropUser', username)
            return {"message": f"User '{username}' deleted from database '{profile.name}'"}
    except Exception as e:
        return {"error": str(e)}
    
@app.get("/mongo/show_roles", tags=["MONGO"])
def show_roles(profile: MONGO, on_which_db: str):
    try:
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        # mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            db = client[on_which_db]

            roles = db.command('rolesInfo')
            role_names = [role['role'] for role in roles['roles']]
            
            return {"roles": role_names}
    except Exception as e:
        return {"error": str(e)}
    finally:
        client.close()

@app.post("/mongo/create_role", tags=["MONGO"])
def create_role(profile: MONGO, role_name: str, db: str, collection: str):
    try:
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        client = MongoClient(mongo_uri)
        database = client["admin"]

        # Create a custom role
        database.command("createRole", role_name,
                         privileges=[{"resource": {"db": db, "collection": collection},
                                      "actions": ["insert", "update", "remove"]}],
                         roles=[])

        client.close()

        return {"role": role_name, "message": f"Role {role_name} has been created on {str(db)}"}
    except Exception as e:
        return {"error": str(e)}



@app.post("/mongo/grant_role_user", tags=["MONGO"], description="use this to grant a role to a user.")
def grant_role_to_user(request:MongoUserRequest, profile: MONGO, role_name: str ):
    try:
        username = request.username
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        # mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            database = client['admin']
            database.command("grantRolesToUser", username, roles=[{'role': role_name, 'db': 'admin'}])
            return {"message": f"added {role_name} to User '{username}' in '{profile.name}'"}
    except Exception as e:
        return {"error": str(e)}

@app.patch("/mongo/reset_password", tags=["MONGO"], description="use this to reset a user's mongo password")
def reset_mongodb_password(request: MongoUserRequest, profile: MONGO):
    try:
        username = request.username
        mongo_uri = f'mongodb://{os.getenv("MONGO_USERNAME")}:{os.getenv("MONGO_PASSWORD")}@{get_mongo_url(profile)}/admin'
        with MongoClient(mongo_uri) as client:
            is_joveo_user = "@joveo.com" in username
            if is_joveo_user:
                password = generate_random_password()
            else:
                password = os.getenv("DEFAULT_MONGO_PASS")           
            database = client['admin']
            database.command('updateUser', username, pwd=password)
            if is_joveo_user:
                # Send login details to the user's email
                msg = f"Hi {username.split('@')[0]},\n\nPassword reset for user {username} in {profile.name}:\n\n\nNew Password: {password}\n"
                sending_mail(username, msg, profile)
                return f"User '{username}' Password reset successfully on {profile.name}. Login details have been sent to the email address."
            else:
                return f"User '{username}' Password reset successfully on {profile.name}. New Password: {password}"
    except Exception as e:
        return {"error": str(e)}
    


@app.post("/joveo/invite_github_user/{github_username}", tags=["Github"])
def invite_github_user_directly(github_username: str):
    invite_github_user(github_username)
    return {"message": f"{github_username} has been successfully added to Joveo GitHub repository."}



@app.delete("/joveo/remove_github_user/{github_username}", tags=["Github"])
def remove_github_user_directly(github_username: str):
    remove_github_user(github_username)
    return {"message": f"{github_username} has been removed from Joveo GitHub repository."}


@app.post("/joveo/invite_grafana_user/{username}", tags=["Grafana"])
def invite_user_to_grafana(username: str):
    invite_grafana_user(username)
    return {"message": f"{username} has been invited to Joveo Grafana."}


# @app.delete("/grafana/delete_users", tags=["Grafana"])
# def delete_user_from_grafana(email: str):
#     try:
#         environments = {
#             "prod": {
#                 "endpoint": f"{grafana_api_endpoint}/api/org/users",
#                 "headers": grafana_api_headers,
#             },
#             "stage": {
#                 "endpoint": f"{grafana_stage_api_endpoint}/api/org/users",
#                 "headers": grafana_stage_api_headers,
#             }
#         }

#         user_deleted_env = [] 

#         for environment, config in environments.items():
#             response = requests.get(
#                 config["endpoint"],
#                 headers=config["headers"],
#             )
#             response.raise_for_status()  # will raise exception for non-2xx status codes
#             # print(config["endpoint"], config["headers"])
#             users = response.json()
#             user_found_in_env = False  

#             for user in users:
#                 if user["email"] == email:
#                     delete_user_grafana(
#                         environment=environment,
#                         userid=user["userId"],
#                         username=email,
#                         api_headers=config["headers"],
#                         api_endpoint=config["endpoint"]
#                     )
#                     print(email, user["userId"], environment)
#                     user_deleted_env.append(environment)
#                     user_found_in_env = True

#             if not user_found_in_env:
#                 print(f"User with email '{email}' not found in '{environment}' environment.")

#         if user_deleted_env:
#             deleted_env_str = ", ".join(user_deleted_env)
#             return {"message": f"User with email '{email}' deleted successfully from the following environments: {deleted_env_str}."}
#         else:
#             return {"message": f"User with email '{email}' not found in any environment."}

#     except requests.exceptions.RequestException as e:
#         return {"error": f"Error occurred while sending the request: {str(e)}"}

#     except Exception as e:
#         return {"error": f"An error occurred: {str(e)}"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80)
