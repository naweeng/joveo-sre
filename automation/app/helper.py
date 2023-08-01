from .config import *
import smtplib
import os
from email.mime.text import MIMEText
import secrets
import string
import requests
from pymongo import MongoClient
from github import Github
import json
import logging



logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')


def generate_random_password():
    length = 16
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if any(char.islower() for char in password) and \
           any(char.isupper() for char in password) and \
           any(char.isdigit() for char in password) and \
           any(char in string.punctuation for char in password) and \
           "'" not in password and '"' not in password and "`" not in password:
            return password
        else:
            continue

def sending_mail(username, msg, profile):
    
    email_body = msg
    sender_email = os.getenv("GMAIL_ID")
    sender_password = os.getenv("GMAIL_TOKEN")
    receiver_email = f"{username}" #f"{user}@example.com"
    subject = f'[{profile.name}] User Credentials'
    message = MIMEText(email_body)
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject

    # Send the email
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()


def onboard_user(username, profile, session):
    iam = session.client('iam')
    try:
        # Check if the user already exists
        try:
            iam.get_user(UserName=username)
            print(f"User '{username}' already exists in {profile.name}. Skipping user creation.")
            return False
        except iam.exceptions.NoSuchEntityException:
            pass

        password = generate_random_password()
        response = iam.create_user(UserName=username)

        if 'JOVEO' in profile.name:
            iam.add_user_to_group(GroupName='Joveo', UserName=username)
        elif 'JOBCLOUD' in profile.name:
            iam.add_user_to_group(GroupName='readonly', UserName=username)
            iam.add_user_to_group(GroupName='securityCompliance', UserName=username)

        iam.create_login_profile(
            UserName=username,
            Password=password,
            PasswordResetRequired=True
        )
        msg = f"Hi {username.split('@')[0]},\n\nYour IAM user credentials for {profile.name}, are as follows:\n\nUsername: {username}\nPassword: {password}\n\nPlease use the following link to log in to the AWS Management Console: {get_aws_account_url(profile)}\n"
        # print(msg)
        sending_mail(username, msg, profile)
        print(f"created {username} in {profile.name} account")
        return True
    except Exception as e:
        print(f"ERROR for {username} in {profile.name}: {str(e)}")
    return False


def offboard_user(username, profile, session):
    iam = session.client('iam')
    try:
        # Deleting user's password/credentials if a login profile exists
        try:
            iam.delete_login_profile(UserName=username)
        except iam.exceptions.NoSuchEntityException:
            pass

        response = iam.list_mfa_devices(UserName=username)
        mfa_devices = response['MFADevices']
        for mfa_device in mfa_devices:
            serial_number = mfa_device['SerialNumber']
            iam.deactivate_mfa_device(UserName=username, SerialNumber=serial_number)
            iam.delete_virtual_mfa_device(SerialNumber=serial_number)

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

        # Delete the user
        iam.delete_user(UserName=username)
        print(f"User {username} deleted successfully from {profile.name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"User {username} not found in {profile.name}.")


def create_or_update_file(repository_owner, repository_name, file_path, file_content, commit_message):
    repo = g.get_repo(f"{repository_owner}/{repository_name}")

    try:
        # Check if the file already exists
        contents = repo.get_contents(file_path)
        repo.update_file(contents.path, commit_message, file_content, contents.sha)
        logging.info(f"File {file_path} updated in GitHub repository.")
    except Exception as e:
        # Create the file
        repo.create_file(file_path, commit_message, file_content)
        logging.info(f"File {file_path} created in GitHub repository.")


def invite_github_user(github_username):
    try:
        file_content = f"""resource "github_membership" "github_membership_{github_username}" {{
  username = "{github_username}"
  role     = "member"
}}

resource "github_team_membership" "github_team_membership_{github_username}" {{
  team_id  = var.write_team_id
  username = "{github_username}"
  role     = "member"
}}
"""

        # Define the file path relative to the repository
        file_path = f"github-user-management/joveo_write_users/{github_username}.tf"

        repository_owner = "joveo"
        repository_name = "tool-automation"

        # Commit message for the file changes
        commit_message = f"Adding {github_username}.tf to joveo github"

        # Create or update the file on GitHub
        create_or_update_file(repository_owner, repository_name, file_path, file_content, commit_message)

        logging.info(f"Terraform file generated for {github_username} and added to GitHub repository.")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return {"error": str(e)}

def delete_file(repository_owner, repository_name, file_path, commit_message):
    repo = g.get_repo(f"{repository_owner}/{repository_name}")

    try:
        contents = repo.get_contents(file_path)

        repo.delete_file(contents.path, commit_message, contents.sha)
    except Exception as e:
        raise e


def remove_github_user(github_username: str):
    try:
        file_path = f"github-user-management/joveo_write_users/{github_username}.tf"
        repository_owner = "joveo"
        repository_name = "tool-automation"
        # Commit message for the file deletion
        commit_message = f"Removing {github_username}.tf from github"

        delete_file(repository_owner, repository_name, file_path, commit_message)

        print(f"Terraform file for {github_username} has been removed from GitHub repository.")

    except Exception as e:
        return {"error": str(e)}



def invite_grafana_user(username):
    try:
        data = json.dumps({
            "email": username,
            "source": "non-staff-invite",
            "role": "Viewer",
            "billing": 0,
        })
        response = requests.post(
            f'{grafana_org_api_endpoint}/invites',
            headers=grafana_org_api_headers,
            data=data,
        )
        response.raise_for_status()
        # print(f'{username} {response.status_code} {response.json()}')
        return(f"{username} has been invited to grafana")

    except requests.exceptions.RequestException as e:
        print(f'Error occurred while sending the request: {str(e)}')

    except Exception as e:
        print(f'An error occurred: {str(e)}')


def invite_grafana_user(username, GrafanaStack):
    try:
        data = json.dumps({
            "email": username,
            "source": "non-staff-invite",
            "role": "Viewer",
            "billing": 0,
        })
        if GrafanaStack == GrafanaENV.Joveo:
            response = requests.post(
                f'{grafana_org_api_endpoint}/joveo/invites',
                headers=grafana_org_api_headers,
                data=data,
            )
            response.raise_for_status()
            logging.info(f"{username} has been invited to Joveo Grafana")

        elif GrafanaStack == GrafanaENV.Jobcloud:
            response = requests.post(
                f'{grafana_org_api_endpoint}/jobcloudprogrammatic/invites',
                headers=grafana_jc_org_api_headers,
                data=data,
            )
            response.raise_for_status()
            logging.info(f"{username} has been invited to JC Grafana")

    except requests.exceptions.RequestException as e:
        raise Exception(f'Error occurred while sending the request: {str(e)}')

    except Exception as e:
        raise Exception(f'An error occurred: {str(e)}')



def remove_user_grafana(username, user_login, stack):
    try:
        if stack == "joveo":
            response = requests.delete(
                f'{grafana_org_api_endpoint}/joveo/members/{user_login}',
                headers=grafana_org_api_headers
            )
            # response.raise_for_status()
            logging.info(f"{username} with login {user_login} has been deleted from Joveo Grafana")

        elif stack == "jobcloudprogrammatic":
            response = requests.delete(
                f'{grafana_org_api_endpoint}/jobcloudprogrammatic/members/{user_login}',
                headers=grafana_jc_org_api_headers
            )
            # response.raise_for_status()
            logging.info(f"{username} with login {user_login} has been deleted from JC Grafana")

    except requests.exceptions.RequestException as e:
        raise Exception(f"Error occurred while sending the request: {str(e)}")

    except Exception as e:
        raise Exception(f"An error occurred: {str(e)}")



def delete_user_grafana(username, stack):
    try:
        response = requests.get(
            f'{grafana_api_endpoint}/api/org/users',
            headers=grafana_api_headers
        )
        users = response.json()

        user_found = False
        for user in users:
            if user["email"] == username:
                user_found = True
                user_login = user["login"]
                logging.info(f"User found: {username} ({user_login}) in {stack} Grafana.")
                remove_user_grafana(username, user_login, stack)  
                break

        if not user_found:
            logging.warning(f"User with email '{username}' not found in {stack} Grafana.")
            return {"message": f"User with email '{username}' not found in {stack} Grafana."}

        # response.raise_for_status()

    except requests.exceptions.RequestException as e:
        logging.error(f"Error occurred while sending the request: {str(e)}")
        raise Exception(f"Error occurred while sending the request: {str(e)}")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise Exception(f"An error occurred: {str(e)}")

