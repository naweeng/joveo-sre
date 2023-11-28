from .config import *
import boto3
from email.mime.text import MIMEText
import smtplib
import requests
from pymongo import MongoClient
import secrets
import string
import json
import logging
from github import Github
from google.oauth2 import service_account
from googleapiclient.discovery import build
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime,  timedelta
import sys
import botocore
import time
from fabric import Connection
import os.path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING) 

varmap={}
varmap['availability_zone'] = ''
varmap['aws_region'] = 'us-east-1'
varmap['subnet_id'] = ''
varmap['KeyName'] = 'craiggenie-aws'
varmap['InstanceType'] = "t3a.small"
varmap['ImageId'] = "ami-0319e6539c622f222"
varmap['SecurityGroupIds'] = [""]
varmap['Service_user'] = "ubuntu"
varmap['Service_port'] = '27017'
varmap['tags'] = [{'Key': 'Name','Value': ''},
        {'Key': 'team','Value': 'SRE'},
        {'Key': 'purpose','Value': 'Mongo-Restoration'},
        {'Key': 'env','Value': 'prod'},
        {'Key': 'DeleteOn','Value': ''}
               ]

client = boto3.client('ec2', region_name='us-east-1')

def get_admin_emails():
    USER_EMAIL = get_secret()["gmail_owner_email"]

    # Setting the necessary scopes
    scopes = ["https://www.googleapis.com/auth/admin.directory.group.member.readonly"]
    secret_info = json.loads(get_secret()["service_account"])
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(
            secret_info, scopes,
        )
    delegated_credentials = credentials.create_delegated(USER_EMAIL)
    directory_service = build("admin", "directory_v1", credentials=delegated_credentials)

    # group's email address
    group_key = "sre-admin@joveo.com"

    members = directory_service.members().list(groupKey=group_key).execute()
    # print(members)
    admin_emails = [member['email'] for member in members['members']]
    return admin_emails

    # print(admin_emails)
# get_admin_emails()


def generate_random_password():
    puncts='!@#$%^&*()_+=[]{|}'
    secret_manager = boto3.client('secretsmanager', region_name='us-east-1')
    response = secret_manager.get_random_password(
                    IncludeSpace=False,
                    PasswordLength=16,
                    RequireEachIncludedType=True,
                    ExcludePunctuation=True)
    random_pass=response['RandomPassword']
    #print(secrets.choice(puncts))
    random_pass=random_pass+secrets.choice(puncts)
    return random_pass



def sending_mail(username, msg, profile):
    
    email_body = msg
    sender_email = get_secret()["sender_email"]
    sender_password = get_secret()["sender_password"]
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
            logging.info(f"User '{username}' already exists in {profile.name}. Skipping user creation.")
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
        msg = f"Hi {username.split('@')[0]},\n\nYour IAM user credentials for {profile.name}, are as follows:\n\nUsername: {username}\nPassword: {password}\n\nPlease use the following link to log in to the AWS Management Console: {get_aws_account_url(profile)}\n CAUTION: Password minimum length should be 14 characters while resetting the password(Require at least one uppercase, one lowercase, one digit, one alphanumeric and no reuse of previoud passwords ).\n Please assign MFA to your user immediately after login by following the steps in document(https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html) "
        # print(msg)
        sending_mail(username, msg, profile)
        logging.info(f"created {username} in {profile.name} account")
        return True
    except iam.exceptions.EntityAlreadyExistsException:
        logging.error(f"User {username} already exists in {profile.name}.")
        return False

def onboard_user_to_group(username, groupname,profile, session):
    iam = session.client('iam')
    try:
        # Check if the user already exists
        try:
            iam.get_user(UserName=username)
        except iam.exceptions.NoSuchEntityException:
            logging.info(f"User '{username}' not doesn't exists in {profile.name}")
            return False

        response = iam.add_user_to_group(GroupName=groupname,UserName=username)
        logging.info(f"Added {username} to {groupname} group ")
        return True
    except iam.exceptions.EntityAlreadyExistsException:
        logging.error(f"User {username} already exists in {groupname} group.")
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
        logging.info(f"User {username} deleted successfully from {profile.name}")
        return True
    except iam.exceptions.NoSuchEntityException:
        logging.error(f"User {username} not found in {profile.name}.")
        return False


g = Github(get_secret()["git_token"])

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

def fetchSnapshotsByTags(filter_key, filter_value,Snapshot_date):
    '''get the snapshot ID and its asscociated Volume id '''
    
    snapshots = client.describe_snapshots(
        Filters=[
            {
                'Name': filter_key,
                'Values': [filter_value + '*']
            },
            {
                'Name': 'status',
                'Values': [
                    'completed'
                ]
            }
        ]
    )
    sorted_snaps = sorted(snapshots['Snapshots'], key=lambda i: i['StartTime'], reverse=True)
    for snap in sorted_snaps:
        start_time= snap['StartTime']
        start_time=start_time.strftime("%Y-%m-%d")
        start_time=datetime.strptime(start_time,'%Y-%m-%d')
        logging.info("%s %s",start_time,Snapshot_date)
        if start_time==Snapshot_date:
            return snap

def fetchInstanceByVol(vol_id,Snapshot_filter_value,delete_date):
    '''get instance attached to the volume and retrive configurations'''
    instances = client.describe_instances(
        Filters=[
            {
                'Name': 'block-device-mapping.volume-id',
                'Values': [vol_id ]
            }
        ]
    )
    for res in instances['Reservations']:
        for each in res['Instances']:
            logging.info(each['PrivateIpAddress'])
    try:
        sg=[]
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for securityGroup in instance['SecurityGroups']:
                    logging.info("SG ID: {}, Name: {}".format(securityGroup['GroupId'], securityGroup['GroupName']))
                    sg.append(securityGroup['GroupId'])

    except Exception as E:
        logging.info(E)

    logging.info("The Existing Instance configurations are")
    i_id=instances['Reservations'][0]['Instances'][0]['InstanceId']
    #print(i_id)
    InstanceType=instances['Reservations'][0]['Instances'][0]['InstanceType']
    KeyName=instances['Reservations'][0]['Instances'][0]['KeyName']
    varmap['availability_zone']=instances['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']
    varmap['subnet_id']=instances['Reservations'][0]['Instances'][0]['SubnetId']
    #varmap['SecurityGroupIds']=[instances['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']]
    varmap['SecurityGroupIds']= sg
    varmap['tags'][0]['Value']='Restored_mongo_%s'%(Snapshot_filter_value)
    varmap['tags'][4]['Value']=delete_date.strftime('%Y-%m-%d')
    instance_config= (str(i_id)+'\n',varmap['ImageId']+'\n',InstanceType+'\n',KeyName+'\n',varmap['availability_zone']+'\n',varmap['subnet_id']+'\n')
    logging.info(instance_config)

def generate_key_file():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name='us-east-1'
    )

    
    get_secret_value_response = client.get_secret_value(
            SecretId='craiggenie-aws')
    key_value=get_secret_value_response['SecretString']
    if os.path.isfile('craiggenie-aws.pem') :
        os.remove('craiggenie-aws.pem')
    with open('craiggenie-aws.pem','w') as f:
        f.write(key_value)
    os.chmod('craiggenie-aws.pem', 0o400)

def verify_key_file(key):
    if not os.path.isfile(key):
        logging.info('Key file doesnot exists')
        sys.exit(1)

def createVolume(snapshot_id):
    response = client.create_volume(
        AvailabilityZone=varmap['availability_zone'],
        SnapshotId=snapshot_id,
        TagSpecifications=[
            {
                'ResourceType': 'volume',
                'Tags': varmap['tags']
            }
        ]
    )
    volume_create_waiter = client.get_waiter('volume_available')
    try:
        volume_create_waiter.wait(VolumeIds=[response["VolumeId"]])
        logging.info('the volume {0} got successfully created with size {1}'.format(response["VolumeId"],response['Size']))
        return response['VolumeId'], response['Size']

    except botocore.exceptions.WaiterError as e:
        logging.info(e.message)


def attachVolume(instance_id, volume_id):
    response = client.attach_volume(
        Device='/dev/sdf',
        InstanceId=instance_id,
        VolumeId=volume_id
    )
    logging.info('the volume got attached successfully')

def createInstance():
    '''create the instance with retrived configurations'''
    response = client.run_instances(
        SubnetId=varmap['subnet_id'],
        MaxCount=1,
        MinCount=1,
        KeyName=varmap['KeyName'],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': varmap['tags']
            },
            {
                'ResourceType': 'volume',
                'Tags': varmap['tags']
            }
        ],
        ImageId=varmap['ImageId'],
        InstanceType=varmap['InstanceType'],
        SecurityGroupIds=varmap['SecurityGroupIds']

    )
    instance_create_waiter = client.get_waiter('instance_status_ok')
    try:
        instance_create_waiter.wait(InstanceIds=[response['Instances'][0]['InstanceId']])
        logging.info('Instance got successfully created with IDs ' + response['Instances'][0]['InstanceId'] + ' and ' + response['Instances'][0]['PrivateIpAddress'])
        return response['Instances'][0]['InstanceId'], response['Instances'][0]['PrivateIpAddress']
    except botocore.exceptions.WaiterError as e:
        logging.info(e.message)
        sys.exit(1)

def check_for_mongo_status(connection,service_port):
    '''check the mongodb status'''
    logging.info('Checking Mongo status!!!')
    c = connection
    mongo_positive = c.run("sudo grep -q 'Waiting for connections' /var/log/mongodb/mongod.log; echo $?",
                           warn=True)
    mongo_positive1 = c.run("sudo grep -q 'waiting for connections on port {0}' /var/log/mongodb/mongod.log; echo $?".format(service_port),
                           warn=True)
    loop_counter=1
    while int(mongo_positive.stdout) != 0 and int(mongo_positive1.stdout) != 0:
        if loop_counter > 5:
            logging.info('Mongo is not ready yet. check from the server!!!')
            return
        logging.info('Not ready yet, wait for 60 seconds')
        loop_counter=loop_counter+1
        time.sleep(60)
        mongo_positive = c.run("sudo grep -q 'Waiting for connections' /var/log/mongodb/mongod.log; echo $?",
                           warn=True)
        mongo_positive1 = c.run("sudo grep -q 'waiting for connections on port {0}' /var/log/mongodb/mongod.log; echo $?".format(service_port),
                           warn=True)
    logging.info(str(datetime.now()) +' Mongo is now ready to accept connections!')


def server_side(ip, vol_size, key_path,Snapshot_filter_value):
    '''install mongodb and check the status'''
    c = Connection(host=ip, user=varmap['Service_user'], connect_kwargs={"key_filename": key_path})
    
    service_port = varmap['Service_port']
    mongo_version=str(version.get(Snapshot_filter_value))

    if Snapshot_filter_value == 'services-rulesengine':
        
        c.run("sudo apt-get install libcurl4 openssl liblzma5")
        c.run("sudo wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu1804-4.0.28.tgz")
        c.run("sudo tar -zxvf mongodb-linux-*.tgz")
        #c.run("sudo ln -s mongodb-linux-x86_64-ubuntu1804-4.0.28/bin/* /usr/local/bin/")
        #c.run("sudo cp mongodb-linux-x86_64-ubuntu1804-4.0.28/bin/* /usr/local/bin/")
        c.run("sudo useradd mongodb")
        #c.run("sudo touch /etc/mongod.conf")
        c.put('mongod.conf', 'mongod.conf')
        c.run("sudo chown root:root mongod.conf")
        c.run("sudo mv mongod.conf /etc/mongod.conf")

        # Create the config file and update it
       
        c.run("sudo sed -i 's#bindIp.*$#bindIp: 127.0.0.1,{0}#g' /etc/mongod.conf".format(ip))

        # Create necessary data directory
        c.run("sudo mkdir -p /data", warn=True)
        c.run("sudo mkdir /var/log/mongodb", warn=True)

        # Mount the right volume
        volume_name = c.run("lsblk | grep {0}G".format(vol_size))
        logging.info(volume_name)
        c.run("sudo mount /dev/{} /data".format(volume_name.stdout.strip().split()[0]))
        c.run("sudo chown -R mongodb:mongodb /data")
        c.run("sudo rm -f /data/mongodb.lock")
        logging.info("Deleted the lock file")

        #start the mongo
        c.run("nohup sudo ./mongodb-linux-x86_64-ubuntu1804-4.0.28/bin/mongod --config /etc/mongod.conf >& /dev/null < /dev/null &")
        logging.info(str(datetime.datetime.now()) + ' Started Mongo with right path and config')
        check_for_mongo_status(c,service_port)
        return

    #install mongo
    c.run("sudo apt-get install gnupg curl")
    c.run("curl -fsSL https://pgp.mongodb.com/server-"+mongo_version+".asc | \
   sudo gpg -o /usr/share/keyrings/mongodb-server-"+mongo_version+".gpg \
   --dearmor")
    c.run("echo \"deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-"+mongo_version+".gpg ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/"+mongo_version+" multiverse\" | sudo tee /etc/apt/sources.list.d/mongodb-org-"+mongo_version+".list")
    c.run("sudo apt-get update")
    c.run("sudo apt-get install -y mongodb-org")

    # Stop Mongo
    c.run('sudo systemctl stop mongod', warn=True)
    timestamp = c.run("date")
    logging.info(str(timestamp) + 'stopped the mongod service')

    # Update config file
    c.run("sudo sed -i 's#dbPath.*$#dbPath: /data#g' /etc/mongod.conf")
    c.run("sudo sed -i 's#port.*$#port: {0}#g' /etc/mongod.conf".format(service_port))
    c.run("sudo sed -i 's#bindIp.*$#bindIp: 127.0.0.1,{0}#g' /etc/mongod.conf".format(ip))

    # Create necessary data directory
    c.run("sudo mkdir -p /data", warn=True)

    # Mount the right volume
    volume_name = c.run("lsblk | grep {0}G".format(vol_size))
    logging.info(volume_name)
    c.run("sudo mount /dev/{} /data".format(volume_name.stdout.strip().split()[0]))
    c.run("sudo chown -R mongodb:mongodb /data")
    c.run("sudo rm -f /data/mongodb.lock")
    logging.info("Deleted the lock file")

    # Start Mongo
    c.run("sudo systemctl restart mongod")
    logging.info(str(datetime.now()) + ' Started Mongo with right path and config')
    check_for_mongo_status(c,service_port)
