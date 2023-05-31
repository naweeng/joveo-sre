from .config import *
import smtplib
from email.mime.text import MIMEText
from pymongo import MongoClient
import secrets
import string


#generating random password   


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

# def sending_mail(username, password, profile):
#     if profile in [Stack.JOVEO_PROD, Stack.JOVEO_STAGE, Stack.JOVEO_MGMT, Stack.JOBCLOUD_PROD, Stack.JOBCLOUD_STAGE, Stack.JOBCLOUD_MGMT]:
#         email_body = create_iam_user_email_body(username, password, profile)
#     elif profile in [MONGO.TRACKING_CG_MONGO_PROD]:
#         email_body = create_mongo_user_email_body(username, password, profile)
#     else:
#         raise Exception("Unknown profile")
    
#     
#     
#     receiver_email = "manish.kumar@joveo.com"  #f"{user}" #f"{user}@example.com"
#     subject = f'[{profile.name}] User Credentials'
#     message = MIMEText(email_body)
#     message['From'] = sender_email
#     message['To'] = receiver_email
#     message['Subject'] = subject

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




# def mongodb_stage_delete_user(email):
#     db = get_mongo_connection(config.get("STAGE_MONGODB_HOST"), config.get(
#         "STAGE_MONGODB_USER"), config.get("STAGE_MONGODB_PASS"))
#     try:
#         db.command('dropUser', email)
#         printAndLog("mongodb_stage: deleted user: "+email+" in mongodb")
#     except Exception as e:
#         printAndLog("mongodb_stage: failed to deleted user: " +
#                     email+" in mongodb")
#         print(e)