from .config import *
import smtplib
import os
from email.mime.text import MIMEText
import secrets
import string

def generate_random_password():
    length = 16
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if any(char.isdigit() for char in password):
            return password

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
