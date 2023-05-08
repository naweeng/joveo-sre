import json
import requests
import sys
import os
import datetime
import boto3


current_date = datetime.datetime.now().strftime("%Y-%m-%d")
alert_type = os.environ['alert_type']
report_filename = f"report_{current_date}.json"


def getting_secret():
    # Create an IAM role session
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn="arn:aws:iam::485239875118:role/jenkins_cross_account_role",
        RoleSessionName="AssumeRoleSession"
    )
    credentials = assumed_role_object['Credentials']

    # Create a Secrets Manager client
    secrets_manager_client = boto3.client(
        'secretsmanager', region_name='us-east-1',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    # Get the secret value
    secret_name = "sre/sre-internal-slack-webhook/prod"
    response = secrets_manager_client.get_secret_value(SecretId=secret_name)
    secret = response['SecretString']
    return json.loads(secret)

def send_slack_notification(slackmessage):
    try:
        # getting_secret()["webhook"]
        url =  getting_secret()["sre-prod-alerts"]
        message = slackmessage
        title = (f"Zap Alerts :zap:")
        slack_data = {
            "username": f"Zap {alert_type} Severity Alert",
            "icon_emoji": ":warning:",
            # "channel" : "#somerandomcahnnel",
            "attachments": [
                {
                    "fields": [
                        {
                            "value": "\n{0}\n".format(message),
                            "short": "false",
                        }
                    ]
                }
            ]
        }
        byte_length = str(sys.getsizeof(slack_data))
        headers = {'Content-Type': "application/json",
                   'Content-Length': byte_length}
        response = requests.post(
            url, data=json.dumps(slack_data), headers=headers)
        return response
    except:
        raise Exception(response.status_code, response.text)


def zap_report():
    with open(report_filename) as f:
        data = json.load(f)

    alert_count = 0
    alert_names = []

    for site_dict in data['site']:
        target = site_dict["@name"]

        for alert_dict in site_dict['alerts']:
            if alert_dict['riskdesc'].startswith(f"{alert_type}"):
                alert_count += 1
                high_alert_name = alert_dict['name']
                alert_names.append(high_alert_name)

        if alert_count > 0:
            output = f"Target: {target}\n\n{alert_type} alert count: {alert_count}\n"
            output += f"{alert_type} alert names:\n"
            for i, alert_name in enumerate(alert_names):
                output += f"{i+1}. {alert_name}\n"
            output += "\n"
            alert_names = []
            alert_count = 0
            return output

    # No alerts found
    return None

message = zap_report()
if message is not None:
    send_slack_notification(message)
else:
    print("No alerts found.")

