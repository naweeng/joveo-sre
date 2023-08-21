from pydantic import BaseModel
from enum import Enum
from typing import List
import os
import json
import boto3

class UserRequest(BaseModel):
    usernames: List[str]

class OnboardingOffBoardingUserRequest(BaseModel):
    username: str

class MongoUserRequest(BaseModel):
    username : str

class GrafanaENV(Enum):
    Joveo = "joveo"
    Jobcloud = "jobcloudprogrammatic"

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
    HASHING_MONGO_PROD = "hashing-mongo-prod"
    STAGE_MONGO = "stage-mongo"
    TRK_DMA_STAGE_MONGO = "trk-dma-stage-mongo"
    TRK_CG_STAGE_MONGO = "trk-cg-stage-mongo"
    DS_STAGE_MONGO = "ds-stage-mongo"
    FNA_HEIMDALL_STAGE_MONGO = "fna-heimdall-stage-mongo"
    APPLY_STAGE_MONGO = "apply-stage-mongo"
    # JC_GENERIC_MONGO = "jc-generic-mongo"
    # JC_HASHING_MONGO_PROD = "jc-hashing-mongo"
    # JC_RULES_MONGO_PROD = "jc-rules-mongo"
    # JC_FNA_HEIMDALL_MONGO_PROD = "jc-heimdall-mongo"
    # JC_FNA_PUBMAN_MONGO_PROD = "jc-pubman-mongo"
    # JC_DS_MONGO_PROD = "jc-ds-mongo"
    # JC_TRACKING_DMA_MONGO_PROD = "jc-trk-dma-mongo"
    # JC_GENERIC_STAGE_MONGO = "jc-stage-mongo"
    # JC_TRK_DMA_STAGE_MONGO = "jc-trk-dma-stage-mongo"
    # JC_DS_STAGE_MONGO = "jc-ds-stage-mongo"
    # JC_FNA_HEIMDALL_STAGE_MONGO = "jc-fna-heimdall-stage-mongo"

class MONGO_ROLES(Enum):
    READONLY = "readAnyDatabase"
    READWRITE = "readWrite"
    CLUSTERMONITOR = "clusterMonitor"

def get_aws_account_url(profile: Stack):
    aws_urls = {
        Stack.JOVEO_PROD: "https://joveo.signin.aws.amazon.com/console",
        Stack.JOVEO_STAGE: "https://joveo-dev.signin.aws.amazon.com/console",
        Stack.JOVEO_MGMT: "https://joveo-mgmt.signin.aws.amazon.com/console",
        Stack.JOBCLOUD_MGMT: "https://jobcloud-mgmt.signin.aws.amazon.com/console",
        Stack.JOBCLOUD_PROD: "https://jobcloud-prod.signin.aws.amazon.com/console",
        Stack.JOBCLOUD_STAGE: "https://jobcloud-stage.signin.aws.amazon.com/console"
    }
    if profile in aws_urls:
        return aws_urls[profile]
    raise Exception("Unknown environment")



webhook_path = "sre/automation"


def get_secret(secret_name=webhook_path, region_name="us-east-1"):

    # Creating a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    except Exception as e:
            raise e

def get_mongo_url(profile: MONGO):
    mongo_urls = {
        MONGO.PROD_MONGO : get_secret()["PROD_MONGO"],
        MONGO.RULES_MONGO_PROD : get_secret()["RULES_MONGO_PROD"],
        MONGO.APPLY_MONGO_PROD : get_secret()["APPLY_MONGO_PROD"],
        MONGO.FNA_HEIMDALL_MONGO_PROD : get_secret()["FNA_HEIMDALL_MONGO_PROD"],
        MONGO.FNA_PUBMAN_MONGO_PROD : get_secret()["FNA_PUBMAN_MONGO_PROD"],
        MONGO.HASHING_MONGO_PROD : get_secret()["HASHING_MONGO_PROD"],
        MONGO.DS_MONGO_PROD : get_secret()["DS_MONGO_PROD"],
        MONGO.TRACKING_DMA_MONGO_PROD : get_secret()["TRACKING_DMA_MONGO_PROD"],
        MONGO.TRACKING_CG_MONGO_PROD : get_secret()["TRACKING_CG_MONGO_PROD"],
        MONGO.STAGE_MONGO : get_secret()["STAGE_MONGO"],
        MONGO.TRK_DMA_STAGE_MONGO : get_secret()["TRK_DMA_STAGE_MONGO"],
        MONGO.TRK_CG_STAGE_MONGO : get_secret()["TRK_CG_STAGE_MONGO"],
        MONGO.DS_STAGE_MONGO : get_secret()["DS_STAGE_MONGO"],
        MONGO.FNA_HEIMDALL_STAGE_MONGO : get_secret()["FNA_HEIMDALL_STAGE_MONGO"],
        MONGO.APPLY_STAGE_MONGO : get_secret()["APPLY_STAGE_MONGO"]
        # MONGO.JC_GENERIC_MONGO : os.getenv("JC_GENERIC_MONGO"),
        # MONGO.JC_HASHING_MONGO_PROD : os.getenv("JC_HASHING_MONGO_PROD"),
        # MONGO.JC_RULES_MONGO_PROD : os.getenv("JC_RULES_MONGO_PROD"),
        # MONGO.JC_FNA_HEIMDALL_MONGO_PROD : os.getenv("JC_FNA_HEIMDALL_MONGO_PROD"),
        # MONGO.JC_FNA_PUBMAN_MONGO_PROD : os.getenv("JC_FNA_PUBMAN_MONGO_PROD"),
        # MONGO.JC_DS_MONGO_PROD : os.getenv("JC_DS_MONGO_PROD"),
        # MONGO.JC_TRACKING_DMA_MONGO_PROD : os.getenv("JC_TRACKING_DMA_MONGO_PROD"),
        # MONGO.JC_GENERIC_STAGE_MONGO : os.getenv("JC_GENERIC_STAGE_MONGO"),
        # MONGO.JC_TRK_DMA_STAGE_MONGO : os.getenv("JC_TRK_DMA_STAGE_MONGO"),
        # MONGO.JC_DS_STAGE_MONGO : os.getenv("JC_DS_STAGE_MONGO"),
        # MONGO.JC_FNA_HEIMDALL_STAGE_MONGO : os.getenv("JC_FNA_HEIMDALL_STAGE_MONGO")
    }
    if profile in mongo_urls:
        return mongo_urls[profile]
    raise Exception("Unknown environment")


class Role(Enum):
    SRE="SRE"
    Engineering="Engineering"
    Others="Others"


class OnboardingOffffBoardingUserRequest(BaseModel):
    username: str


MONGO_USERNAME = get_secret()["MONGO_USERNAME"]
MONGO_PASSWORD = get_secret()["MONGO_PASSWORD"]
DEFAULT_MONGO_PASS = get_secret()["DEFAULT_MONGO_PASS"]
sender_id = get_secret()["sender_email"]
sender_password_id = get_secret()["sender_password"]
GRAFANA_API_KEY = get_secret()["GRAFANA_API_KEY"]
GRAFANA_JC_API_KEY = get_secret()["GRAFANA_JC_API_KEY"]
GRAFANA_API_ADMIN_KEY = get_secret()["GRAFANA_API_ADMIN_KEY"]
grafana_org_api_endpoint = "https://grafana.com/api/orgs"
grafana_api_endpoint = "https://joveoprodaws.grafana.net"


grafana_api_headers = {
            'Authorization':
                f"Bearer {GRAFANA_API_ADMIN_KEY}",
            'Content-Type': "application/json",
        }


grafana_org_api_headers = {
            'Authorization':
                f"Bearer {GRAFANA_API_KEY}",
            'Content-Type': "application/json",
        }

grafana_jc_org_api_headers = {
            'Authorization':
                f"Bearer {GRAFANA_JC_API_KEY}",
            'Content-Type': "application/json",
        }
