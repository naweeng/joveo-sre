from pydantic import BaseModel
from enum import Enum
from typing import List
import os

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

def get_mongo_url(profile: MONGO):
    mongo_urls = {
        MONGO.PROD_MONGO : os.getenv("PROD_MONGO"),
        MONGO.RULES_MONGO_PROD : os.getenv("RULES_MONGO_PROD"),
        MONGO.APPLY_MONGO_PROD : os.getenv("APPLY_MONGO_PROD"),
        MONGO.FNA_HEIMDALL_MONGO_PROD : os.getenv("FNA_HEIMDALL_MONGO_PROD"),
        MONGO.FNA_PUBMAN_MONGO_PROD : os.getenv("FNA_PUBMAN_MONGO_PROD"),
        MONGO.HASHING_MONGO_PROD : os.getenv("HASHING_MONGO_PROD"),
        MONGO.DS_MONGO_PROD : os.getenv("DS_MONGO_PROD"),
        MONGO.TRACKING_DMA_MONGO_PROD : os.getenv("TRACKING_DMA_MONGO_PROD"),
        MONGO.TRACKING_CG_MONGO_PROD : os.getenv("TRACKING_CG_MONGO_PROD"),
        MONGO.STAGE_MONGO : os.getenv("STAGE_MONGO"),
        MONGO.TRK_DMA_STAGE_MONGO : os.getenv("TRK_DMA_STAGE_MONGO"),
        MONGO.TRK_CG_STAGE_MONGO : os.getenv("TRK_CG_STAGE_MONGO"),
        MONGO.DS_STAGE_MONGO : os.getenv("DS_STAGE_MONGO"),
        MONGO.FNA_HEIMDALL_STAGE_MONGO : os.getenv("FNA_HEIMDALL_STAGE_MONGO"),
        MONGO.APPLY_STAGE_MONGO : os.getenv("APPLY_STAGE_MONGO")

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

git_token = os.getenv("GIT_TOKEN")
g = Github(git_token)
GRAFANA_API_KEY = os.getenv("GRAFANA_API_KEY")
GRAFANA_JC_API_KEY = os.getenv("GRAFANA_JC_API_KEY")
GRAFANA_API_ADMIN_KEY = os.getenv("GRAFANA_API_ADMIN_KEY")
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
