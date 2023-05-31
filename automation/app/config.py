# from pydantic import BaseModel
# from enum import Enum
# from typing import List

# class UserRequest(BaseModel):
#     usernames: List[str]
    
# class MongoUserRequest(BaseModel):
#     username : str

# class Stack(Enum):
#     JOVEO_PROD = "aws-prod-joveo"
#     JOVEO_STAGE = "aws-stage-joveo"
#     JOVEO_MGMT = "aws-mgmt-joveo"
#     JOBCLOUD_PROD = "aws-prod-jc"
#     JOBCLOUD_STAGE = "aws-stage-jc"
#     JOBCLOUD_MGMT = "aws-mgmt-jc"

# class MONGO(Enum):
#     PROD_MONGO = "prod-mongo"
#     RULES_MONGO_PROD = "rules-mongo"
#     APPLY_MONGO_PROD = "apply-mongo"
#     FNA_HEIMDALL_MONGO_PROD = "heimdall-mongo"
#     FNA_PUBMAN_MONGO_PROD = "pubman-mongo"
#     DS_MONGO_PROD = "ds-mongo"
#     TRACKING_DMA_MONGO_PROD = "trk-dma-mongo"
#     TRACKING_CG_MONGO_PROD = "trk-cg-mongo"

# def get_aws_account_url(profile: Stack):
#     aws_urls = {
#         Stack.JOVEO_PROD: "https://joveo-prod.signin.aws.amazon.com/console",
#         Stack.JOVEO_STAGE: "https://joveo-dev.signin.aws.amazon.com/console",
#         Stack.JOVEO_MGMT: "https://joveo-mgmt.signin.aws.amazon.com/console",
#         Stack.JOBCLOUD_MGMT: "https://jobcloud-mgmt.signin.aws.amazon.com/console",
#         Stack.JOBCLOUD_PROD: "https://jobcloud-prod.signin.aws.amazon.com/console",
#         Stack.JOBCLOUD_STAGE: "https://jobcloud-stage.signin.aws.amazon.com/console"
#     }
#     if profile in aws_urls:
#         return aws_urls[profile]
#     raise Exception("Unknown environment")

# def get_mongo_url(profile: MONGO):
#     mongo_urls = {
#         MONGO.PROD_MONGO : "prod-mongo-url",
#         MONGO.RULES_MONGO_PROD : "rules-mongo-url",
#         MONGO.APPLY_MONGO_PROD : "apply-mongo-url",
#         MONGO.FNA_HEIMDALL_MONGO_PROD : "heimdall-mongo-url",
#         MONGO.FNA_PUBMAN_MONGO_PROD : "pubman-mongo-url",
#         MONGO.DS_MONGO_PROD : "ds-mongo-url",
#         MONGO.TRACKING_DMA_MONGO_PROD : "trk-dma-mongo-url",
#         MONGO.TRACKING_CG_MONGO_PROD : "trk-dma-cg-mongo-2.prod.joveo.com:27017"
#     }
#     if profile in mongo_urls:
#         return mongo_urls[profile]
#     raise Exception("Unknown environment")