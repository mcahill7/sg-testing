# sg-testing

POC to deploy test and deploy security groups using cfn-nag

## Pipeline
To create the pipeline run the following:
```
aws cloudformation create-stack --stack-name sg-pipeline --template-body file://pipeline/pipeline.yaml --capabilities CAPABILITY_NAMED_IAM
```
