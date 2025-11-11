#!/bin/bash

# --- VARIABLES (UPDATE THESE FOR YOUR ENVIRONMENT) ---
AWS_REGION="eu-west-2"
ACCOUNT_ID="YOUR_AWS_ACCOUNT_ID"
ECR_REPO_NAME="cscat-scanner-repository-261111"
IMAGE_TAG="latest" # Use a consistent tag
# --- END VARIABLES ---

ECR_URI="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME"

echo "1. Authenticating to AWS ECR..."
# This command requires the role running the GitHub Action to have ECR permissions (which it does, as we gave it Administrator Access).
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Check for authentication success
if [ $? -ne 0 ]; then
    echo "ERROR: Docker ECR login failed."
    exit 1
fi
echo "Authentication successful."


echo "2. Building Docker Image..."
# Build the image based on the Dockerfile in the current directory.
# The image name must match the ECR repository URI and tag.
docker build -t $ECR_REPO_NAME:$IMAGE_TAG .

# Tag the image for ECR upload
docker tag $ECR_REPO_NAME:$IMAGE_TAG $ECR_URI:$IMAGE_TAG
echo "Image tagged: $ECR_URI:$IMAGE_TAG"


echo "3. Pushing Docker Image to ECR..."
docker push $ECR_URI:$IMAGE_TAG

# Check for push success
if [ $? -ne 0 ]; then
    echo "ERROR: Docker push failed."
    exit 1
fi
echo "Image push complete. ECR is now populated."
