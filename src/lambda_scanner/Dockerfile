ARG FUNCTION_DIR="/var/task"

# Use the official AWS Lambda Python 3.9 base image
# This base image is optimised for Lambda and includes the necessary Runtime Interface Client (RIC)
FROM public.ecr.aws/lambda/python:3.9

# Set the working directory to the path where Lambda expects the code
# LAMBDA_TASK_ROOT is a standard environment variable in the Lambda execution environment
WORKDIR ${LAMBDA_TASK_ROOT}

# Copy the dependencies file and install Python packages
# This step is often separated to leverage Docker layer caching (if dependencies don't change, this layer isn't rebuilt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the core scanner logic file
COPY app.py .

# Define the command that Lambda executes upon invocation.
# This specifies the function handler: [filename.function_name]
# NOTE: This command is critical for Lambda to find your code.
CMD [ "app.lambda_handler" ]
