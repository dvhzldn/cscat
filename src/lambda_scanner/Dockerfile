# Use the Amazon Linux 2 base image for Python 3.9
FROM public.ecr.aws/lambda/python:3.9-al2

# Set the working directory inside the container
WORKDIR ${LAMBDA_TASK_ROOT}

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the function code (app.py is in the same directory as the Dockerfile)
COPY index.py .

# Set the CMD to your handler function (app.lambda_handler)
CMD ["app.lambda_handler"]
