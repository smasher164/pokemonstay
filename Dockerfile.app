# Below are the Dockerfile instructions to construct
# an image for our web application. Running 'docker build'
# will execute these instructions inside a container, and
# finish by committing itself into a new image.

# First specify the base image. We are using alpine
# linux 3.10 with python 3.8 preinstalled.
FROM python:3.8.0b4-alpine3.10

# Set the current working directory inside the container to
# /pokemonstay. If it doesn't exist, it will be created.
WORKDIR /pokemonstay

# Copy over the requirements.txt separately to prevent
# dependencies from being reinstalled during development.
ADD ./requirements.txt /pokemonstay/requirements.txt

# Download dependencies.
RUN apk --update add openssl ca-certificates py-openssl wget
RUN apk --update add --virtual build-dependencies libffi-dev openssl-dev build-base \
    && pip install -r requirements.txt \
    && apk del build-dependencies

# Copy everything in the current directory into /pokemonstay.
COPY . /pokemonstay

# Specify the port needed by our container.
EXPOSE 8000

# Run our application.
ENTRYPOINT ["gunicorn", "app:app", "-b", ":8000"]