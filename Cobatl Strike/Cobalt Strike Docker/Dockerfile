FROM --platform=linux/amd64 ubuntu:latest

# Required Arguments for Cobalt Strike license
ARG COBALTSTRIKE_LICENSE

# Set environment variables to prevent interactive prompts during apt operations
ENV DEBIAN_FRONTEND=noninteractive

# Update and upgrade the system, install necessary packages for Cobalt Strike
RUN apt-get update && apt-get -y dist-upgrade && \
    apt-get install --no-install-recommends -y \
    gnupg \
    ca-certificates \
    expect \
    openjdk-11-jdk \
    curl \
    iproute2 && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/apt/*

# Define Cobalt Strike installation home
ENV COBALTSTRIKE_HOME /opt/cobaltstrike
ENV PATH=$COBALTSTRIKE_HOME:$PATH

# Install and update Cobalt Strike by downloading it using the provided license key
RUN echo "COBALTSTRIKE_LICENSE: ${COBALTSTRIKE_LICENSE}" && \
    export TOKEN=$(curl -s https://download.cobaltstrike.com/download -d "dlkey=${COBALTSTRIKE_LICENSE}" | grep 'href="/downloads/' | cut -d '/' -f3,4) && \
    cd /opt && \
    curl -s https://download.cobaltstrike.com/downloads/${TOKEN}/cobaltstrike-dist-linux.tgz -o cobaltstrike-dist-linux.tgz && \
    tar zxf cobaltstrike-dist-linux.tgz && \
    rm cobaltstrike-dist-linux.tgz && \
    rm /etc/ssl/certs/java/cacerts && \
    update-ca-certificates -f && \
    cd /opt/cobaltstrike && \
    echo "${COBALTSTRIKE_LICENSE}" | ./update && \
    mkdir /opt/cobaltstrike/mount

# Expose all necessary ports for Cobalt Strike Team Server and C2 communications
# Remember that for external access on common ports like 80/443, you'll typically use
# Docker port mapping (e.g., -p 80:80 -p 443:443) and potentially a redirector.
EXPOSE 50050 80 443 4443 4444 4445 4446 4447 4448 4449 9050 9051 9053 9054 9055 9056 53/udp

# Set the working directory to the server directory
WORKDIR /opt/cobaltstrike/server

# Set the entry point for the container to run the Team Server
# Arguments for the teamserver (e.g., IP address and password) should be passed
# directly when you run the Docker container (e.g., docker run ... 0.0.0.0 your_password)
ENTRYPOINT ["./teamserver"]
