FROM public.ecr.aws/docker/library/debian:bookworm-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    net-tools \
    sudo \
    curl \
    ca-certificates \
    gnupg \
    && apt-get clean

# Add the GNS3 PPA for IOUYAP
RUN echo "deb http://ppa.launchpad.net/gns3/ppa/ubuntu trusty main" >> /etc/apt/sources.list
RUN curl -fsSL 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xb83aaabffbd82d21b543c8ea86c22c2ec6a24d7f' | \
    gpg --dearmor -o /etc/apt/trusted.gpg.d/gns3.gpg

# Update and install IOUYAP
RUN apt-get update && \
    apt-get install -y iouyap

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /iol

# Add the IOL image and config files
COPY *.bin /iol/iol.bin

# Make the IOL image and script executable
RUN chmod +x /iol/iol.bin

ENTRYPOINT ["/entrypoint.sh"]
