# Define function directory
ARG FUNCTION_DIR="/function"

FROM ubuntu:latest

# Install aws-lambda-cpp build dependencies
RUN apt-get update && \
  apt-get install -y \
  g++ \
  make \
  cmake \
  unzip \
  libcurl4-openssl-dev\
  software-properties-common\
  nmap && \
  add-apt-repository -y ppa:deadsnakes/ppa

# RUN apt-get update && \
#     apt-get install -y sudo 
# #     sudo
# RUN chown root:root /usr/bin && \
#     chmod 7775 /usr/bin/sudo 
# USER root

RUN apt-get update && apt-get install -y python3.8 python3-distutils python3-pip python3-apt
# Include global arg in this stage of the build
ARG FUNCTION_DIR
# Create function directory
RUN mkdir -p ${FUNCTION_DIR}

# Copy function code
COPY app/* ${FUNCTION_DIR}

# Install the runtime interface client
RUN pip3 install \
        --target ${FUNCTION_DIR} \
        python-nmap
        
RUN pip3 install \
        --target ${FUNCTION_DIR} \
        awslambdaric

WORKDIR ${FUNCTION_DIR}

ENTRYPOINT ["su", "root", ";", "python3", "-m", "awslambdaric" ]
CMD [ "app.main"]
        