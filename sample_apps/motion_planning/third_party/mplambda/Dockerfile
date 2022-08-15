# FROM base image:latest => https://hub.docker.com/r/nvidia/cuda/ (ubuntu18.04, cuda 10.1-devel)
FROM ubuntu:latest

LABEL maintainer = "Jackson Chui <jacksonchui@berkeley.edu> version: 0.1"
USER root

# ARG SERVER-TYPE=EC2

# RUN executes a shell command
# software-properties-common has the command add-apt-repository in it
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    && apt-get install -y software-properties-common \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && apt-get update
# Install gcc-9, zeroMQ (libzmq3-dev), python3, curl
RUN apt install -y build-essential subversion python3-dev \
        libncurses5-dev libxml2-dev libedit-dev swig doxygen graphviz xz-utils \
        gcc-9 g++ python3-pip curl libzmq3-dev git libc++-dev libc++abi-dev libassimp \
        autoconf automake libtool make unzip pkg-config wget libpq-dev openssl libffi-dev zlib1g-dev \
        clang-5.0 lldb-5.0 libcurl4-openssl-dev libssl-dev clang++ libeigen

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-5.0 1
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-5.0 1

# gcc and g++ symbolinks 
RUN rm /usr/bin/gcc && \
    rm /usr/bin/g++ && \
    ln -s /usr/bin/gcc-9 /usr/bin/gcc && \
    ln -s /usr/bin/g++-9 /usr/bin/g++
    
# Install Pytorch under pip3 (torch torchvision)
RUN pip3 install awscli cloudpickle zmq protobuf boto3 kubernetes six

# Install CMake 3.15
RUN wget "https://cmake.org/files/v3.15/cmake-3.15.4-Linux-x86_64.tar.gz" && \
    tar xvzf cmake-3.15.4-Linux-x86_64.tar.gz && \
    mv cmake-3.15.4-Linux-x86_64 /usr/bin/cmake && \
    rm /cmake-3.15.4-Linux-x86_64.tar.gz

# Set the env path (Thanks Vikram!)
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/cmake/bin

# Install all of our repos    
RUN git clone https://github.com/UNC-Robotics/nigh.git && \
    git clone https://github.com/hydro-project/anna.git && \
    git clone https://github.com/danfis/libccd.git && \
WORKDIR /libccd
RUN mkdir build && cd build && \
    cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release .. && \
    make -j8 && make install
    
# Install protobuf
RUN wget https://github.com/google/protobuf/releases/download/v3.5.1/protobuf-all-3.5.1.zip && \
    unzip protobuf-all-3.5.1.zip 
WORKDIR /protobuf-3.5.1
RUN ./autogen.sh && \
    ./configure CXX=clang++ CXXFLAGS='-std=c++11 -stdlib=libc++ -O3 -g' && \
    make -j8 && make install
RUN ldconfig && \
    rm -rf /protobuf-3.5.1 /protobuf-all-3.5.1.zip

WORKDIR /
RUN git clone https://github.com/flexible-collision-library/fcl.git && \
    cd fcl && mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && make -j8 && make install

WORKDIR /anna
RUN git submodule init && git submodule update
RUN bash scripts/build.sh -j4 -bRelease
# COPY /anna/dockerfiles/start-anna.sh start-anna.sh 
# CMD bash start-anna.sh $SERVER-TYPE

# # Install AWS Lambda stuff
# RUN git clone https://github.com/awslabs/aws-lambda-cpp.git && \
#     cd aws-lambda-cpp && \
#     mkdir build && \
#     cd build && \
#     cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
#     -DCMAKE_INSTALL_PREFIX=~/out && \
#     make -j8 && make install

# WORKDIR /
# RUN git clone https://github.com/aws/aws-sdk-cpp.git && \
#     cd aws-sdk-cpp && \
#     mkdir build && cd build && \
#     cmake .. -DBUILD_ONLY=s3 \
#     -DBUILD_SHARED_LIBS=OFF \
#     -DENABLE_UNITY_BUILD=ON \
#     -DCMAKE_BUILD_TYPE=Release \
#     -DCMAKE_INSTALL_PREFIX=~/out

# WORKDIR /mplambda
# RUN mkdir -p build/Debug && \
#     cd build/debug && \
#     cmake -DCMAKE_BUILD_TYPE=Debug ../.. && \
#     make -j8

# https://solarianprogrammer.com/2013/01/17/building-clang-libcpp-ubuntu-linux/
