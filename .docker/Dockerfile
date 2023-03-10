FROM ubuntu:22.04

COPY ./build /server

RUN apt update && apt install -f -y libjsoncpp25 libgoogle-glog0v5 libmariadb3 libhiredis0.14
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /server
RUN chmod 770 relying-party 
ENTRYPOINT [ "./relying-party" ]