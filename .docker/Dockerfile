FROM ubuntu:22.04

RUN mkdir -p /server
RUN cp -r ./build/ /server

RUN apt update && apt install -f -y libjsoncpp25 libgoogle-glog0v5 libmariadb3 libhiredis0.14
RUN chmod 770 relying-party 
RUN rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/server/relying-party" ]