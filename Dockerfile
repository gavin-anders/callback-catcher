FROM python:3

MAINTAINER Gavin Anders
LABEL \
    name="Callback Catcher" \
    author="Gavin Anders <gavin.anders@googlemail.com>" \
    description="Pentesting services framework designed to easily and quickly start and stop different services. Supports collecting and filtering of sucesfull data connections which is then exposed via a REST API."

#Install Required Libs
RUN apt-get update && apt-get upgrade -y && apt-get autoremove && apt-get autoclean
RUN apt-get install -y libffi-dev 
RUN apt-get install -y libssl-dev 
RUN apt-get install -y libmysqlclient-dev 
RUN apt-get install -y libxml2-dev 
RUN apt-get install -y libxslt-dev 
RUN apt-get install -y libjpeg-dev 
RUN apt-get install -y libfreetype6-dev 
RUN apt-get install -y zlib1g-dev 
RUN apt-get install -y net-tools 
RUN apt-get install -y build-essential 
RUN apt-get install -y python3.6 
RUN apt-get install -y python3-dev 
RUN apt-get install -y python3-setuptools 
RUN apt-get install -y sqlite3 
RUN python3 /usr/lib/python3/dist-packages/easy_install.py pip
   
#Setup project
ENV $PROJECT_DIR=/root/callback-catcher
COPY . $PROJECT_DIR
WORKDIR $PROJECT_DIR/src

#Install modules
RUN pip3 install -r ../requirements.txt

#Expose all ports
EXPOSE 1-65535

#Run
CMD ["python3","manage.py","runserver","0.0.0.0:12443","--noreload"]