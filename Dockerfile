FROM debian:latest
MAINTAINER Gavin Anders

ENV DEBIAN_FRONTEND noninteractive
ENV CATCHER_USERNAME admin
ENV CATCHER_PASSWORD admin
ENV CATCHER_DOMAIN callbackcatcher.uk

RUN apt-get update -y && apt-get dist-upgrade -y
RUN apt-get install -y \
    apt-utils \
    apache2 \
    apache2-utils \
    python3 \
    python3-dev \
    python3-pip \
    libapache2-mod-wsgi-py3 \
    libmariadbclient-dev \
    netcat \
    dnsutils \
    default-mysql-client
RUN a2enmod \
    ssl \
    wsgi 

# Setup pip
COPY ./requirements.txt /catcher-app/requirements.txt
RUN pip3 install -r /catcher-app/requirements.txt

# Setup catcher
COPY ./src/ /catcher-app/
COPY run.sh /catcher-app/
RUN chown -R www-data:www-data /catcher-app/
WORKDIR /catcher-app
RUN rm -r static/*
RUN python3 manage.py collectstatic

# Enable site
COPY ./catcher-site.conf /etc/apache2/sites-available/catcher-site.conf
RUN sed -i "s/PY_VERSION/python$(python3 -V | grep -oP '(\d.\d)')/" /etc/apache2/sites-available/catcher-site.conf
RUN sed -i '/Listen 80/d' /etc/apache2/ports.conf
RUN sed -i "s/Listen 443/Listen 12443/" /etc/apache2/ports.conf
RUN a2dissite 000-default && a2ensite catcher-site

EXPOSE 12443 12443

CMD ["./run.sh"]
