"""
Django settings for catcher project.

Generated by 'django-admin startproject' using Django 1.9.

For more information on this file, see
https://docs.djangoproject.com/en/1.9/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.9/ref/settings/
"""

import os
import logging
import queue

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#==================Catcher settings=============
CATCHER_VERSION = "v1.0"
BANNER = """
 _____       _ _______            _    _____       _       _               
/  __ \     | | | ___ \          | |  /  __ \     | |     | |              
| /  \/ __ _| | | |_/ / __ _  ___| | _| /  \/ __ _| |_ ___| |__   ___ _ __ 
| |    / _` | | | ___ \/ _` |/ __| |/ / |    / _` | __/ __| '_ \ / _ \ '__|
| \__/\ (_| | | | |_/ / (_| | (__|   <| \__/\ (_| | || (__| | | |  __/ |   
 \____/\__,_|_|_\____/ \__,_|\___|_|\_\\____/\__,_|\__\___|_| |_|\___|_|   
                                                                                                                               
"""
DEBUG_LVL = 'DEBUG' #INFO for less noise
USERNAME = 'admin'
PASSWORD = 'Gubbins123'
EMAIL = 'gavin.anders@googlemail.com'
LISTEN_IP = '0.0.0.0'
IPV6 = False
EXTERNAL_IP = '85.187.140.59'
DOMAIN = 'pentestlabs.uk'
HANDLER_DIR = os.path.join(BASE_DIR, 'catcher/handlers')
HANDLER_CONTENT_DIR = os.path.join(BASE_DIR, 'content/')
FINGERPRINT_DEFS = os.path.join(BASE_DIR, 'files/fingerprints.xml')
ADVANCED_TOKEN_DETECTION = True
SSL_KEY = os.path.join(BASE_DIR, 'files/ssl/server.key')
SSL_CERT = os.path.join(BASE_DIR, 'files/ssl/server.crt')

#========= Advanced Catcher Settings ==========

LETSENCRYPTDIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
CLIENT_USER_PERMISSIONS = ["view_blacklist",
                           "view_callback",
                           "view_handler",
                           "add_port",
                           "delete_port",
                           "view_port",
                           "view_secret",
                           "add_token",
                           "change_token",
                           "delete_token",
                           "view_token",]
TOKEN_QUEUE = queue.Queue() # DO NOT CHANGE
FINGERPRINT_QUEUE = queue.Queue() # DO NOT CHANGE
#===================================

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'vfbc$jpg#b+dgwkpns9ch-&dipkb2d-ryxf0og92cgh1uja5q^'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_yasg',
    'django_filters',
    'restapi',
    'catcher',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.common.CommonMiddleware',
    #'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'catcher.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'catcher.wsgi.application'


# Database

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}
#DATABASES = {
#    'default': {
#      'ENGINE': 'django.db.backends.mysql',
#      'NAME': 'catcher',
#      'USER': 'root',
#      'PASSWORD': 'password',
#      'HOST': 'db',   
#      'PORT': '3306',
#    }
#}

# Internationalization
# https://docs.djangoproject.com/en/1.9/topics/i18n/

LANGUAGE_CODE = 'en-uk'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Customer user class
AUTH_USER_MODEL = 'catcher.Client'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/
FILES_DIR = os.path.join(BASE_DIR, 'files/')
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_DIRS = (
    os.path.join(FILES_DIR, 'static/'),
)

# Django rest framework settings

# REST FRAMEWORK SETTINGS
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 100
}


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '[%(asctime)s] %(message)s',
            'datefmt' : "%d/%b/%Y %H:%M:%S"
        },
    },
    'handlers': {
        'console': {  # Log to stdout
            'level': DEBUG_LVL,
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {  # For dev, show errors + some info in the console
        'handlers': ['console'],
        'level': DEBUG_LVL,
    },
}

# Swagger settings
SWAGGER_SETTINGS = {
    'JSON_EDITOR': True,
    'SHOW_REQUEST_HEADERS': True,
    'USE_SESSION_AUTH': False,
    "SHOW_REQUEST_HEADERS": True,
}


