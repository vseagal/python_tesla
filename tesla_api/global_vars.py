import uuid
import os
import base64
from Crypto.Cipher import AES
import ast
import sys
import getpass
import time
import urllib
import json


client_id = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
client_secret = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"
mac_addr = uuid.UUID(int=uuid.getnode()).hex[-12:]
hwinfo = '%@' + mac_addr + '!#'
token_file = os.environ['HOME'] + '/.token'
car_data_file = os.environ['HOME'] + '/.car_info'
mac_addr = uuid.UUID(int=uuid.getnode()).hex[-12:]
base_url = 'https://owner-api.teslamotors.com/api/1/vehicles/'
token_url = 'https://owner-api.teslamotors.com/oauth/token'
