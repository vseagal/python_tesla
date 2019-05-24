from .global_vars import *
import urllib.request
import urllib.parse


"""
The module gets teslamotors credentials and gets a token data.
Stores the token data in an encrypted file.
Using the access token, you can get information from the car and send commands to it.
"""
debug = 0


def load_token(filename=token_file):
    if os.path.exists(filename):
        return read_token_file(filename)
    else:
        creds = get_credentials()
        json_data = get_auth_token(token_url, creds['email'], creds['pw'])
        return json_data['access_token']


def get_credentials():
    _creds = {}
    _creds.update({'email': input("Enter email: ")})
    _creds.update({'pw': getpass.getpass("Enter password: ")})
    return _creds


def read_token_file(filename):
    current_time = int(time.time())
    try:
        lt_data = decrypt_file(filename)
    except ValueError as error:
        print("Can't read %s" % filename)
        print(error)
        sys.exit(1)

    if current_time > (lt_data['created_at'] + lt_data['expires_in']):
        return renew_token(lt_data['refresh_token'])
    else:
        if debug:
            print(lt_data['access_token'])
        return lt_data['access_token']


def encrypt_file(enc_string, filename):
    encrypted_string = encryption(enc_string)
    with open(filename, "w") as output_file:
        output_file.write(str(encrypted_string))
    os.chmod(filename, 0o600)


def encryption(private_info):
    block_size = 16
    padding = '%'
    key = hwinfo.encode('utf-8')
    padded_private_info = private_info + (block_size - len(private_info) % block_size) * padding
    pad = padded_private_info.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    output = base64.b64encode(cipher.encrypt(pad))
    encoded = output.decode('utf-8')
    return encoded


def decrypt_file(input_file):
    with open(input_file) as infile:
        encrypted_string = infile.readline()

    decrypt_str = decryption(encrypted_string)
    try:
        json_data = ast.literal_eval(decrypt_str)
    except TypeError as err:
        print("Error: decryption failed. %s", err)
        sys.exit(1)
    return json_data


def decryption(encrypted_string):
    padding = '%'
    key = hwinfo.encode('utf-8')
    enc_str = encrypted_string.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(base64.b64decode(enc_str))
    decoded = output.decode('utf-8').rstrip(padding)
    return decoded


def get_auth_token(auth_url, email, pw):
    pw_data = {'grant_type': 'password', 'client_id': client_id, 'client_secret': client_secret, 'email': email,
               'password': pw}
    url_type = 'auth'
    json_data = exec_command(auth_url, pw_data, url_type)
    json_string = str(json_data)
    encrypt_file(json_string, token_file)

    return json_data


def renew_token(ref_token):
    renew_data = {'grant_type': 'refresh_token', 'client_id': client_id, 'client_secret': client_secret,
                  'refresh_token': ref_token}
    url_type = 'auth'
    json_data = exec_command(token_url, renew_data, url_type)
    json_string = str(json_data)
    encrypt_file(json_string, token_file)

    return json_data['access_token']


def get_data(get_data_url):
    get_data_access_token = load_token(token_file)

    if len(get_data_access_token) < 5:
        print("Token length is less then 5 char")
        sys.exit(1)

    try:
        request = urllib.request.Request(get_data_url)
        request.add_header("Authorization", "Bearer %s" % get_data_access_token)
        response = urllib.request.urlopen(request, timeout=15).read()
    except urllib.request.HTTPError as e:
        print("Error: ", e)
        sys.exit(1)

    return json.loads(response)


def exec_command(input_url, payload, url_type='generic'):
    try:
        request = urllib.request.Request(input_url)
        data = urllib.parse.urlencode(payload).encode('utf-8')
        request.data = data

        if url_type == 'generic':
            request.add_header("Authorization", "Bearer %s" % load_token(token_file))

        exec_command_output = urllib.request.urlopen(request, timeout=15).read()
        if debug:
            print("the output is %s", json.loads(exec_command_output))
        return json.loads(exec_command_output)

    except urllib.request.HTTPError as e:
        print("Error: ", e)
        sys.exit(1)


def get_car_info(param):
    if os.path.exists(car_data_file) and os.path.getsize(car_data_file) > 0:
        with open(car_data_file) as car_file:
            car_data = json.load(car_file)
            param_data = car_data['response'][0][param]
    else:
        car_data = get_data(base_url)
        with open(car_data_file, "w") as car_file:
            json.dump(car_data, car_file, sort_keys=True, indent=4, separators=(',', ': '))
        param_data = car_data['response'][0][param]
    return param_data
