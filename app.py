from flask import Flask, request, jsonify
import subprocess
import os
import numpy as np
import pandas as pd
from typing import Literal
from features_utils import bitwise_operation, general_search, parse_file, extract_package_details, write_dict_to_csv, write_each_package_and_version_to_csv_and_create_dir, calculate_entropy, find_longest_line_in_the_file, search_substring_in_package
import logging
import math
import joblib
import hashlib
import json
import sys
import csv
import random
import time
from pymongo import MongoClient
from bson import json_util
from datetime import datetime, timedelta
import requests
from flask_cors import CORS


is_PII = 0
is_file_sys_access = 0
is_process_creation = 0
is_network_access = 0
is_crypto_functionality = 0
is_data_encoding = 0
is_dynamic_code_generation = 0
is_package_installation = 0
is_geolocation = 0
is_minified_code = 0
is_has_no_content = 0
longest_line = 0
num_of_files = 0
has_license = 0

# MongoDB connection URI
MONGO_URI = ""
NPM_API_URL = 'https://api.npmjs.org/downloads/point'

# Create a MongoClient using the connection URI
client = MongoClient(MONGO_URI)

# Access your MongoDB database
db = client.get_database("SafeDep")
collection = db.get_collection("Packages")


def search_PII(root_node) -> Literal[1, 0]:
    """
    (1) Access to personally-identifying information (PII): creditcard numbers, passwords, and cookies
     """
    logging.info("start func: search_PII")
    # print('root node search pii: ',root_node)
    keywords = ['screenshot', ['keypress', 'POST'],
                'creditcard', 'cookies', 'passwords', 'appData']
    return general_search(root_node, keywords)


def search_file_sys_access(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (a) File-system access: reading and writing files
    """

    '''#(2)a
    File-system access: reading and writing files
    #require('fs') is the File System Library that provides a simple
    and convenient way to interact with the file system on the computer.
    It provides functions for reading and writing files,
    creating and deleting directories, and more.'''

    keywords = ['read', 'write', 'file',
                'require("fs")', 'os = require("os")', 'platform', 'hostname', 'system32']

    logging.info("start func: search_file_sys_access")

    return general_search(root_node, keywords)


def search_file_process_creation(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (b) Process creation: spawning new processes
    """

    '''
        #(2)b
    Process creation: spawning new processes
    #exec -> execute, used to run cmd commands on the device, including creation of new processes.
    #spawn -> The spawn keyword in JavaScript is used to start a new process in Node.js.
    It creates a new process and runs a specified command in that process.
    #fork -> The fork method in the child_process module in Node.js is used to create a new
    Node.js process that is a child of the current process. Unlike the spawn method,
    which creates a new process and runs a separate command, the fork method creates
    a new process that runs the same code as the parent process.
    #child_process -> The child_process module in Node.js is a module for creating and controlling
    child processes in a Node.js application. It provides a way to start new processes,
    run shell commands, and manage the communication between a Node.js process and its child processes.'''

    logging.info("start func: search_file_process_creation")
    keywords = ['exec', 'spawn', 'fork', 'thread', 'process', 'child_process']
    return general_search(root_node, keywords)


def search_network_access(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (c)Network access: sending or receiving data
    """
    logging.info("start func: search_network_access_data")
    '''(2)c
    Network access: sending or receiving data
    #send -> we use send keyweord because when it comes to outward comminicaton, we expect to receive data,
    but it is very very unlikely that we will transfer data out from the device.
    thus we marked 'send' keyword'''

    keywords = ['send', 'export', 'upload', 'post',
                'XMLHttpRequest', 'submit', 'dns', 'nodemailer']
    return general_search(root_node, keywords)


def search_cryptographic_functionality(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs 
    (a) Access to crypto functionality:
    """
    logging.info("start func: search_crypto_data")

    '''(3)(a) Cryptographic functionality
    mining: The process of finding a hash that meets certain criteria in a cryptocurrency network.'''
    keywords = ['crypto', 'mining', 'miner', 'cpu']

    return general_search(root_node, keywords)


def search_data_encoding(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs
    (b) encoded data: find encoded data in the script
    """
    logging.info("start func: search_encoded_data")

    '''(3)(b) Data encoding using encodeURIComponent etc.
    base64 -> common encoding method.
    encodeURIComponent -> common encoding function with utf-8.
    querystring -> This is a built-in Node.js library for working with query strings. 
    It provides methods for encoding and decoding query strings.
    qs: This is a popular library for encoding and decoding query strings in both the browser and Node.js. 
    It provides a more powerful set of features compared to the built-in querystring library.
    btoa and atob: These are global functions in JavaScript for base64 encoding and decoding respectively.
    Buffer: This is a built-in class in Node.js for working with binary data.
    You can use the .toString('base64') method to encode binary data as a base64 string.
    JSON.stringify: This is a built-in method in JavaScript for converting a JavaScript object to a JSON string. 
    JSON is a widely used format for encoding data structures and exchanging data between client and server.'''

    keywords = ['encodeURIComponent', 'querystring', 'qs',
                'base64', 'btoa', 'atob', 'Buffer', 'JSON.stringify']

    return general_search(root_node, keywords)


def search_dynamic_code_generation(root_node) -> Literal[1, 0]:
    """
    (3) encoded data: find encoded data in the script
    (c) search_dynamic_code_generation: run external scripts within the script
    """
    logging.info("start func: search_dynamic_code_generation")

    '''(3)(c) Dynamic code generation using eval, Function, etc.
    #eval -> a function that is used to dynamically execute the code defined in the string code.
    # Function -> Function constructor: This allows you to dynamically create a new function
    and execute it. The Function constructor takes a string of code as its
    argument and returns a reference to a new function that can be executed.'''
    keywords = ['eval', 'Function']

    return general_search(root_node, keywords)


def search_package_installation(root_node) -> Literal[1, 0]:
    """
    (4) search_package_installation: unautherized external package installation
    """
    logging.info("start func: search_dynamic_code_generation")

    '''(4) Use of package installation scripts
    #In npm, pre-install and post-install are scripts that can
    be defined in the scripts section of the package.json file.
    These scripts are executed before and after the installation of packages, respectively.'''
    keywords = ['preinstall', 'postinstall', 'install', 'sudo']

    return general_search(root_node, keywords)


def search_minified_code(directory_path) -> Literal[1, 0]:
    """
    (5) Presence of minified code (to avoid detection) or binary files (such as binary executables)
    Extracts the is_minified feature from the files in the directory.

    Parameters:
        directory_path (str): the path to the directory to extract features from.

    Returns:
        is_minified (int): 1 if the code is minified, 0 otherwise.
    """
    logging.info("start func: search_minified_code")
    logging.debug(f'directory_path: {directory_path}')

    # Store the entropy values of each file in the directory
    entropy_values = []

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            logging.debug(f'filename: {filename}')
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                logging.debug('ignore')
                continue

            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) > 0:
                # Calculate the entropy of the binary data
                entropy = calculate_entropy(data)
                logging.debug(f"entropy: {entropy}")
                # Append the entropy to the list of entropy values
                entropy_values.append(entropy)

    is_minified = 0

    # Calculate the average entropy and standard deviation of the entropy values
    if len(entropy_values) != 0:
        avg_entropy = sum(entropy_values) / len(entropy_values)
        std_dev_entropy = math.sqrt(
            sum((x - avg_entropy)**2 for x in entropy_values) / len(entropy_values))

        # Create a feature indicating whether the data is minified or not
        AVG_ENTROPY_THRESHOLD = 5
        STD_DEV_ENTROPY_THRESHOLD = 0.1
        if avg_entropy > AVG_ENTROPY_THRESHOLD and std_dev_entropy > STD_DEV_ENTROPY_THRESHOLD:
            is_minified = 1
        logging.info(f'avg_entropy: {avg_entropy}')
        logging.info(f'std_dev_entropy: {std_dev_entropy}')
        logging.info(f'is_minified: {is_minified}')

    return is_minified


def search_packages_with_no_content(directory_path: str) -> Literal[1, 0]:
    """
    The function takes in a directory path as input and returns 1 if the directory does not contain any '.js' or '.ts' files, and 0 otherwise.

    Args:
    - directory_path (str): The path to the directory being checked.

    Returns:
    - int: Returns 1 if the directory does not contain any '.js' or '.ts' files and 0 otherwise.

    """
    logging.info("start func: extract_is_has_no_content")

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            else:
                return 0

    return 1


def search_geolocation(directory_path) -> Literal[1, 0]:
    """
    search_geolocation: unautherized acess to the location of the device 
    """
    logging.info("start func: search_location")

    # searching for an API that gets the location of the device base on its IP.
    keywords = ['ipgeolocation']

    return search_substring_in_package(directory_path, keywords)


def longest_line_in_the_package(directory_path: str) -> int:
    """
    The function returns the longest line in the package.
    Malicious packages sometimes use obfuscation techniques, 
    that write the whole code in the file as one line.

    Args:
    - directory_path (str): The path to the directory being checked.

    Returns:
    - int: Returns the longest line in the package.
    """
    logging.info("start func: longest_line_in_the_package")

    # Store the longest line in the package
    longest_line_package = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            logging.debug(f'filename: {filename}')
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                logging.debug('ignore')
                continue

            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            longest_line_file = find_longest_line_in_the_file(file_path)
            # print('longest_line_file:',longest_line_file)
            if longest_line_file > longest_line_package:
                longest_line_package = longest_line_file

    return longest_line_package


def num_of_files_in_the_package(directory_path: str) -> int:
    """
    The function returns the number of files in the package.
    Malicious packages often tend to contain a very small amount of files.

    Args:
    - directory_path (str): The path to the directory being checked.

    Returns:
    - int: Returns the of files in the package.
    """
    logging.info("start func: num_of_files_in_the_package")

    # Store the number of files in the package
    num_of_files = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for _, __, filenames in os.walk(directory_path):
        # print('num_of_files: ', _, __, num_of_files)
        num_of_files += len(filenames)

    return num_of_files


def does_contain_license(directory_path: str) -> int:
    """
    The function returns 1 if the package contain a license file and 0 otherwise.

    Args:
    - directory_path (str): The path to the directory being checked.

    Returns:
    - int: Returns 1 if the package contain a license file and 0 otherwise.
    """
    logging.info("start func: is_contain_license")

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename == 'LICENSE':
                return 1

    return 0


def predict(dataDict):
    print('predicting')
    print(dataDict)
    # return dataDict
    # return jsonify(dataDict), 200
    return jsonify(dataDict), 200


app = Flask(__name__)
CORS(app)

# target_folder = "./node_modules/normalize-git-url"


def extract_feature(directory, target_folder, package_name, package_version, level):
    global is_PII, is_file_sys_access, is_process_creation, is_network_access, is_crypto_functionality, is_data_encoding, is_dynamic_code_generation, is_package_installation, is_geolocation, is_minified_code, is_has_no_content, longest_line, num_of_files, has_license
    package_features = {}  # {package_name:[f1, f2, ..., fn]}
    visited_packages = set()  # the set will contain the packages name that were traversed
    NUM_OF_FEATURES_INCLUDE = 17

    for root, dirs, files in os.walk(directory):
        # print("Root:", root, " level: ", level, 'files: ',
        #   files, 'target_folder: ', target_folder)
        # print("Dirs:", dirs)
        # print("Files:", files)

        if root == target_folder:

            # Process the files or perform actions in the target folder
            for file in files:
                # print('file: ', file)
                if (not file.endswith('.js') and not file.endswith('.json')) or file.endswith('.min.js'):
                    continue
                file_path = os.path.join(root, file)
                # print('file_path: ', file_path)

                if package_name not in package_features:
                    # if not, initialize a list of NUM_OF_FEATURES_INCLUDE elements with value 0
                    # print('not init')
                    init_lst = [0] * NUM_OF_FEATURES_INCLUDE
                    package_features[package_name] = init_lst

                name, version = package_name, package_version
                is_PII = max(is_PII, search_PII(parse_file(file_path)))
                is_file_sys_access = max(is_file_sys_access, search_file_sys_access(
                    parse_file(file_path)))  # 3
                is_process_creation = max(is_process_creation, search_file_process_creation(
                    parse_file(file_path)))  # 4
                is_network_access = max(is_network_access, search_network_access(
                    parse_file(file_path)))  # 5
                is_crypto_functionality = max(is_crypto_functionality, search_cryptographic_functionality(
                    parse_file(file_path)))  # 6
                is_data_encoding = max(
                    is_data_encoding, search_data_encoding(parse_file(file_path)))   # 7
                is_dynamic_code_generation = max(is_dynamic_code_generation, search_dynamic_code_generation(
                    parse_file(file_path)))   # 8
                is_package_installation = max(is_package_installation, search_package_installation(
                    parse_file(file_path)))   # 9
                # print('etodur')
                # print('visited packages: ', visited_packages)
                # check if the package was already processed
                if package_name not in visited_packages:
                    logging.info(f'package_name: {package_name}')
                    logging.debug(f"{package_name} was not visit yet")
                    index = root.find(package_name)
                    # print('index: ', index)
                    logging.debug(f"dirname[:index]: {root[:index]}")
                    # print('root[:index]: ', root[:index])
                    is_geolocation = max(
                        is_geolocation, search_geolocation(root[:index]))  # 10
                    is_minified_code = max(
                        is_minified_code, search_minified_code(root[:index]))  # 11
                    is_has_no_content = search_packages_with_no_content(
                        root[:index])  # 12
                    # print('majhe')
                    longest_line = longest_line_in_the_package(
                        root[:index])  # 13
                    # print('\n\n\nreturned longest_line: ', longest_line, '\n\n\n\n')
                    num_of_files = num_of_files_in_the_package(
                        root[:index])  # 14
                    has_license = does_contain_license(root[:index])  # 15
                    visited_packages.add(package_name)
                    # print('shesh')
                else:
                    logging.debug(f"package_features: {package_features}")
                    is_geolocation = package_features[package_name][10]
                    is_minified_code = package_features[package_name][11]
                    is_has_no_content = package_features[package_name][12]
                    longest_line = package_features[package_name][13]
                    num_of_files = package_features[package_name][14]
                    has_license = package_features[package_name][15]
                if (dirs.__len__() > 0 and level < 1):
                    # print('dirs calling inside: ', level, root ,dirs)
                    for dir in dirs:
                        extract_feature(os.path.join(root, dir), os.path.join(
                            root, dir), package_name, package_version, level+1)

                label = 'Unknown'  # 16
                # create a new list of the current package's features
                new_inner_lst = [name, version, is_PII, is_file_sys_access, is_process_creation,
                                 is_network_access, is_crypto_functionality, is_data_encoding,
                                 is_dynamic_code_generation, is_package_installation, is_geolocation, is_minified_code,
                                 is_has_no_content, longest_line, num_of_files, has_license, label]

                # print('new_inner_lst: ', new_inner_lst)
                # get the old feature list for the current package name
                old_inner_lst = package_features[package_name]

                logging.debug(f'new_inner_lst: {new_inner_lst[2:-7]}')
                logging.debug(f'old_inner_lst: {old_inner_lst[2:-7]}')
                # perform the bitwise operation between the new and old feature lists
                updated_inner_lst = bitwise_operation(
                    new_inner_lst[2:-7], old_inner_lst[2:-7], '|')
                logging.debug(f'updated_inner_lst: {updated_inner_lst}')

                pre_list = [name, version]
                past_list = [is_geolocation, is_minified_code, is_has_no_content,
                             longest_line, num_of_files, has_license, label]

                # update the value in the package_features dictionary with the updated feature list
                package_features[package_name] = pre_list + \
                    updated_inner_lst + past_list

            break
    headers = ['package', 'version', 'PII', 'file_sys_access', 'file_process_creation',
               'network_access', 'cryptographic_functionality', 'data_encoding',
               'dynamic_code_generation', 'package_installation', 'geolocation', 'minified_code',
               'no_content', 'longest_line', 'num_of_files', 'has_license', 'label']

    # define the path for the output CSV file
    csv_file = 'dataset-validation.csv'
    # print('calling write data to csv')
    if level == 0:
        write_dict_to_csv(dict_data=package_features,
                          csv_file=csv_file, headers=headers, method='a')
        return package_features


fileData = open("./utils/predictor/model.pkl", "rb")
myModel = joblib.load(fileData)
fileData.close()


def predictPackage(featureDict):
    df = pd.DataFrame([featureDict])
    prediction = myModel.predict(df)
    print(prediction)
    return prediction


def hash_package(root):
    """
    Compute an md5 hash of all files under root, visiting them in deterministic order.
    `package.json` files are stripped of their `name` and `version` fields.
    """
    m = hashlib.md5()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            m.update(f"{os.path.relpath(path, root)}\n".encode("utf-8"))
            if filename == "package.json":
                pkg = json.load(open(path))
                pkg["name"] = ""
                pkg["version"] = ""
                m.update(json.dumps(pkg, sort_keys=True).encode("utf-8"))
            else:
                try:
                    with open(path, "rb") as f:
                        m.update(f.read())
                except:
                    print(f'ERROR: path {path}')
    return m.hexdigest()


def is_hash_in_csv(root: str, csv_file: str) -> int:
    """
    This function calculates the hash of a package and returns 1 if the hash is in the given CSV file, and 0 otherwise.

    Args:
        root: The root directory of the package to calculate the hash
        csv_file: The path to the CSV file.

    Returns:
        1 if the hash of the directory is in the CSV file, 0 otherwise.
    """
    hash = hash_package(root)
    with open(csv_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0] == hash:
                return 1
    return 0


@app.route('/')
def hello():
    return "Hello from Siam!"


@app.route('/packages/vote', methods=['POST'])
def vote():
    # Get the JSON data from the request
    data = request.get_json()
    # Check if the request contains valid JSON data
    if data is None:
        return jsonify({'error': 'Invalid JSON data'}), 400

    # print(data)

    # # Process the received JSON object (data) here if needed
    pkgName = request.args.get('package_name')
    pkgVersion = request.args.get('package_version')
    vote = data['vote']
    # query the database for the package
    package = collection.find_one({"name": pkgName, "version": pkgVersion})
    # print('package: ', package)
    if package:
        # Package found, return the package details as JSON
        # return jsonify({"package_name": package["name"], "package_version": package["version"], "other_info": package["other_info"]})
        # update the package info
        totalVotes = package['totalVotes']
        agreedVotes = package['agreedVotes']
        if vote == 'Agree':
            agreedVotes += 1
        totalVotes += 1

        # update the package info in db
        collection.find_one_and_update({"name": pkgName, "version": pkgVersion}, {
                                       "$set": {"totalVotes": totalVotes, "agreedVotes": agreedVotes}})
        return jsonify({"package_name": package["name"], "package_version": package["version"], "totalVotes": totalVotes, "agreedVotes": agreedVotes}), 200
    else:
        # Package not found
        return jsonify({"error": "Package not found"}, 404)


def getDownloadCount(package_name):

    yearly_download_count = []
    # Calculate the start and end dates for the week range
    end_date = datetime.now()
    for i in range(0, 52):
        # print('i: ', i)
        start_date = end_date - timedelta(days=7)

        # Format dates as strings in the 'YYYY-MM-DD' format
        start_date_str = start_date.strftime('%Y-%m-%d')
        end_date_str = end_date.strftime('%Y-%m-%d')

        # Build the URL for the npm download stats API
        url = f'{NPM_API_URL}/{start_date_str}:{end_date_str}/{package_name}'

        try:
            # Make a GET request to the npm API
            # print(url)
            response = requests.get(url)
            # print(response)

            if response.status_code == 200:
                # Parse the JSON response and extract the download count
                data = response.json()
                # print('data: ', data)
                download_count = data['downloads']
                # print('download count: ', download_count)
                yearly_download_count.append(
                    {'downloads': download_count, 'startDate': start_date_str, 'endDate': end_date_str})
                # return jsonify({"package_name": package_name, "download_count": download_count})
            else:
                # API request failed
                print('error occurred')
                # return jsonify({"error": "Failed to retrieve download count"}, 500)
        except Exception as e:
            print("error", str(e))
            return jsonify({"error": str(e)}, 500)
        end_date = start_date
    return {"package_name": package_name, "download_count": yearly_download_count}


@app.route('/package', methods=['GET'])
def getPackageDetails():
    # Get package name and version from the request parameters
    package_name = request.args.get('package_name')
    package_version = request.args.get('package_version')
    try:
        # Run 'npm view' command and capture the output
        processed_package_name = package_name + '@' + package_version
        cmd = ['npm', 'view', processed_package_name, '--json']
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:

            package_info = json.loads(result.stdout)

            if (type(package_info) == list):
                index = package_info.__len__() - 1
                package_info = package_info[index]
            # package_info = result.stdout
            # print('package info: ', package_info)
            # get the package info from database
            package = collection.find_one(
                {"name": package_name, "version": package_version})
            # print('package: ', package)
            if package:
                # print(type(package_info))
                # Package found, return the package details as JSON
                package_info['prediction'] = package['prediction']
                package_info['reproducible'] = package['reproducible']
                package_info['cloned'] = package['cloned']
                package_info['features'] = package['features']
                package_info['finalPrediction'] = package['finalPrediction']
                package_info['totalVotes'] = package['totalVotes']
                package_info['agreedVotes'] = package['agreedVotes']
                return jsonify(package_info), 200
                # package_info['download_count'] = getDownloadCount(package_name)

            else:
                package = posthelper(package_name, package_version)
                package_info['prediction'] = package['prediction']
                package_info['reproducible'] = package['reproducible']
                package_info['cloned'] = package['cloned']
                package_info['features'] = package['features']
                package_info['finalPrediction'] = package['finalPrediction']
                package_info['totalVotes'] = package['totalVotes']
                package_info['agreedVotes'] = package['agreedVotes']
                return package
        else:
            # Command failed
            return jsonify({"error": "Failed to retrieve package information"}, 500)
    except Exception as e:
        return jsonify({"error": str(e)}, 500)


def posthelper(pkgName, pkgVersion):
    try:
        global is_PII, is_file_sys_access, is_process_creation, is_network_access, is_crypto_functionality, is_data_encoding, is_dynamic_code_generation, is_package_installation, is_geolocation, is_minified_code, is_has_no_content, longest_line, num_of_files, has_license
        # check if a package with the same name and version already exists in the database
        pkg = collection.find_one({"name": pkgName, "version": pkgVersion})

        if pkg:
            # Package found, return the package details as JSON
            # print('package found: ', pkg)
            # return jsonify(pkg_serializable), 200
            return jsonify({'_id': str(pkg['_id']), 'prediction': str(pkg['prediction']), 'features': str(pkg['features']), 'reproducible': str(pkg['reproducible']), 'cloned': str(pkg['cloned']), 'finalPrediction': str(pkg['finalPrediction']),
                            'totalVotes': pkg['totalVotes'], 'agreedVotes': pkg['agreedVotes']}), 200

         # Call the reproduce-package.sh script using subprocess
        cmd = ['./utils/reproducer/build-package.sh',
               pkgName, pkgVersion, '.', 'node_modules']
        # print(cmd)
        result = subprocess.Popen(cmd)
        result.wait()
        # print(cmd)
        # print(result.returncode)
        # print(result.stdout)
        # print(result.stderr)
        is_crypto_functionality = 0
        is_data_encoding = 0
        is_dynamic_code_generation = 0
        is_package_installation = 0
        is_geolocation = 0
        is_minified_code = 0
        is_has_no_content = 0
        longest_line = 0
        num_of_files = 0
        has_license = 0
        is_PII = 0
        is_file_sys_access = 0
        is_process_creation = 0
        is_network_access = 0
        pkgFeatures = extract_feature(
            './node_modules', './node_modules/'+pkgName, pkgName, pkgVersion, 0)[pkgName]
        # traverse the node_modules folder and find the folder of pkgName
        # print('pkgFeatures: ', pkgFeatures)
        # remove the first two elements from the list
        pkgFeatures = pkgFeatures[2:]
        # remove the last element from the list
        pkgFeatures = pkgFeatures[:-1]
        print('pkgFeatures: ', pkgFeatures)
        prediction = predictPackage(pkgFeatures)
        # print('prediction: ', prediction)
        reproducible = 0
        cloned = 0
        finalPrediction = prediction[0]
        # print('finalPrediction: ', finalPrediction)
        if prediction[0] == 'Malicious' or prediction[0] == 'malicious':
            # check reproducibility
            cmd = ['./utils/reproducer/reproduce-package.sh',
                   pkgName + '@' + pkgVersion, './node_modules/']
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            # print(result.returncode)
            # print(result.stdout)
            # print(result.stderr)
            if result.returncode == 0:
                # pkgFeatures.append('benign')
                finalPrediction = 'Benign'
                reproducible = 1

        else:
            cloned = is_hash_in_csv('./node_modules/'+pkgName,
                                    'malicious_hash.csv')
            if cloned == 1:
                # pkgFeatures.append('malicious')
                finalPrediction = 'Malicious'
                cloned = 0
                # check clone

            # insert the package info in db
        packageInfo = {
            'name': pkgName,
            'version': pkgVersion,
            'features': pkgFeatures,
            'prediction': prediction[0],
            'reproducible': reproducible,
            'cloned': cloned,
            'finalPrediction': finalPrediction,
            'totalVotes': 0,
            'agreedVotes': 0,
        }
        # Store the data in the MongoDB collection
        collection.insert_one(packageInfo)

        return jsonify({'prediction': str(prediction[0]), 'features': str(pkgFeatures), 'reproducible': str(reproducible), 'cloned': str(cloned), 'finalPrediction': str(finalPrediction), 'totalVotes': str(0), 'agreedVotes': str(0)}), 200

        # Return the received JSON object as a JSON response

        # create a package.json file in ./reproducer
        # run npm install in ./reproducer

        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/package', methods=['POST'])
def post():
    try:
        global is_PII, is_file_sys_access, is_process_creation, is_network_access, is_crypto_functionality, is_data_encoding, is_dynamic_code_generation, is_package_installation, is_geolocation, is_minified_code, is_has_no_content, longest_line, num_of_files, has_license

        data = request.get_json()

        if data is None:
            return jsonify({'error': 'Invalid JSON data'}), 400
        packages = data['packages']
        for package in packages:
            # print(package)
            # num = random.randint(0, 10)
            # if num < 5:
            #     # SLEEP FOR 2 seconds
            #     # time.sleep(2)
            #     packageInfo = {
            #         'prediction': 'Benign',
            #         'features': [0, 1, 1, 0, 0, 0, 0, 0, 0],
            #         'reproducible': 0,
            #         'cloned': 0,
            #         'finalPrediction': 'Benign'
            #     }
            #     # Store the data in the MongoDB collection
            #     collection.insert_one(packageInfo)

            # else:
            #     packageInfo = {
            #         'prediction': 'Benign',
            #         'features': [0, 1, 1, 0, 0, 0, 0, 0, 0]
            #     }
            #     # Store the data in the MongoDB collection
            #     collection.insert_one(packageInfo)
            # return jsonify({'prediction': 'Malicious', 'features': [
            #         1, 0, 0, 1, 1, 1, 1, 1, 1]}), 200
            pkgName = package.split(':')[0]
            pkgVersion = package.split(':')[1]
            # print('pkgName: ', pkgName, 'pkgVersion: ', pkgVersion)
            responnse = posthelper(pkgName, pkgVersion)

            # check if a package with the same name and version already exists in the database
            # pkg = collection.find_one({"name": pkgName, "version": pkgVersion})
            # print('package: ', pkg)
            # if pkg:
            #     # Package found, return the package details as JSON
            #     print('package found: ', pkg)
            #     # return jsonify(pkg_serializable), 200
            #     return jsonify({'_id': str(pkg['_id']), 'prediction': str(pkg['prediction']), 'features': str(pkg['features']), 'reproducible': str(pkg['reproducible']), 'cloned': str(pkg['cloned']), 'finalPrediction': str(pkg['finalPrediction'])}), 200

            # # Call the reproduce-package.sh script using subprocess
            # cmd = ['./utils/reproducer/build-package.sh',
            #        pkgName, pkgVersion, '.', 'node_modules']
            # print(cmd)
            # result = subprocess.Popen(cmd)
            # result.wait()
            # # print(cmd)
            # # print(result.returncode)
            # # print(result.stdout)
            # # print(result.stderr)
            # is_crypto_functionality = 0
            # is_data_encoding = 0
            # is_dynamic_code_generation = 0
            # is_package_installation = 0
            # is_geolocation = 0
            # is_minified_code = 0
            # is_has_no_content = 0
            # longest_line = 0
            # num_of_files = 0
            # has_license = 0
            # is_PII = 0
            # is_file_sys_access = 0
            # is_process_creation = 0
            # is_network_access = 0
            # pkgFeatures = extract_feature(
            #     './node_modules', './node_modules/'+pkgName, pkgName, pkgVersion, 0)[pkgName]
            # # traverse the node_modules folder and find the folder of pkgName
            # print('pkgFeatures: ', pkgFeatures)
            # # remove the first two elements from the list
            # pkgFeatures = pkgFeatures[2:]
            # # remove the last element from the list
            # pkgFeatures = pkgFeatures[:-1]
            # prediction = predictPackage(pkgFeatures)
            # print('prediction: ', prediction)
            # reproducible = 0
            # cloned = 0
            # finalPrediction = prediction[0]
            # if prediction[0] == 'Malicious' or prediction[0] == 'malicious':
            #     # check reproducibility
            #     cmd = ['./utils/reproducer/reproduce-package.sh',
            #            pkgName + '@' + pkgVersion, './node_modules/']
            #     result = subprocess.run(cmd, stdout=subprocess.PIPE,
            #                             stderr=subprocess.PIPE, text=True)
            #     print(result.returncode)
            #     print(result.stdout)
            #     print(result.stderr)
            #     if result.returncode == 0:
            #         pkgFeatures.append('benign')
            #         finalPrediction = 'Benign'
            #         reproducible = 1

            # else:
            #     cloned = is_hash_in_csv('./node_modules/'+pkgName,
            #                             'malicious_hash.csv')
            #     if cloned == 1:
            #         pkgFeatures.append('malicious')
            #         finalPrediction = 'Malicious'
            #         cloned = 0
            #     # check clone

            # # insert the package info in db
            # packageInfo = {
            #     'name': pkgName,
            #     'version': pkgVersion,
            #     'features': pkgFeatures,
            #     'prediction': prediction[0],
            #     'reproducible': reproducible,
            #     'cloned': cloned,
            #     'finalPrediction': finalPrediction,
            #     'totalVotes': 0,
            #     'agreedVotes': 0,
            # }
            # # Store the data in the MongoDB collection
            # collection.insert_one(packageInfo)

            # return jsonify({'prediction': str(prediction[0]), 'features': str(pkgFeatures), 'reproducible': str(reproducible), 'cloned': str(cloned), 'finalPrediction': str(finalPrediction)}), 200

        # Return the received JSON object as a JSON response

        # create a package.json file in ./reproducer
        # run npm install in ./reproducer

        return responnse
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # print('db', db)
    app.run(host='0.0.0.0', port=5001)

# import sys

# print("Virtual Environment Path:")
# print(sys.prefix)
