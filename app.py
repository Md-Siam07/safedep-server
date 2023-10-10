from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)


@app.route('/')
def hello():
    return "Hello from Siam!"


@app.route('/post', methods=['POST'])
def post():
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Check if the request contains valid JSON data
        if data is None:
            return jsonify({'error': 'Invalid JSON data'}), 400

        print(data)

        # # Process the received JSON object (data) here if needed
        packages = data['packages']
        for package in packages:
            print(package)
            pkgName = package.split(':')[0]
            pkgVersion = package.split(':')[1]
            print(pkgName, pkgVersion)
            # Call the reproduce-package.sh script using subprocess
            cmd = ['./utils/reproducer/reproduce-package.sh',
                   pkgName, pkgVersion, '.', 'node_modules']
            print(cmd)
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)

            print(cmd)
            print(result.returncode)
            print(result.stdout)
            print(result.stderr)

        # Return the received JSON object as a JSON response

        # create a package.json file in ./reproducer
        # run npm install in ./reproducer

        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# import sys

# print("Virtual Environment Path:")
# print(sys.prefix)
