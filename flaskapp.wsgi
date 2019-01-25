#!/usr/bin/python
import sys, os
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/FlaskApp/")
os.chdir('/var/www/FlaskApp/')

from application import app as application
application.secret_key = 'your secret key'

from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return sys.version

if __name__ == "__main__":
    app.run()
