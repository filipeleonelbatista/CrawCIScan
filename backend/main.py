#CRAWCISCAN

import requests
from flask import Flask, render_template, request
import flask
import scanner
import json
from flask_cors import CORS

crawciscan = Flask(__name__)
CORS(crawciscan)

@crawciscan.route("/",methods=['POST'])
def scanthesite():
    target_url = request.get_json()

    links_to_ignore = [""]
    data_dict = {"username": "admin", "password": "password", "Login": "submit"}
    vuln_scanner = scanner.Scanner(target_url["site"], links_to_ignore)
    vuln_scanner.crawl()

    output = vuln_scanner.run_scanner()
    
    return flask.json.jsonify(output)


if __name__ == "__main__":
    crawciscan.run(debug=True)

