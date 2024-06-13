from flask import Flask, request
from flask_cors import CORS
import waitress
from anicli import get_stream_url
import asyncio

app = Flask(__name__)
CORS(app)  # This will enable CORS for all routes


@app.route("/")
def hello_world():
    return "Hello, World!"


@app.route("/", methods=["POST", "OPTIONS"])
def reverse_string():
    if request.method == "OPTIONS":
        return "", 204  # Handle CORS preflight request
    input_string = request.json.get("input_string", "")
    try:
        links = asyncio.run(get_stream_url(input_string))
        return {"links": links}
    except Exception as e:
        print(e)
        return {"error": "An error occurred"}, 500


if __name__ == "__main__":
    waitress.serve(app, port=5000)
