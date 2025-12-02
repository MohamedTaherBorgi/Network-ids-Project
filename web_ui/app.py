# web_ui/app.py
from flask import Flask, render_template, jsonify
from alerts import ALERTS

app = Flask(__name__, template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def get_alerts():
    return jsonify(ALERTS[-100:])  # Last 100 alerts