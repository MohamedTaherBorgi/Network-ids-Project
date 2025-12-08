from flask import Flask, render_template, jsonify # type: ignore
from alerts import ALERTS # type: ignore

app = Flask(__name__, template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def get_alerts():
    return jsonify({
        "total": len(ALERTS),
        "alerts": ALERTS[-500:]     # last 500 for dashboard
    })