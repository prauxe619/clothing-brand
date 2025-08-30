from datetime import datetime
import pandas as pd
from app import app
from flask import request
from flask import Flask, request, redirect, url_for, flash
from app import is_login_anomaly


login_attempts = []

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    username = request.form['username']
    password = request.form['password']
    timestamp = datetime.now()

    login_attempts.append({'ip': ip, 'username': username, 'timestamp': timestamp})

    # Run anomaly detection after X attempts
    if len(login_attempts) > 20:
        df = pd.DataFrame(login_attempts)
        if is_login_anomaly(df):
            flash("Unusual login activity detected.", "danger")
            return redirect(url_for('login'))

    # Continue login as normal
