import os
from flask import Flask
import mysql.connector as db
import logging
app = Flask("pokemonstay")

conn = {}
debug = bool(os.environ.get("DEBUG"))
dbhost = os.environ.get("DB_HOST")
dbuser = os.environ.get("DB_USERNAME")
dbpass = os.environ.get("DB_PASSWORD")

if debug:
    conn = db.connect(host=dbhost, port=3306, user=dbuser, password=dbpass, database='mysql')
    if not dbhost:
        raise ValueError("No database hostname/ip set")
    if not dbuser:
        raise ValueError("No database username set")
    if not dbpass:
        raise ValueError("No database password set")

@app.route("/")
def root():
    if debug:
        cursor = conn.cursor()
        cursor.execute("SELECT User FROM user;")
        s = ''
        for (user) in cursor:
            s += user[0].decode("utf-8")
        cursor.close()
        return s
    return "Hello, Production"
