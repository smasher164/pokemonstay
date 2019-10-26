import os
from flask import Flask, render_template
import mysql.connector as db
import logging
app = Flask(__name__)

# Store application's state in this dictionary
stay = {}

def env(s):
    v = os.environ.get(s)
    if not v:
        raise ValueError(f"{s} not set")
    return v

def init():
    # Use this flag for debug-specific logic
    stay["debug"] = env("DEBUG") == "True"
    stay["conn"] = db.connect(
        host=env("DB_HOST"),
        user=env("DB_USERNAME"),
        password=env("DB_PASSWORD"),
        database=env("DB_NAME"),
    )
    app = Flask(
        import_name="pokemonstay",
        static_url_path="/static",
    )

@app.route("/")
def root():
    return render_template("create_account.html")

if __name__ == '__main__':
    init()
    app.run()