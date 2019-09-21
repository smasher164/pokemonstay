from flask import Flask
app = Flask("pokemonstay")

@app.route("/")
def root():
    return 'Hello, World!'