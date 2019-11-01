import os
from flask import Flask, request, render_template, redirect, jsonify, url_for, make_response
from http import HTTPStatus as status
import mysql.connector as db
import logging
import secrets
import re
import bcrypt
import datetime
import jwt

# Store application's state in this dictionary
stay = {}

def env(s):
    v = os.environ.get(s)
    if not v:
        raise ValueError(s+" not set")
    return v

# Initialize app
# Use this flag for debug-specific logic
stay["debug"] = env("DEBUG") == "True"

# Connect to MariaDB
stay["conn"] = db.connect(
    host=env("DB_HOST"),
    user=env("DB_USERNAME"),
    password=env("DB_PASSWORD"),
    database=env("DB_NAME"),
)

# Create secret key for JSON-WEB-TOKEN
stay["jwt_secret"] = env("JWT_SECRET")

# Construct application
app = Flask(
    import_name="pokemonstay",
    static_url_path="/static",
)

@app.route("/myMon")
def myMon():
    msg = request.args.get('msg', None)
    #do a query based on user
    # display their pokemon nicknames with links to the pokedex page, rename, and release
    cursor = stay["conn"].cursor(prepared=True)
    query = ("SELECT pokemonNo, level, gender, speciesName, gender, shiny, met, nickname, ownsId FROM `owns` natural join `pokemon` "
            "WHERE userId = %s")
    #how do users work?
    # temporarily just doing with userid = 1 (testing all other shit)
    uid = 1
    tup = (uid,)
    cursor.execute(query, tup)
    info = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for item in info:
        item['speciesName'] = str(item['speciesName'],'utf-8')
        if item['nickname'] is not None:
            item['nickname'] = str(item['nickname'],'utf-8')
    size = len(info)
    cursor.close()
    return render_template("/myMon.html", info=info, size=size, msg=msg)


@app.route("/release/<id>")
def release(id):
    cursor = stay["conn"].cursor(prepared=True)
    # also make sure that the user owns this pokemon (via part of the query)
    # will have to adjust userId number later
    uid = 1
    tup = (id,uid)
    query = ("SELECT pokemonNo, level, gender, speciesName, gender, shiny, met, nickname, ownsId FROM `owns` natural join `pokemon` "
            "Where ownsId = %s AND userId = %s")
    cursor.execute(query, tup)
    info = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for item in info:
        item['speciesName'] = str(item['speciesName'],'utf-8')
        if item['nickname'] is not None:
            item['nickname'] = str(item['nickname'],'utf-8')
    size = len(info)
    if size==0:
        msg = "Either that mon does not exist or you do not have privileges to release it"
    if size !=0:
        msg = "You just released mon " + info[0]['speciesName'] + " with mon id "+ str(id)
        query = ("DELETE FROM `owns` "
                "WHERE ownsId = %s")
        cursor.execute(query, (id,))
        stay["conn"].commit()

    cursor.close()

    return redirect(url_for('myMon',msg=msg), code=302)

@app.route("/rename/<id>")
def rename(id):
    return render_template("/rename.html", id=id)

@app.route("/rename/submit/<id>",methods=['GET','POST'])
def rename_submit(id):
    if request.method == 'POST':
        nickname = request.form['nickname']
        cursor = stay["conn"].cursor(prepared=True)
        # also make sure that the user owns this pokemon (via part of the query)
        # will have to adjust userId number later
        uid = 1
        tup = (id,uid)
        # returns 0 or 1 entries... 0 if user and mon mismatch or mon DNE... 1 if match
        query = ("SELECT pokemonNo, level, gender, speciesName, gender, shiny, met, nickname, ownsId FROM `owns` natural join `pokemon` "
                "Where ownsId = %s AND userId = %s")
        cursor.execute(query, tup)
        info = []
        columns = tuple( [d[0] for d in cursor.description] )
        for row in cursor:
            info.append(dict(zip(columns, row)))
        for item in info:
            item['speciesName'] = str(item['speciesName'],'utf-8')
            if item['nickname'] is not None:
                item['nickname'] = str(item['nickname'],'utf-8')
        size = len(info)
        if size==0:
            msg = "Either that mon does not exist or you do not have privileges to rename it"
        if size !=0:
            msg = "You just renamed mon " + info[0]['speciesName'] + " with mon id " + str(info[0]['ownsId']) + " to "+ nickname
            if nickname == "":
                msg = "You just got rid of the nickname for mon " + info[0]['speciesName'] + " with mon id " + str(info[0]['ownsId'])
            query = ("UPDATE `owns` SET `nickname`=%s WHERE `ownsId`=%s")
            cursor.execute(query, (nickname,id))
            stay["conn"].commit()

        cursor.close()

        return redirect(url_for('myMon',msg=msg), code=302)

    return redirect(url_for('myMon',msg="bad url"), code=302)

@app.route("/pokedex")
def dexMain_view():
    cursor = stay["conn"].cursor(prepared=True)
    query = ("SELECT pokemonNo, speciesName, typeName, slot from pokemon NATURAL JOIN hasType NATURAL JOIN types ORDER By pokemonNo")
    cursor.execute(query)
    info = []
    result = []
    i = 0
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    while i < len(info):
        item = {}
        if i != len(info) -1 and info[i]['pokemonNo'] == info[i+1]['pokemonNo']:
            item['pokemonNo'] = info[i]['pokemonNo']
            item['speciesName'] = str(info[i]['speciesName'],'utf-8')
            item['typeName'] = str(info[i]['typeName'],'utf-8')
            item['typeName2'] = str(info[i+1]['typeName'],'utf-8')
            result.append(item)
            i +=2
        else:
            item['pokemonNo'] = info[i]['pokemonNo']
            item['speciesName'] = str(info[i]['speciesName'],'utf-8')
            item['typeName'] = str(info[i]['typeName'],'utf-8')
            result.append(item)
            i+=1 
    cursor.close()
    return render_template("/dexmain.html", info=result)

@app.route("/dex/<id>")
def dex_view(id):
    cursor = stay["conn"].cursor(prepared=True)
    # at most one match
    query = ("SELECT speciesName, pokemonNo, height, weight, typeName, slot from pokemon NATURAL JOIN hasType NATURAL JOIN types Where pokemonNo=%s ORDER By pokemonNo")
    tup = (id,)
    cursor.execute(query, tup)
    info = []
    result = []
    i = 0
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))

    item = {}
    if len(info) ==2:
        item['pokemonNo'] = info[i]['pokemonNo']
        item['height'] = info[i]['height'] / 10
        item['weight'] = info[i]['weight'] / 10
        item['speciesName'] = str(info[i]['speciesName'],'utf-8')
        item['typeName'] = str(info[i]['typeName'],'utf-8')
        item['typeName2'] = str(info[i+1]['typeName'],'utf-8')
        result.append(item)
    else:
        item['pokemonNo'] = info[i]['pokemonNo']
        item['height'] = info[i]['height'] / 10
        item['weight'] = info[i]['weight'] / 10
        item['speciesName'] = str(info[i]['speciesName'],'utf-8')
        item['typeName'] = str(info[i]['typeName'],'utf-8')
        result.append(item) 
    cursor.close()
    return render_template("/dex.html", info=result)

# Pre-compile password validation regexes
valid_password = [
    re.compile(r"^[a-zA-Z\d !\"#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]{8,128}$"),
    re.compile(r".*[a-zA-Z].*"),
    re.compile(r".*[\d].*"),
    re.compile(r".*[ !\"#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~].*"),
]

valid_userName = re.compile(r"^[a-zA-Z\d.-_]{8,128}$")

# Prevent caching on static assets until cache policy is decided.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# validate checks that the provided password meets the following restrictions
# 1. It is between 8 and 128 characters long.
# 2. Its characters must be limited to lower-case ascii characters,
#    upper-case ascii characters, the digits 0 through 9, and the
#    following special characters: " !\"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~".
# 3. At least one letter, one number, and one special character.
def validate(password):
    for rgx in valid_password:
        if not rgx.match(password):
            return False
    return True

def authenticate(token):
    try:
        return jwt.decode(token, stay["jwt_secret"])
    except:
        return None

@app.route("/auth/logout", methods=["POST"])
@app.route("/auth/login", methods=["POST"])
@app.route("/auth/create-account", methods=["POST"])
def auth():
    cmd = os.path.basename(request.path)
    body = request.get_json()
    res = make_response('', status.OK)
    params = authenticate(request.cookies.get('access_token'))
    if params is not None:
        # User is already logged in.
        if cmd != "logout":
            # Check that command is not logout
            return make_response(jsonify({'err': 'Already logged in'}), status.BAD_REQUEST)
        # Clear client's access token
        res.set_cookie('access_token', value='', expires=0, httponly=True)
    elif cmd == "login":
        # User has requested to log in.
        # Get timestamp early
        lastLogin = datetime.datetime.utcnow()
        # Try parsing JSON from request for email and password.
        try:
            email, password = body['email'], body['password']
        except:
            return make_response(jsonify({'err': 'Could not parse email and password'}), status.BAD_REQUEST)

        # Check db for preexisting record for that email
        try:
            cursor = stay["conn"].cursor(prepared=True)
            cursor.execute("SELECT userid, passHash FROM Trainer WHERE email = %s", (email,))
            row = cursor.fetchone()
            cursor.close()
            if row == None:
                return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
        except Exception as err:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)

        (userid, passHash) = row
        if not bcrypt.checkpw(password.encode('utf-8'), passHash.encode('utf-8')):
            return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)

        # Set lastLogin.
        try:
            cursor = stay["conn"].cursor(prepared=True)
            cursor.execute("UPDATE Trainer SET lastLogin = %s WHERE userid = %s", (lastLogin, userid))
            stay["conn"].commit()
            cursor.close()
        except Exception as err:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)

        # Set JWT
        exp = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        token = jwt.encode({
            'userid': userid,
            'email': email,
            'exp': exp,
        }, stay["jwt_secret"], algorithm='HS256')
        res.set_cookie('access_token', value=token, expires=exp, httponly=True)
    elif cmd == "create-account":
        # User has requested to create an account.
        # Try parsing JSON from request for email, username, and password.
        try:
            email, userName, password = body['email'], body['username'], body['password']
        except:
            return make_response(jsonify({'err': 'Could not parse email, username, and password'}), status.BAD_REQUEST)

        # Check db for preexisting record for that email
        try:
            cursor = stay["conn"].cursor(prepared=True)
            cursor.execute("SELECT userid FROM Trainer WHERE email = %s", (email,))
            nrows = len(cursor.fetchall())
            cursor.close()
            if nrows > 0:
                return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
        except:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)

        # Validate username
        if not valid_userName.match(userName):
            return make_response(jsonify({'err': 'Invalid username'}), status.BAD_REQUEST)

        # Validate password
        if not validate(password):
            return make_response(jsonify({'err': 'Invalid password'}), status.BAD_REQUEST)

        # Hash password with bcrypt
        passHash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert into table
        try:
            cursor = stay["conn"].cursor(prepared=True)
            cursor.execute("INSERT INTO Trainer (email, userName, passHash) VALUES (%s, %s, %s)", (email, userName, passHash))
            stay["conn"].commit()
            cursor.close()
        except Exception as err:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    return res

@app.route("/")
def root():
    token = authenticate(request.cookies.get('access_token'))
    if token is not None:
        return render_template("index.html", token=token)
    return render_template("auth.html")