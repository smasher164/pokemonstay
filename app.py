import os
from flask import Flask, request, render_template, redirect, jsonify, url_for, make_response
from http import HTTPStatus as status
from email_validator import validate_email
import mysql.connector as db
from mysql.connector.cursor import MySQLCursor
import logging
import secrets
import string
import re
import bcrypt
import datetime
import time
import jwt
import numpy

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

# Create secret key for JSON-WEB-TOKEN
stay["jwt_secret"] = env("JWT_SECRET")

# Construct application
app = Flask(
    import_name="pokemonstay",
    static_url_path="/static",
)

class Cursor():
    def __init__(self, *args, **kwargs):
        self.conn = db.connect(
            host=env("DB_HOST"),
            user=env("DB_USERNAME"),
            password=env("DB_PASSWORD"),
            database=env("DB_NAME"),
        )
        self.cursor = self.conn.cursor(*args, **kwargs)
    def __getattr__(self, name):
        if name == "close":
            return self.close
        elif name == "commit":
            return self.conn.commit
        else:
            return getattr(self.cursor, name)
    def __iter__(self):
        for x in self.cursor:
                yield x
    def close(self):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()

def redirback(u):
    res = make_response(redirect(u))
    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    res.set_cookie('referrer', value=request.path, expires=exp, httponly=True)
    return res

def clearref(r):
    res = make_response(r)
    res.set_cookie('referrer', value='', expires=0, httponly=True)
    return res

# rand11 returns a url-safe 11-character cryptographically random
# string (similar to youtube video IDs) composed of a-z, A-Z, 0-9, '-',
# or '_'. This is meant to be used for temporary urls.
def rand11():
    alphabet = alphabet = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(alphabet) for i in range(11))

def get_mon(cursor, userid):
    cursor.execute("SELECT pokemonNo, level, gender, speciesName, gender, shiny, met, nickname, ownsId FROM `owns` natural join `pokemon` WHERE userId = %s", (userid,))
    info = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for row in info:
        row['speciesName'] = row['speciesName'].capitalize()
        if row['nickname'] is not None:
            row['nickname'] = row['nickname']
    return info

@app.route("/myMon")
def myMon():
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    msg = request.args.get('msg', None)
    # do a query based on user
    # display their pokemon nicknames with links to the pokedex page, rename, and release
    cursor = Cursor(buffered=True)
    info = get_mon(cursor, token["userid"])
    size = len(info)
    cursor.close()
    return render_template("/myMon.html", info=info, size=size, msg=msg)


@app.route("/release/<id>")
def release(id):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    cursor = Cursor(prepared=True)
    # also make sure that the user owns this pokemon (via part of the query)
    # will have to adjust userId number later
    uid = token["userid"]
    tup = (id,uid)
    query = ("SELECT pokemonNo, level, gender, speciesName, gender, shiny, met, nickname, ownsId FROM `owns` natural join `pokemon` "
            "Where ownsId = %s AND userId = %s")
    cursor.execute(query, tup)
    info = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for item in info:
        item['speciesName'] = str(item['speciesName'],'utf-8').capitalize()
        if item['nickname'] is not None:
            item['nickname'] = str(item['nickname'],'utf-8')
    size = len(info)
    if size==0:
        msg = "Either that mon does not exist or you do not have privileges to release it"
    if size !=0:
        msg = "You just released mon " + info[0]['speciesName'].capitalize()
        query = ("DELETE FROM `owns` "
                "WHERE ownsId = %s")
        cursor.execute(query, (id,))

    cursor.close()
    return redirect(url_for('myMon',msg=msg), code=status.FOUND)

@app.route("/rename/<id>")
def rename(id):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    cursor = Cursor(prepared=True)
    tup = (id,)
    query = ("SELECT pokemonNo, speciesName, nickname, shiny FROM `owns` natural join `pokemon` "
                "Where ownsId = %s")
    cursor.execute(query, tup)
    info = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for item in info:
        item['speciesName'] = str(item['speciesName'],'utf-8').capitalize()
        if item['nickname'] is not None:
            item['nickname'] = str(item['nickname'],'utf-8')

    return render_template("/rename.html", id=id, info=info[0])

@app.route("/rename/submit/<id>",methods=['GET','POST'])
def rename_submit(id):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    if request.method == 'POST':
        nickname = request.form['nickname']
        cursor = Cursor(prepared=True)
        # also make sure that the user owns this pokemon (via part of the query)
        # will have to adjust userId number later
        uid = token["userid"]
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
            item['speciesName'] = str(item['speciesName'],'utf-8').capitalize()
            if item['nickname'] is not None:
                item['nickname'] = str(item['nickname'],'utf-8')
        size = len(info)
        if size==0:
            msg = "Either that mon does not exist or you do not have privileges to rename it"
        if size !=0:
            msg = "You just renamed mon " + info[0]['speciesName'] + " to "+ nickname
            if nickname == "":
                msg = "You just got rid of the nickname for mon " + info[0]['speciesName']
            query = ("UPDATE `owns` SET `nickname`=%s WHERE `ownsId`=%s")
            cursor.execute(query, (nickname,id))

        cursor.close()
        
        return redirect(url_for('myMon',msg=msg), code=status.FOUND)

    return redirect(url_for('myMon',msg="bad url"), code=status.FOUND)

@app.route("/pokedex")
def dexMain_view():
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    cursor = Cursor(prepared=True)
    query = ("SELECT pokemonNo, speciesName, typeName, slot from pokemon NATURAL JOIN hasType NATURAL JOIN types ORDER By pokemonNo,typeName")
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
            item['speciesName'] = str(info[i]['speciesName'],'utf-8').capitalize()
            item['typeName'] = str(info[i]['typeName'],'utf-8')
            item['typeName2'] = str(info[i+1]['typeName'],'utf-8')
            result.append(item)
            i +=2
        else:
            item['pokemonNo'] = info[i]['pokemonNo']
            item['speciesName'] = str(info[i]['speciesName'],'utf-8').capitalize()
            item['typeName'] = str(info[i]['typeName'],'utf-8')
            result.append(item)
            i+=1 
    cursor.close()
    
    return render_template("/dexmain.html", info=result)

@app.route("/dex/<id>")
def dex_view(id):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    cursor = Cursor(prepared=True)
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
        #https://www.serebii.net/pokedex-bw/type/fighting.gif
        item['speciesName'] = str(info[i]['speciesName'],'utf-8').capitalize()
        item['typeName'] = "https://www.serebii.net/pokedex-bw/type/"+str(info[i]['typeName'],'utf-8')+".gif"
        item['typeName2'] = "https://www.serebii.net/pokedex-bw/type/"+str(info[i+1]['typeName'],'utf-8')+".gif"

    else:
        item['pokemonNo'] = info[i]['pokemonNo']
        item['height'] = info[i]['height'] / 10
        item['weight'] = info[i]['weight'] / 10
        item['speciesName'] = str(info[i]['speciesName'],'utf-8').capitalize()
        item['typeName'] = "https://www.serebii.net/pokedex-bw/type/"+str(info[i]['typeName'],'utf-8')+".gif"
    
    # egg groups here
    info = []
    eggs = []
    query = ("SELECT eggName FROM pokemon NATURAL JOIN inEggGroup NATURAL JOIN EggGroup WHERE pokemonNo=%s")
    cursor.execute(query, tup)
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for x in info:
        eggs.append(str(x['eggName'],'utf-8'))
    item['egg'] = eggs

    # locations (with region) here
    query = ("SELECT locationName, regionName FROM pokemon NATURAL JOIN isFound NATURAL JOIN Location NATURAL JOIN Region WHERE pokemonNo=%s")
    info = []
    loc = []
    cursor.execute(query, tup)
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for x in info:
        loc.append((str(x['locationName'],'utf-8'),str(x['regionName'],'utf-8')))
    item['loc'] = loc
    item['locLen'] = len(loc)

    #evolves from
    query = ("SELECT from_pokemonNo FROM pokemon NATURAL JOIN evolves where pokemon.pokemonNo = evolves.to_pokemonNo and pokemonNo=%s")
    info = []
    evolvesFrom = []
    cursor.execute(query, tup)
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for x in info:
        c2 = Cursor(prepared=True)
        extra = []
        query = ("SELECT speciesName FROM pokemon where pokemonNo = %s")
        c2.execute(query,(x['from_pokemonNo'],))
        col2 = tuple( [d[0] for d in c2.description] )
        for row in c2:
            extra.append(dict(zip(col2, row)))
        evolvesFrom.append((x['from_pokemonNo'],str(extra[0]['speciesName'],'utf-8').capitalize()))
        c2.close()

    item['from'] = evolvesFrom
    item['fromLen'] = len(evolvesFrom)
    

    #evolves to
    query = ("SELECT to_pokemonNo FROM pokemon NATURAL JOIN evolves where pokemon.pokemonNo = evolves.from_pokemonNo and pokemonNo=%s")
    info = []
    evolvesTo = []
    cursor.execute(query, tup)
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for x in info:
        c2 = Cursor(prepared=True)
        extra = []
        query = ("SELECT speciesName FROM pokemon where pokemonNo = %s")
        c2.execute(query,(x['to_pokemonNo'],))
        col2 = tuple( [d[0] for d in c2.description] )
        for row in c2:
            extra.append(dict(zip(col2, row)))
        evolvesTo.append((x['to_pokemonNo'],str(extra[0]['speciesName'],'utf-8').capitalize()))
        c2.close()


    item['to'] = evolvesTo
    item['toLen'] = len(evolvesTo)
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
            cursor = Cursor()
            cursor.execute("SELECT userid, passHash FROM Trainer WHERE email = %s", (email,))
            row = cursor.fetchone()
            cursor.close()
            
            if row == None:
                return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
        except Exception as err:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)

        # Validate email
        try:
            validate_email(email)
        except:
            return make_response(jsonify({'err': 'Invalid email'}), status.BAD_REQUEST)

        (userid, passHash) = row
        if not bcrypt.checkpw(password.encode('utf-8'), passHash.encode('utf-8')):
            return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)

        # Set lastLogin.
        try:
            cursor = Cursor()
            cursor.execute("UPDATE Trainer SET lastLogin = %s WHERE userid = %s", (lastLogin, userid))
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
            cursor = Cursor()
            cursor.execute("SELECT userid FROM Trainer WHERE email = %s", (email,))
            nrows = len(cursor.fetchall())
            cursor.close()
            
            if nrows > 0:
                return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
        except:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)

        # Validate email
        try:
            validate_email(email)
        except:
            return make_response(jsonify({'err': 'Invalid email'}), status.BAD_REQUEST)

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
            cursor = Cursor()
            cursor.execute("INSERT INTO Trainer (email, userName, passHash) VALUES (%s, %s, %s)", (email, userName, passHash))
            cursor.close()
            
        except Exception as err:
            return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    return res

# Returns tuple (pkmn_id,pkmn_name)
def rand_pkmn():
    def get_chance_weight(pokeNo):
        return 1
    
    cursor = Cursor(buffered=True)
    query = ("SELECT pokemonNo, speciesName FROM `pokemon`")
    cursor.execute(query,())
    
    #columns = tuple( [d[0] for d in cursor.description] )
    pokemon_ids=[]
    pokemon_names=[]
    
    for row in cursor:
        pokemon_ids.append(row[0])
        pokemon_names.append(row[1])
    cursor.close()
    weighted_pokemon=numpy.array([get_chance_weight(pkmnid) for pkmnid in pokemon_ids])
    weighted_sum=sum(weighted_pokemon)
    r=numpy.random.randint(weighted_sum)
    inc=0

    for i, weight in enumerate(weighted_pokemon):
        inc+=weight
        if r<inc:
            wild_pkmn_idx=i
            break
    pkmn_name=pokemon_names[wild_pkmn_idx].title()
    pkmn_id = pokemon_ids[wild_pkmn_idx]
    return (pkmn_id,pkmn_name)
    

# Returns tuple (pkmn_id,pkmn_name)
# Probably needs to be refactored/optimized later
def get_catchable(uid):
    try:
        cursor = Cursor(buffered=True)
        query = ("SELECT pokemonNo,speciesName,level,gender,shiny FROM `catchable` NATURAL JOIN `pokemon` where userid=%s")
        args = (uid,)
        cursor.execute(query,args)

        columns = tuple( [d[0] for d in cursor.description])
        if cursor.rowcount==0:
            return None
        info = (dict(zip(columns, cursor.fetchone())))
        info['speciesName'] = info['speciesName'].capitalize()
        cursor.close()
        return info
    except Exception as err:
        print('catch ',err)
        return None

# Expects a datetime.timedelta object
# Need to make more robust
def format_catch_time(d):
    s=d.seconds
    hours, remainder = divmod(s, 3600)
    minutes, seconds = divmod(remainder, 60)
    return '{:02} Hours, {:02} Minutes, {:02} seconds'.format(int(hours), int(minutes), int(seconds))

# Returns the amount of time left until the user's last catch expires
def last_catch_expire(uid,expiration_duration):
    last_encounter_query=("SELECT lastCatch FROM `Trainer` where userid=%s")
    last_encounter_args=(uid,)
    cursor = Cursor(buffered=True)
    cursor.execute(last_encounter_query,last_encounter_args)
    columns = tuple( [d[0] for d in cursor.description] )
    last_encounter_dict=dict(zip(columns, cursor.fetchone()))
    cursor.close()
    last_encounter_time=last_encounter_dict.get('lastCatch')
    if last_encounter_time is None:
        last_encounter_time=datetime.datetime.utcnow()-expiration_duration
    time_left=last_encounter_time+expiration_duration-datetime.datetime.utcnow()
    return time_left


@app.route("/catch",methods=['GET','POST'])
def catch():
    token = authenticate(request.cookies.get('access_token'))
    shiny_rate=1/8192
    last_encounter_delta= datetime.timedelta(minutes=1)
    if token is None:
        return redirback(url_for('root'))
    uid=token["userid"]
    def get_shiny_chance():
        return int(numpy.random.ranf()<shiny_rate)
    def get_gender_chance(pokeNo):
        return numpy.random.randint(3)
    if request.method=="GET":
        try:
            msg = request.args.get('msg', None)
            # First check if available to catch new pokemon
            time_left=last_catch_expire(uid,last_encounter_delta)
            pkmn_info={}
            # If user is eligible for new catch, get new pkmn
            if time_left<=datetime.timedelta(0):
                # Find new random pokemon
                pkmn_id,pkmn_name=rand_pkmn()
                pkmn_gender=str(get_gender_chance(pkmn_id))
                pkmn_shiny=str(get_shiny_chance())
                pkmn_level=str(1)
                #Need to pass pkmn id
                #Need to delete old encounters and add new one
                delete_encounter_query=("DELETE FROM `catchable` WHERE userid=%s")
                delete_encounter_args=(uid,)
                insert_encounter_query=("INSERT INTO `catchable` (userid,pokemonNo,gender,shiny,level) VALUES "
                "(%s,%s,%s,%s,%s)")
                insert_encounter_args=(uid,pkmn_id,pkmn_gender,pkmn_shiny,pkmn_level)

                update_encounter_query=("Update `Trainer` SET lastCatch=%s WHERE userid=%s")
                update_encounter_args=(datetime.datetime.utcnow(),uid,)
                
                cursor = Cursor(buffered=True)
                cursor.execute(delete_encounter_query,delete_encounter_args)
                cursor.execute(insert_encounter_query,insert_encounter_args)
                cursor.execute(update_encounter_query,update_encounter_args)
                cursor.close()
                time_left=last_encounter_delta
            # Check `catchable` table to see if user can catch a pokemon
            pkmn_info=get_catchable(uid)
            if pkmn_info==None:
                return render_template("/catch.html", msg=msg, wait_time=format_catch_time(time_left))

            
            return render_template("/catch.html", msg=msg, wait_time=format_catch_time(time_left),
                mon_name=pkmn_info['speciesName'].title(),
                mon_lvl=pkmn_info['level'],
                mon_gender=pkmn_info['gender'],
                mon_shiny=pkmn_info['shiny'],
                mon_no=pkmn_info['pokemonNo']
            )
        except Exception as err:
            print('catch: ', err)
            return redirect(url_for('myMon',msg="Couldn't find a Pokemon"), code=status.SEE_OTHER)
    # Handle POST (caught pokemon)
    else:
        try:
            pkmn_info=get_catchable(uid)
            time_left=last_catch_expire(uid,last_encounter_delta)
            #Will need to handle this better later
            if pkmn_info is None or time_left < datetime.timedelta(0):
                #Couldn't find catchable pokemon in the table
                return redirect(url_for('myMon',msg="The wild pokemon fled!"), code=status.FOUND)
            
            delete_encounter_query=("DELETE FROM `catchable` WHERE userid=%s")
            delete_encounter_args=(uid,)
            cursor = Cursor(buffered=True)
            should_catch=request.form.get('catch', False)
            if should_catch:
                insert_catch_query=("INSERT INTO `owns` "
                "(pokemonNo, userid, level, gender, shiny, met, originalTrainerId) VALUES "
                "(%s,%s,%s,%s,%s,CURRENT_TIMESTAMP(),%s)")
                insert_catch_args=(pkmn_info['pokemonNo'],uid,pkmn_info['level'], pkmn_info['gender'], pkmn_info['shiny'],uid, )
                cursor.execute(insert_catch_query,insert_catch_args)
                catch_message="You caught a {}!".format(pkmn_info['speciesName'].title())
            else:
                catch_message="Got away safely!"
            cursor.execute(delete_encounter_query,delete_encounter_args)
            cursor.close()
            return redirect(url_for('myMon',msg=catch_message), code=status.FOUND)
        except Exception as err:
            print('catch: ', err)
            return redirect(url_for('catch',msg="The Pokemon broke free!",method="GET"), code=status.SEE_OTHER)

@app.route("/trade", methods=["POST"])
def create_trade():
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
    # Create random resource id until we find one that isn't in the table.
    l = []
    try:
        cursor = Cursor()
        cursor.execute("SELECT resourceId FROM `temp_trades` WHERE expires > CURRENT_TIMESTAMP", ())
        for row in cursor:
            l.append(row[0])
        cursor.close()
        
    except Exception as err:
        print(err)
        return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    rscID = rand11()
    while rscID in l:
        rscID = rand11()
    try:
        cursor = Cursor()
        exp = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        cursor.execute("INSERT INTO `temp_trades` (resourceId, expires) VALUES (%s,%s)", (rscID,exp))
        cursor.close()
    except Exception as err:
        print(err)
        return make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    return make_response(jsonify({'resourceID': rscID}), status.OK)

def tempfor(cursor, rscID):
    cursor.execute("SELECT * FROM `temp_trades` WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (rscID,))
    row = cursor.fetchone()
    if row == None:
        return None
    cols = tuple(d[0] for d in cursor.description)
    data = dict(zip(cols, row))
    data['resourceId'] = data['resourceId'].decode('utf-8')
    return data

@app.route("/trade/<rscID>", methods=["GET","POST"])
def trade(rscID):
    # Check DB to see if unexpired rscID exists
    s = request.headers.get("Content-Type")
    if s == "application/json;charset=UTF-8":
        return tradeDaemon(rscID)
    return tradeView(rscID)

def tradeView(rscID):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    return render_template("trade.html")

valid_stageID = re.compile(r"^$|^\d+$")

def tradeDaemon(rscID):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
    body = request.get_json()
    try:
        rtype = body['type']
    except Exception as err:
        print(err)
        return make_response(jsonify({'err': 'Invalid json'}), status.BAD_REQUEST)
    if rtype == "join":
        res = make_response(jsonify({'err': "Room doesn't exist"}), status.NOT_FOUND)
        try:
            cursor = Cursor()
            data = tempfor(cursor, rscID)
            if data:
                if data["user1Id"] == token["userid"] or data["user2Id"] == token["userid"]:
                    res = make_response(jsonify({'err': "Already joined"}), status.BAD_REQUEST)
                elif data["user1Id"] is None:
                    # update into uid1
                    cursor.execute("UPDATE `temp_trades` SET user1Id = %s WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (token["userid"],rscID))
                    res = make_response('', status.OK)
                elif data["user2Id"] is None:
                    # update into uid2
                    cursor.execute("UPDATE `temp_trades` SET user2Id = %s WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (token["userid"],rscID))
                    res = make_response('', status.OK)
                else:
                    res = make_response(jsonify({'err': "Room is full"}), status.BAD_REQUEST)
            cursor.close()
            
        except Exception as err:
            print(err)
            res = make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    elif rtype == "leave":
        res = make_response(jsonify({'err': "Room doesn't exist"}), status.NOT_FOUND)
        try:
            cursor = Cursor()
            data = tempfor(cursor, rscID)
            if data:
                if data["user1Id"] == token["userid"]:
                    cursor.execute("UPDATE `temp_trades` SET user1Id = %s, pokemon1 = %s WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (None,None,rscID))
                    res = make_response('', status.OK)
                elif data["user2Id"] == token["userid"]:
                    cursor.execute("UPDATE `temp_trades` SET user2Id = %s, pokemon2 = %s WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (None,None,rscID))
                    res = make_response('', status.OK)
                else:
                    res = make_response(jsonify({'err': "Cannot leave if not a member"}), status.BAD_REQUEST)
            cursor.close()
            
        except Exception as err:
            print(err)
            res = make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    elif rtype == "stage":
        try:
            stageID = body['stageID']
        except Exception as err:
            print(err)
            return make_response(jsonify({'err': 'Invalid json'}), status.BAD_REQUEST)
        if not valid_stageID.match(stageID):
            return make_response(jsonify({'err': 'Invalid stage ID'}), status.BAD_REQUEST)
        try:
            cursor = Cursor(buffered=True)
            # Trade is valid (exists, not expired)
            data = tempfor(cursor, rscID)
            if data is None:
                cursor.close()
                return make_response(jsonify({'err': 'Invalid resource'}), status.NOT_FOUND)
            # User is in trade, capture position
            pos = 1
            if data["user1Id"] == token["userid"]:
                pass
            elif data["user2Id"] == token["userid"]:
                pos = 2
            else:
                cursor.close()
                return make_response(jsonify({'err': 'User is not in trade'}), status.BAD_REQUEST)
            # Check that user actually owns this particular pokemon
            if stageID != "":
                cursor.execute("SELECT userId FROM owns WHERE ownsId=%s AND userId=%s", (stageID, token["userid"]))
                if cursor.rowcount == 0:
                    cursor.close()
                    return make_response(jsonify({'err': 'Pokemon does not belong to user'}), status.BAD_REQUEST)
            # Update pokemon that is staged
            if stageID == "":
                stageID = None
            cursor.execute("UPDATE `temp_trades` SET pokemon{} = %s, confirm1 = 0, confirm2 = 0 WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP".format(pos), (stageID,rscID))
            cursor.close()
            res = make_response('', status.OK)
        except Exception as err:
            print("stage", err)
            res = make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    elif rtype == "confirm":
        try:
            value = body['value']
            if type(value) != bool:
                raise Exception("bad bool")
        except Exception as err:
            print(err)
            return make_response(jsonify({'err': 'Invalid json'}), status.BAD_REQUEST)
        try:
            cursor = Cursor(buffered=True)
            
            # Trade is valid (exists, not expired)
            data = tempfor(cursor, rscID)
            if data is None:
                cursor.close()
                return make_response(jsonify({'err': 'Invalid resource'}), status.NOT_FOUND)

            # User is in trade, capture position
            pos = 1
            if data["user1Id"] == token["userid"]:
                pass
            elif data["user2Id"] == token["userid"]:
                pos = 2
            else:
                cursor.close()
                return make_response(jsonify({'err': 'User is not in trade'}), status.BAD_REQUEST)

            # Check that both users are confirmed
            data["confirm{}".format(pos)]=value
            if not data["confirm1"] or not data["confirm2"]:
                cursor.execute("UPDATE `temp_trades` SET confirm1 = %s, confirm2 = %s WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (data["confirm1"], data["confirm2"], rscID))
                cursor.close()
                return make_response('', status.OK)
            if data["pokemon1"] is not None:
                cursor.execute("SELECT userId FROM owns WHERE ownsId=%s AND userId=%s ", (data["pokemon1"], data["user1Id"]))
                if cursor.rowcount == 0:
                    data["pokemon1"] = None
                    data["confirm1"] = False
                    data["confirm2"] = False
                    res = make_response(jsonify({'err': 'Pokemon does not belong to user'}), status.BAD_REQUEST)
                    cursor.execute("UPDATE `temp_trades` SET pokemon1 = NULL, pokemon2 = NULL, confirm1 = 0, confirm2 = 0 WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (rscID,))
            
            if data["pokemon2"] is not None:
                cursor.execute("SELECT userId FROM owns WHERE ownsId=%s AND userId=%s", (data["pokemon2"], data["user2Id"]))
                if cursor.rowcount == 0:
                    data["pokemon2"] = None
                    data["confirm1"] = False
                    data["confirm2"] = False
                    res = make_response(jsonify({'err': 'Pokemon does not belong to user'}), status.BAD_REQUEST)
                    # Clear attributes in temp_trades
                    cursor.execute("UPDATE `temp_trades` SET pokemon1 = NULL, pokemon2 = NULL, confirm1 = 0, confirm2 = 0 WHERE resourceId = %s AND expires > CURRENT_TIMESTAMP", (rscID,))

            # Do the trade
            if data["confirm1"] and data["confirm2"]:
                # 1. Move to trades
                cursor.execute("INSERT INTO `trades` (user1Id, user2Id, pokemon1, pokemon2) VALUES (%s, %s, %s, %s)", (data["user1Id"], data["user2Id"], data["pokemon1"], data["pokemon2"]))
                # 2. Remove row in temp_trades
                cursor.execute("DELETE FROM `temp_trades` WHERE resourceId = %s", (rscID,))
                res = make_response('', status.OK)

            cursor.close()
        except Exception as err:
            print("confirm", err)
            res = make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    elif rtype == "tradePoll":
        try:
            cursor = Cursor()
            data = tempfor(cursor, rscID)
            if data is None:
                return make_response(jsonify({'err': 'Invalid resource'}), status.NOT_FOUND)
            data["userid"] = token["userid"]
            cursor.close()
            
            res = make_response(jsonify(data), status.OK)
        except Exception as err:
            print("tradePoll", err)
            res = make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    elif rtype == "boxPoll":
        try:
            cursor = Cursor(buffered=True)
            info = get_mon(cursor, token["userid"])
            cursor.close()
            
            res = make_response(jsonify(info), status.OK)
        except Exception as err:
            print("boxPoll", err)
            res = make_response(jsonify({'err': 'ISE'}), status.INTERNAL_SERVER_ERROR)
    return res

@app.route("/")
def root():
    token = authenticate(request.cookies.get('access_token'))
    if token is not None:
        to = url_for('catch')
        try:
            ref = request.cookies.get('referrer')
            if len(ref) != 0:
                to = ref
        except:
            pass
        return clearref(redirect(to, code=status.FOUND))
    return render_template("auth.html")

@app.route("/train/submit/<id>", methods=['POST'])
def trained(id):
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return make_response(jsonify({'err': 'Unauthorized login'}), status.UNAUTHORIZED)
    uid = token['userid']
    msg=""
    clickreq = request.get_json()
    clicks = clickreq['clicks']

    cursor = Cursor(prepared=True)
    query = ("SELECT pokemonNo, speciesName, level, gender, nickname, shiny, exp FROM `owns` NATURAL JOIN `pokemon` WHERE ownsId=%s AND userId = %s")
    tup = (id,uid)
    #Query returns either a single row or nothing if ownsId is invalid
    cursor.execute(query, tup)
    info = []
    result = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    size = len(info)
    if (size == 0):
        msg = "Train... that mon does not exist or it does not belong to you!"
        return make_response(jsonify({'err': msg}), status.BAD_REQUEST)
    item = {}
    item['pokemonNo'] = info[0]['pokemonNo']
    item['shiny'] = info[0]['shiny']
    item['speciesName'] = str(info[0]['speciesName'], 'utf-8').capitalize()
    item['exp'] = info[0]['exp'] + (clicks * 5)
    lvlinc = getlevel(info[0]['level'],item['exp'])
    item['level'] = info[0]['level'] + lvlinc
    if item['level'] >= 100:
        item['level'] = 100
    item['gender'] = info[0]['gender']
    if info[0]['nickname'] is not None:
        item['nickname'] = str(info[0]['nickname'], 'utf-8')
    item['id'] = id
    expNeeded = pow(item['level'] + 1, 3) - item['exp']
    item['expNeeded'] = expNeeded
    result.append(item)
    query = ("UPDATE `owns` SET `exp`=%s, `level`=%s WHERE `ownsId`=%s")
    #cursor.execute(query, (item['exp'],id))
    #query = ("UPDATE `owns` SET `level`=%s WHERE `ownsId`=%s")
    cursor.execute(query, (item['exp'],item['level'],id))
    if lvlinc > 0:
        if info[0]['nickname'] is not None:
            msg = item['nickname'] + " has leveled up to level " + str(item['level'])
        else:
            msg = item['speciesName'] + " has leveled up to level " + str(item['level'])
    cursor.close()
    #return render_template("/train.html", info=result, msg=msg)
    return make_response(jsonify(info=result,msg=msg), status.OK)



@app.route("/train/<id>", methods=['GET', 'POST'])
def train(id):
    msg = request.args.get('msg', None)
    token = authenticate(request.cookies.get('access_token'))
    if token is None:
        return redirback(url_for('root'))
    uid = token['userid']
    cursor = Cursor(prepared=True)
    query = ("SELECT pokemonNo, speciesName, level, gender, nickname, shiny, exp FROM `owns` NATURAL JOIN `pokemon` WHERE ownsId=%s AND userId=%s")
    tup = (id,uid)
    #Query returns either a single row or nothing if ownsId is invalid
    cursor.execute(query, tup)
    info = []
    result = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    size = len(info)
    if size==0:
        msg = "Something isn't right, this mon doesn't exist or you do not own that mon"
        return redirect(url_for('myMon',msg=msg), code=status.FOUND)
    else:
        item = {}
        item['pokemonNo'] = info[0]['pokemonNo']
        item['speciesName'] = str(info[0]['speciesName'], 'utf-8').capitalize()
        item['level'] = info[0]['level']
        item['gender'] = info[0]['gender']
        item['shiny'] = info[0]['shiny']
        if info[0]['nickname'] is not None:
            item['nickname'] = str(info[0]['nickname'], 'utf-8')
        item['exp'] = info[0]['exp']
        item['id'] = id

        expNeeded = pow(info[0]['level'] + 1, 3) - info[0]['exp']
        item['expNeeded'] = expNeeded

        result.append(item)
    cursor.close()
    return render_template("/train.html", info=result, msg=msg)

def getlevel(lvl,exp):
    gain=0
    count=1
    if pow((lvl+count),3) < exp:
        gain = 1
        count+=1
        while pow(lvl+count, 3) < exp:
            gain+=1
            count+=1
    return gain