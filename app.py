import os
from flask import Flask, render_template, redirect, url_for, request
import mysql.connector as db
import logging
import numpy
import datetime

# Store application's state in this dictionary
stay = {}

def env(s):
    v = os.environ.get(s)
    if not v:
        raise ValueError(s+" not set")
    return v


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

def get_userid():
    token = authenticate(request.cookies.get('access_token'))
    return token.get('userid',None)

@app.route("/")
def root():
    return render_template("index.html")


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



@app.route("/dex/<id>")
def dex_view(id):
    cursor = stay["conn"].cursor(prepared=True)
    # at most one match
    query = ("SELECT speciesName FROM `pokemon` "
            "Where pokemonNo=%s")
    tup = (id,)
    cursor.execute(query, tup)
    info = []
    columns = tuple( [d[0] for d in cursor.description] )
    for row in cursor:
        info.append(dict(zip(columns, row)))
    for item in info:
        item['speciesName'] = str(item['speciesName'],'utf-8')
    size = len(info)
    if size==0:
        msg = "That mon species does not exist"
    if size !=0:
        msg = "You are viewing the dex entry for mon number " + str(id) + " which is " +info[0]['speciesName']
    cursor.close()
    return msg

@app.route("/catch",methods=['GET','POST'])
def catch_pokemon():
    uid=get_userid()
    if uid is None:
        return redirect(url_for('/',), code=302)
    shiny_rate=1/8192
    last_catch_delta = datetime.timedelta(minutes=1)
    '''
    update_catch_query=("Update `Trainer` SET lastCatch=%s WHERE userid=%s")
    update_catch_args=(datetime.datetime.now()-last_catch_delta,uid,)
    cursor = stay["conn"].cursor(buffered=True)
    cursor.execute(update_catch_query,update_catch_args)
    cursor.close()
    stay['conn'].commit()
    '''
    def get_chance_weight(pokeNo):
        return 1
    def get_shiny_chance():
        return int(numpy.random.ranf()<shiny_rate)
    def get_gender_chance(pokeNo):
        return numpy.rint(numpy.random.ranf()*2)
    if request.method=="GET":
        msg = request.args.get('msg', None)
        # Should first check if available to catch
        #For now just use userid=1
        last_catch_query=("SELECT lastCatch FROM `Trainer` where userid=%s")
        last_catch_args=(uid,)
        cursor = stay["conn"].cursor(buffered=True)
        cursor.execute(last_catch_query,last_catch_args)
        columns = tuple( [d[0] for d in cursor.description] )
        for x in cursor:
            last_catch_dict=dict(zip(columns, x))
            print(datetime.datetime.now().date())
        cursor.close()
        # tmp until lastCatch changes to datetime
        # last_catch_time = datetime.datetime.combine(last_catch_dict.get('lastCatch'), datetime.datetime.min.time())
        last_catch_time=last_catch_dict.get('lastCatch')
        time_left=last_catch_time+last_catch_delta-datetime.datetime.now()
        if time_left>datetime.timedelta(0):
            return render_template("/catch.html", msg=msg, can_catch=False, wait_time=str(time_left))

        # Now find new rand pokemon
        msg = request.args.get('msg', None)
        cursor = stay["conn"].cursor(buffered=True)
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
        pkmn_shiny=get_shiny_chance()
        pkmn_gender=get_gender_chance(pkmn_id)
        #print(vals)
        #Need to pass pkmn id
        # Wait until datetime instead of date
        # Need to update catch time
        update_catch_query=("Update `Trainer` SET lastCatch=%s WHERE userid=%s")
        update_catch_args=(datetime.datetime.now(),uid,)
        cursor = stay["conn"].cursor(buffered=True)
        cursor.execute(update_catch_query,update_catch_args)
        cursor.close()
        stay['conn'].commit()
        #    Maybe include temporary reset button/route?
        return render_template("/catch.html", msg=msg, can_catch=True,mon_name=pkmn_name,mon_id=pkmn_id,is_shiny=pkmn_shiny,pkmn_gender=pkmn_gender)
    # Handle POST (caught pokemon)
    else:
        dft_level=1
        dft_gender=1
        dft_shiny=0
        pkmn_id=request.form.get('pkmn_id',None)
        pkmn_shiny=request.form.get('pkmn_shiny',dft_shiny)
        pkmn_gender=request.form.get('pkmn_gender',dft_gender)
        if pkmn_id is None:
            return
        insert_catch_query=("INSERT INTO `owns` "
        "(pokemonNo, userid, level, gender, shiny, met, originalTrainerId) VALUES "
        "(%s,%s,%s,%s,%s,%s,%s)")
        insert_catch_args=(pkmn_id,uid,dft_level, pkmn_gender, pkmn_shiny,datetime.datetime.now(),uid, )
        cursor = stay["conn"].cursor(buffered=True)
        cursor.execute(insert_catch_query,insert_catch_args)
        cursor.close()
        stay['conn'].commit()

        return redirect(url_for('myMon',msg=None), code=302)