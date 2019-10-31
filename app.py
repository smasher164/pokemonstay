import os
from flask import Flask, render_template, redirect, url_for, request
import mysql.connector as db
import logging

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
    return render_template("/dexMain.html", info=result)

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
