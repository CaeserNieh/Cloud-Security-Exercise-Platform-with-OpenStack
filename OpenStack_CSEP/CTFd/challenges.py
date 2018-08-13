from flask import current_app as app, render_template, request, redirect, abort, jsonify, json as json_mod, url_for, session, Blueprint

from CTFd.utils import ctftime, view_after_ctf, authed, unix_time, get_kpm, can_view_challenges, is_admin, get_config
from CTFd.models import db, Challenges, Files, Solves, WrongKeys, Keys

import time
import re
import logging
import json
import paramiko as parami

from keystoneauth1.identity import v3
from keystoneauth1 import session as keystone_sess
from novaclient.client import Client

challenges = Blueprint('challenges', __name__)

global start_experiment


def get_session():
	auth = v3.Password(
		auth_url = 'http://10.52.52.185:5000/v3',
		username = 'demo',
		password = '12345',
		project_name = 'demo',
		user_domain_name = 'default',
		project_domain_name='default',
	)
	return keystone_sess.Session(auth = auth , verify=False)


@challenges.route('/Iptables')
def ip_table_provide():
	sess = get_session()
	nova = Client("2.1",session = sess,insecure=True)
	ff = nova.floating_ips.list()
	ret = []
	for i in ff:
		if i.instance_id == None:
			name = "None"
		else :
			name = nova.servers.find(id = i.instance_id).name
		quo = {"address" : i.ip , "instance" : name , "internal":i.fixed_ip}
		ret.append(quo)
	return render_template('iptable.html',vm_data = ret)

@challenges.route('/challenges', methods=['GET'])
def challenges_view():
    if not is_admin():
        if not ctftime():
            if view_after_ctf():
                pass
            else:
                return redirect('/')
    if can_view_challenges():
        return render_template('chals.html', ctftime=ctftime())
    else:
        return redirect('/login')

@challenges.route('/test')
def challenges_hello():
	chals = Challenges.query.add_columns('id', 'name', 'value', 'description', 'category').order_by(Challenges.value).all()
	chal_name = request.args.get('name')
	chal_filter = Challenges.query.add_columns('id', 'name', 'value', 'description', 'category').filter_by(id=chal_name).all()[0]
	ff =[ str(i.location) for i in Files.query.filter_by(chal=chal_name).all()]
	print(ff)
	start_experiment = True
	json_test = []
	json_test.append({'id':chal_filter[1],'name':chal_filter[2] ,'value': chal_filter[3],'description':chal_filter[4],'category':chal_filter[5],'files':ff})
	return render_template('test.html',file_test = start_experiment)

@challenges.route('/experiment_start',methods=['GET'])
def challenges_experiment():
        ssh = parami.SSHClient()
        host = "10.52.52.33"
        username = "ubuntu"
        passwd = "ubuntu"
        ssh.set_missing_host_key_policy(parami.AutoAddPolicy())
        ssh.connect(host,22,username,passwd,allow_agent=False,look_for_keys=False)
        stdin,stdout,stderr = ssh.exec_command('./test.sh')
        json = {'game':[]}
        json['game'].append({'data': False})
        return jsonify(json)


@challenges.route('/ttt',methods=['GET'])
def ttt():
        print("TTTTTTT")
        chals = Challenges.query.add_columns('id', 'name', 'value', 'description', 'category').order_by(Challenges.value).all()

        json = {'game':[]}
        for x in chals:
            files = [ str(f.location) for f in Files.query.filter_by(chal=x.id).all() ]
            json['game'].append({'id':x[1], 'name':x[2], 'value':x[3], 'description':x[4], 'category':x[5], 'files':files})

        db.session.close()
        return jsonify(json)


@challenges.route('/chals', methods=['GET'])
def chals():
    if not is_admin():
        if not ctftime():
            if view_after_ctf():
                pass
            else:
                return redirect('/')
    if can_view_challenges():
        chals = Challenges.query.add_columns('id', 'name', 'value', 'description', 'category').order_by(Challenges.value).all()

        json = {'game':[]}
        for x in chals:
            files = [ str(f.location) for f in Files.query.filter_by(chal=x.id).all() ]
            json['game'].append({'id':x[1], 'name':x[2], 'value':x[3], 'description':x[4], 'category':x[5], 'files':files})

        db.session.close()
        return jsonify(json)
    else:
        db.session.close()
        return redirect('/login')


@challenges.route('/chals/solves')
def chals_per_solves():
    if can_view_challenges():
        solves = Solves.query.add_columns(db.func.count(Solves.chalid)).group_by(Solves.chalid).all()
        json = {}
        for chal, count in solves:
            json[chal.chal.name] = count
        return jsonify(json)
    return redirect('/login')


@challenges.route('/solves')
@challenges.route('/solves/<teamid>')
def solves(teamid=None):
    if teamid is None:
        if authed():
            solves = Solves.query.filter_by(teamid=session['id']).all()
        else:
            abort(401)
    else:
        solves = Solves.query.filter_by(teamid=teamid).all()
    db.session.close()
    json = {'solves':[]}
    for x in solves:
        json['solves'].append({ 'chal':x.chal.name, 'chalid':x.chalid,'team':x.teamid, 'value': x.chal.value, 'category':x.chal.category, 'time':unix_time(x.date)})
    return jsonify(json)


@challenges.route('/maxattempts')
def attempts():
    chals = Challenges.query.add_columns('id').all()
    json = {'maxattempts':[]}
    for chal, chalid in chals:
        fails = WrongKeys.query.filter_by(team=session['id'], chalid=chalid).count()
        if fails >= int(get_config("max_tries")) and int(get_config("max_tries")) > 0:
            json['maxattempts'].append({'chalid':chalid})
    return jsonify(json)


@challenges.route('/fails/<teamid>', methods=['GET'])
def fails(teamid):
    fails = WrongKeys.query.filter_by(team=teamid).count()
    solves = Solves.query.filter_by(teamid=teamid).count()
    db.session.close()
    json = {'fails':str(fails), 'solves': str(solves)}
    return jsonify(json)


@challenges.route('/chal/<chalid>/solves', methods=['GET'])
def who_solved(chalid):
    solves = Solves.query.filter_by(chalid=chalid).order_by(Solves.date.asc())
    json = {'teams':[]}
    for solve in solves:
        json['teams'].append({'id':solve.team.id, 'name':solve.team.name, 'date':solve.date})
    return jsonify(json)


@challenges.route('/chal/<chalid>', methods=['POST'])
def chal(chalid):
    if not ctftime():
        return redirect('/challenges')
    if authed():
        fails = WrongKeys.query.filter_by(team=session['id'], chalid=chalid).count()
        logger = logging.getLogger('keys')
        data = (time.strftime("%m/%d/%Y %X"), session['username'].encode('utf-8'), request.form['key'].encode('utf-8'), get_kpm(session['id']))
        print("[{0}] {1} submitted {2} with kpm {3}".format(*data))

        # Hit max attempts
        if fails >= int(get_config("max_tries")) and int(get_config("max_tries")) > 0:
            return "4" #too many tries on this challenge

        # Anti-bruteforce / submitting keys too quickly
        if get_kpm(session['id']) > 10:
            wrong = WrongKeys(session['id'], chalid, request.form['key'])
            db.session.add(wrong)
            db.session.commit()
            db.session.close()
            logger.warn("[{0}] {1} submitted {2} with kpm {3} [TOO FAST]".format(*data))
            return "3" # Submitting too fast

        solves = Solves.query.filter_by(teamid=session['id'], chalid=chalid).first()

        # Challange not solved yet
        if not solves:
            chal = Challenges.query.filter_by(id=chalid).first()
            key = str(request.form['key'].strip().lower())
            keys = json.loads(chal.flags)
            for x in keys:
                if x['type'] == 0: #static key
                    print(x['flag'], key.strip().lower())
                    if x['flag'] == key.strip().lower():
                        solve = Solves(chalid=chalid, teamid=session['id'], ip=request.remote_addr, flag=key)
                        db.session.add(solve)
                        db.session.commit()
                        db.session.close()
                        logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                        return "1" # key was correct
                elif x['type'] == 1: #regex
                    res = re.match(str(x['flag']), key, re.IGNORECASE)
                    if res and res.group() == key:
                        solve = Solves(chalid=chalid, teamid=session['id'], ip=request.remote_addr, flag=key)
                        db.session.add(solve)
                        db.session.commit()
                        db.session.close()
                        logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                        return "1" # key was correct

            wrong = WrongKeys(session['id'], chalid, request.form['key'])
            db.session.add(wrong)
            db.session.commit()
            db.session.close()
            logger.info("[{0}] {1} submitted {2} with kpm {3} [WRONG]".format(*data))
            return '0' # key was wrong

        # Challenge already solved
        else:
            logger.info("{0} submitted {1} with kpm {2} [ALREADY SOLVED]".format(*data))
            return "2" # challenge was already solved
    else:
        return "-1"
