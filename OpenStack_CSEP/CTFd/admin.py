from flask import render_template, request, redirect, abort, jsonify, url_for, session, Blueprint
from CTFd.utils import sha512, is_safe_url, authed, admins_only, is_admin, unix_time, unix_time_millis, get_config, set_config, sendmail, rmdir
from CTFd.models import db, Teams, Solves, Challenges, WrongKeys, Keys, Tags, Files, Tracking, Pages, Config
from itsdangerous import TimedSerializer, BadTimeSignature
from werkzeug.utils import secure_filename
from socket import inet_aton, inet_ntoa
from passlib.hash import bcrypt_sha256
from flask import current_app as app

import logging
import hashlib
import time
import re
import os
import json

from subprocess import Popen, PIPE
from keystoneauth1.identity import v3
from keystoneauth1 import session as keystone_sess
from novaclient.client import Client
import paramiko as param
from threading import Thread
from neutronclient.v2_0 import client as neutron_client


admin = Blueprint('admin', __name__)


sess = ""

@admin.route('/admin', methods=['GET', 'POST'])
def admin_view():
    if request.method == 'POST':
        username = request.form.get('name')
        password = request.form.get('password')

        admin_user= Teams.query.filter_by(name=request.form['name'], admin=True).first()
        if admin_user and bcrypt_sha256.verify(request.form['password'], admin_user.password):
            try:
                session.regenerate() # NO SESSION FIXATION FOR YOU
            except:
                pass # TODO: Some session objects dont implement regenerate :(
            session['username'] = admin_user.name
            session['id'] = admin_user.id
            session['admin'] = True
            session['nonce'] = sha512(os.urandom(10))
            db.session.close()
            return redirect('/admin/graphs')

    if is_admin():
        return redirect('/admin/graphs')

    return render_template('admin/login.html')


@admin.route('/admin/graphs')
@admins_only
def admin_graphs():
    return render_template('admin/graphs.html')


@admin.route('/admin/config', methods=['GET', 'POST'])
@admins_only
def admin_config():
    if request.method == "POST":
        try:
            start = int(request.form['start'])
            end = int(request.form['end'])
        except (ValueError, TypeError):
            start = None
            end = None

        try:
            view_challenges_unregistered = bool(request.form.get('view_challenges_unregistered', None))
            prevent_registration = bool(request.form.get('prevent_registration', None))
            prevent_name_change = bool(request.form.get('prevent_name_change', None))
            view_after_ctf = bool(request.form.get('view_after_ctf', None))
        except (ValueError, TypeError):
            view_challenges_unregistered = None
            prevent_registration = None
            prevent_name_change = None
            view_after_ctf = None
        finally:
            view_challenges_unregistered = set_config('view_challenges_unregistered', view_challenges_unregistered)
            prevent_registration = set_config('prevent_registration', prevent_registration)
            prevent_name_change = set_config('prevent_name_change', prevent_name_change)
            view_after_ctf = set_config('view_after_ctf', view_after_ctf)

        ctf_name = set_config("ctf_name", request.form.get('ctf_name', None))
        mg_api_key = set_config("mg_api_key", request.form.get('mg_api_key', None))
        max_tries = set_config("max_tries", request.form.get('max_tries', None))


        db_start = Config.query.filter_by(key='start').first()
        db_start.value = start

        db_end = Config.query.filter_by(key='end').first()
        db_end.value = end

        db.session.add(db_start)
        db.session.add(db_end)

        db.session.commit()
        return redirect('/admin/config')

    ctf_name = get_config('ctf_name')
    if not ctf_name:
        set_config('ctf_name', None)

    mg_api_key = get_config('mg_api_key')
    if not mg_api_key:
        set_config('mg_api_key', None)

    max_tries = get_config('max_tries')
    if not max_tries:
        set_config('max_tries', 0)
        max_tries = 0

    view_after_ctf = get_config('view_after_ctf') == '1'
    if not view_after_ctf:
        set_config('view_after_ctf', 0)
        view_after_ctf = 0

    start = get_config('start')
    if not start:
        set_config('start', None)

    end = get_config('end')
    if not end:
        set_config('end', None)

    view_challenges_unregistered = get_config('view_challenges_unregistered') == '1'
    if not view_challenges_unregistered:
        set_config('view_challenges_unregistered', None)

    prevent_registration = get_config('prevent_registration') == '1'
    if not prevent_registration:
        set_config('prevent_registration', None)

    prevent_name_change = get_config('prevent_name_change') == '1'
    if not prevent_name_change:
        set_config('prevent_name_change', None)

    db.session.commit()
    db.session.close()

    return render_template('admin/config.html', ctf_name=ctf_name, start=start, end=end,
                           max_tries=max_tries,
                           view_challenges_unregistered=view_challenges_unregistered,
                           prevent_registration=prevent_registration, mg_api_key=mg_api_key,
                           prevent_name_change=prevent_name_change,
                           view_after_ctf=view_after_ctf)


@admin.route('/admin/css', methods=['GET', 'POST'])
@admins_only
def admin_css():
    if request.method == 'POST':
        css = request.form['css']
        css = set_config('css', css)
        return "1"
    return "0"

@admin.route('/admin/pages', defaults={'route': None}, methods=['GET', 'POST'])
@admin.route('/admin/pages/<route>', methods=['GET', 'POST'])
@admins_only
def admin_pages(route):
    if request.method == 'GET' and request.args.get('mode') == 'create':
        return render_template('admin/editor.html')
    if route and request.method == 'GET':
        page = Pages.query.filter_by(route=route).first()
        return render_template('admin/editor.html', page=page)
    if route and request.method == 'POST':
        page = Pages.query.filter_by(route=route).first()
        errors = []
        html = request.form['html']
        route = request.form['route']
        if not route:
            errors.append('Missing URL route')
        if errors:
            page = Pages(html, "")
            return render_template('/admin/editor.html', page=page)
        if page:
            page.route = route
            page.html = html
            db.session.commit()
            return redirect('/admin/pages')
        page = Pages(route, html)
        db.session.add(page)
        db.session.commit()
        return redirect('/admin/pages')
    pages = Pages.query.all()
    return render_template('admin/pages.html', routes=pages, css=get_config('css'))


@admin.route('/admin/page/<pageroute>/delete', methods=['POST'])
@admins_only
def delete_page(pageroute):
    page = Pages.query.filter_by(route=pageroute).first()
    db.session.delete(page)
    db.session.commit()
    return '1'


@admin.route('/admin/chals', methods=['POST', 'GET'])
@admins_only
def admin_chals():
    if request.method == 'POST':
        chals = Challenges.query.add_columns('id', 'name', 'value', 'description', 'category').order_by(Challenges.value).all()
        
        json_data = {'game':[]}
        for x in chals:
            json_data['game'].append({'id':x[1], 'name':x[2], 'value':x[3], 'description':x[4], 'category':x[5]})

        db.session.close()
        return jsonify(json_data)
    else:
        return render_template('admin/chals.html')


@admin.route('/admin/detail_server', methods=['POST', 'GET'])
@admins_only
def detail_server():
	print("Detail server----")
	global sess
	nova = Client("2.1",session = sess,insecure=True)
	
	image_list = nova.images.list()
	flavor_list = nova.flavors.list()
	net_list = nova.networks.list()
	
	ret_image = []
	ret_flavor = []
	ret_net = []

	for image in image_list : 
		quo = {"name":image.name,"uuid":image.id,"minDisk":image.minDisk}
		ret_image.append(quo)

	for flavor in flavor_list : 
		quo = {"name":flavor.name,"vcpu":flavor.vcpus ,"RAM":flavor.ram ,"Disk" :flavor.disk }
		ret_flavor.append(quo)

	for net in net_list :
		quo = {"name" : net.label,"id":net.id}
		ret_net.append(quo)

	return render_template('admin/create.html',ret_image = ret_image, ret_flavor = ret_flavor, ret_net = ret_net )

def create_selfservice_network(neutron,name):
	print("---------- create self network---------")
	#create network
	body_data = {
		"network":{
			'name' : name,
			'admin_state_up' : 'True',
		}
	}
	network_new = neutron.create_network(body = body_data)
	net_dict = network_new['network']
	network_id = net_dict['id']
	print(network_id)

	return network_new

def create_selfservice_subnet(neutron,network_new,start_ip,end_ip,gateway,name):
	print("-------- create selfservice subnet ----------")
	net_dict = network_new['network']
	network_id = net_dict['id']
	
	#allocation pool
	start = start_ip
	end = end_ip
	gateway_ip = gateway
	cidr = gateway[:-1]+"0/24" 
	allocation_pools = {'start':start,'end' : end}
	
	body_data = {
		"subnet":{
			'name' : name,
			'network_id' : network_id,
			'cidr' : cidr,
			'ip_version' : 4,
			'enable_dhcp' : True,
			'allocation_pools' : [allocation_pools],
			'gateway_ip' : gateway_ip,
		}
	}

	ret = neutron.create_subnet(body=body_data)['subnet']['id']
	return ret

def create_router(neutron,subnet_id,name):
	name = name+"-router"
	request = {
		"router" :{
		'name' : name,
		'admin_state_up' : 'True',
	}}
	provider_id = '89a46a9c-a99a-441d-b4c2-67c7ef7a84f4'
	router_new = neutron.create_router(request)
	router_id = router_new['router']['id']
	print(router_id)

	router_interface_subnet = {'subnet_id' :subnet_id }
	interface_add = neutron.add_interface_router(router_id,router_interface_subnet)

	router_interface_provider = {'network_id' : provider_id}
	neutron.add_gateway_router(router_id,router_interface_provider)

def server_on_net(name):
	global sess
	user = "ubuntu"
	passwd = "ubuntu"
	nova = Client("2.1",session = sess,insecure=True)
	net = nova.neutron.find_network(name)
	img = nova.images.find(name = "m1.ubuntu")
	flav = nova.flavors.find(name = "ubuntu16_04")
	nics = [{'net-id':net.id}]
	count = 2
	user_data = "#cloud-config \npassword: ubuntu \nchpasswd: { expire: False } \nssh_pwauth: True"
	detail = nova.servers.create(name,img,flav,min_count = count,nics = nics,userdata = user_data)


def ssh(user,ip,cmd,key = None):
	# SSH_ARGS="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
	ssh_cmd = ['ssh', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no']
	if key:
		ssh_cmd = ssh_cmd + ['-i',key]
	ssh_cmd.append('%s@%s' % (user, ip))
	ssh_cmd = ssh_cmd + cmd
	process = Popen(ssh_cmd, stdout=PIPE, stderr=PIPE)
	return process

def scp(user,ip,cmd,filename,key=None):
	scp_cmd = ['scp', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no']
	if key :
		scp_cmd = scp_cmd + ['-i', key]
	scp_cmd.append(filename)
	scp_cmd.append('%s@%s:./' % (user, ip))
	print(scp_cmd)
	process = Popen(scp_cmd, stdout=PIPE, stderr=PIPE)
	return process

def wait_for_instance(user,ip,filename,key=None):
	count = 0
	while True:
		print("wait to scp")
		process = scp(user,ip,['true'],filename)
		count = count+1
		if process.wait() == 0:
			break
	print(count)

def wait_for_dhcp_ip(nova,detail):
	while True :
		time.sleep(10)
		print("Wait 10 sec")
		server = nova.servers.find(name=detail.human_id)
		if server.networks:
			break
	return server


@admin.route('/admin/create_network',methods=['POST'])
@admins_only
def create_selfnetwork():
	print("--------create network-----")
	neutron = neutron_client.Client(session = sess)
	name = request.form['name']
	start_ip = request.form['start']
	end_ip = request.form['end']
	gateway = request.form['gateway']
	#create network
	new_network = create_selfservice_network(neutron,name)
	print(new_network['network'])
	#create subnetwork
	ret = create_selfservice_subnet(neutron,new_network,start_ip,end_ip,gateway,name)
	print(ret)
	#create router
	create_router(neutron,ret,name)

	return redirect('/admin/detail_server')

@admin.route('/admin/create_server',methods=['POST'])
@admins_only
def create_server():
	print("Create Server")
	name = request.form['name']
	image = request.form['image']
	count = request.form['count']
	flavor = request.form['flavor']
	network = request.form['network']
	files = request.files.getlist('files[]')
	print(len(files))
	if not os.path.exists(os.path.join(os.path.normpath(app.static_folder), 'upload'+name)):
		os.makedirs(os.path.join(os.path.normpath(app.static_folder), 'upload'+name))
	print(os.path.join(os.path.normpath(app.static_folder), 'upload'+name))
	for f in files:
		print(f.filename)
		f.save(os.path.join(os.path.normpath(app.static_folder), 'upload'+name, f.filename))
	
	print("--------------------------------")
	global sess
	user = "ubuntu"
	passwd = "ubuntu"
	#sftp.put(os.path.join(os.path.normpath(app.static_folder), 'upload_anoth', files[0].filename),'pythonfile')
	nova = Client("2.1",session = sess,insecure=True)
	net = nova.neutron.find_network(network)
	img = nova.images.find(name = image)
	flav = nova.flavors.find(name = flavor)
	nics = [{'net-id':net.id}]
	keyname = 'keyp'
	user_data = "#cloud-config \npassword: ubuntu \nchpasswd: { expire: False } \nssh_pwauth: True"
	detail = nova.servers.create(name,img,flav,key_name=keyname,min_count = count,nics = nics,userdata = user_data)	
	
	server = wait_for_dhcp_ip(nova,detail)
	ip = str(server.networks.values()[0][0])
	print("there is ip address %s"%ip)

	wait_for_instance("ubuntu",ip,"LICENSE")
	for i in files:
		scp("ubuntu",ip,['true'],os.path.join(os.path.normpath(app.static_folder), 'upload'+name, i.filename))
	
	print("Start Experiment")
	#start_experiment(user,passwd,ip)
	start_exp = param.SSHClient()
	start_exp.set_missing_host_key_policy(param.AutoAddPolicy())
	start_exp.connect(ip,22,user,passwd,allow_agent=False,look_for_keys=False)
	#stdin,stdout,stderr = start_exp.exec_command('chmod +x baby_bof')
	#stdin,stdout,stderr = start_exp.exec_command('chmod +x nc_shell.sh')
	stdin,stdout,stderr = start_exp.exec_command('sudo apt install -y nmap')
	while True:
		if stdout.read():
			print("Done")
			break
	stdin,stdout,stderr = start_exp.exec_command('chmod +x nc_shell.sh')
	print("chmod")
	time.sleep(5)
	stdin,stdout,stderr = start_exp.exec_command('chmod +x baby_bof')
	print("chmod")
	time.sleep(5)
	stdin,stdout,stderr = start_exp.exec_command('./nc_shell.sh')

	#ssh = param.SSHClient()
	#ssh.set_missing_host_key_policy(param.AutoAddPolicy())
	#ssh.connect(ip,22,user,passwd,allow_agent=False,look_for_keys=False)
	#sftp = param.SFTPClient.from_transport(ssh.get_transport())
	#sftp = ssh.open_sftp()
	print("Finish")

	return redirect('/admin/detail_server')


def start_experiment(user,passwd,ip):
	start_exp = param.SSHClient()
	start_exp.set_missing_host_key_policy(param.AutoAddPolicy())
	start_exp.connect(ip,22,user,passwd,allow_agent=False,look_for_keys=False)
	stdin,stdout,stderr = start_exp.exec_command('sudo apt install -y nmap')
	while True:
		if stdout.read():
			print("Done")
			break
	stdin,stdout,stderr = start_exp.exec_command('chmod +x baby_bof')
	stdin,stdout,stderr = start_exp.exec_command('chmod +x nc_shell.sh')
	#stdin,stdout,stderr = start_exp.exec_command('./nc_shell.sh')


def get_session():
	auth = v3.Password(
		auth_url = 'http://10.52.52.185:5000/v3',
		username = 'demo',
		password = '12345',
		project_name = 'demo',
		user_domain_name = 'default',
		project_domain_name='default',
	)
	return keystone_sess.Session(auth = auth,verify=False)

def vm_list(nova):
	servers = nova.servers.list()
	if not servers : 
		return 0
	else : 
		return servers

def vm_details(servers):
	ret = []
	for instance in servers:
		quo = {"name":instance.name,"uuid":instance.id,"status":instance.status,"network":instance.networks.keys()[0],"IP":str(instance.networks.values()[0][0])}
		ret.append(quo)
	
	return ret



@admin.route('/admin/servers', methods=['GET'])
@admins_only
def admin_servers():
	#print admin_servers
	print("admin _servers")
	global sess
	sess = get_session()
	nova = Client("2.1",session = sess,insecure=True)

	# instance_list
	instance_list = vm_list(nova)
	#print instance list
	print(instance_list)
	
	if instance_list == 0:
		return render_template('admin/servers.html',vm_data = 0)
	else :
		vm_data = vm_details(instance_list)
		return render_template('admin/servers.html',vm_data = vm_data)


@admin.route('/admin/keys/<chalid>', methods=['POST', 'GET'])
@admins_only
def admin_keys(chalid):
    if request.method == 'GET':
        chal = Challenges.query.filter_by(id=chalid).first_or_404()
        json_data = {'keys':[]}
        flags = json.loads(chal.flags)
        for i, x in enumerate(flags):
            json_data['keys'].append({'id':i, 'key':x['flag'], 'type':x['type']})
        return jsonify(json_data)
    elif request.method == 'POST':
        chal = Challenges.query.filter_by(id=chalid).first()

        newkeys = request.form.getlist('keys[]')
        newvals = request.form.getlist('vals[]')
        print(list(zip(newkeys, newvals)))
        flags = []
        for flag, val in zip(newkeys, newvals):
            flag_dict = {'flag':flag, 'type':int(val)}
            flags.append(flag_dict)
        json_data = json.dumps(flags)
       
        chal.flags = json_data

        db.session.commit()
        db.session.close()
        return '1'


@admin.route('/admin/tags/<chalid>', methods=['GET', 'POST'])
@admins_only
def admin_tags(chalid):
    if request.method == 'GET':
        tags = Tags.query.filter_by(chal=chalid).all()
        json_data = {'tags':[]}
        for x in tags:
             json_data['tags'].append({'id':x.id, 'chal':x.chal, 'tag':x.tag})
        return jsonify(json_data)

    elif request.method == 'POST':
        newtags = request.form.getlist('tags[]')
        for x in newtags:
            tag = Tags(chalid, x)
            db.session.add(tag)
        db.session.commit()
        db.session.close()
        return '1'


@admin.route('/admin/tags/<tagid>/delete', methods=['POST'])
@admins_only
def admin_delete_tags(tagid):
    if request.method == 'POST':
        tag = Tags.query.filter_by(id=tagid).first_or_404()
        db.session.delete(tag)
        db.session.commit()
        db.session.close()
        return "1"


@admin.route('/admin/files/<chalid>', methods=['GET', 'POST'])
@admins_only
def admin_files(chalid):
    if request.method == 'GET':
        files = Files.query.filter_by(chal=chalid).all()
        json_data = {'files':[]}
        for x in files:
            json_data['files'].append({'id':x.id, 'file':x.location})
        return jsonify(json_data)
    if request.method == 'POST':
        if request.form['method'] == "delete":
            f = Files.query.filter_by(id=request.form['file']).first_or_404()
            if os.path.exists(os.path.join(app.static_folder, 'uploads', f.location)): ## Some kind of os.path.isfile issue on Windows...
                os.unlink(os.path.join(app.static_folder, 'uploads', f.location))
            db.session.delete(f)
            db.session.commit()
            db.session.close()
            return "1"
        elif request.form['method'] == "upload":
            files = request.files.getlist('files[]')

            for f in files:
                filename = secure_filename(f.filename)

                if len(filename) <= 0:
                    continue
                
                md5hash = hashlib.md5(os.urandom(64)).hexdigest()

                if not os.path.exists(os.path.join(os.path.normpath(app.static_folder), 'uploads', md5hash)):
                    os.makedirs(os.path.join(os.path.normpath(app.static_folder), 'uploads', md5hash))

                f.save(os.path.join(os.path.normpath(app.static_folder), 'uploads', md5hash, filename))
                db_f = Files(chalid, os.path.join('static', 'uploads', md5hash, filename))
                db.session.add(db_f)

            db.session.commit()
            db.session.close()
            return redirect('/admin/chals')


@admin.route('/admin/teams', defaults={'page':'1'})
@admin.route('/admin/teams/<page>')
@admins_only
def admin_teams(page):
    page = abs(int(page))
    results_per_page = 50
    page_start = results_per_page * ( page - 1 )
    page_end = results_per_page * ( page - 1 ) + results_per_page

    teams = Teams.query.slice(page_start, page_end).all()
    count = db.session.query(db.func.count(Teams.id)).first()[0]
    print(count)
    pages = int(count / results_per_page) + (count % results_per_page > 0)
    return render_template('admin/teams.html', teams=teams, pages=pages)


@admin.route('/admin/team/<teamid>', methods=['GET', 'POST'])
@admins_only
def admin_team(teamid):
    user = Teams.query.filter_by(id=teamid).first()
    solves = Solves.query.filter_by(teamid=teamid).all()
    addrs = Tracking.query.filter_by(team=teamid).order_by(Tracking.date.desc()).group_by(Tracking.ip).all()
    wrong_keys = WrongKeys.query.filter_by(team=teamid).order_by(WrongKeys.date.desc()).all()
    score = user.score()
    place = user.place()

    if request.method == 'GET':
        return render_template('admin/team.html', solves=solves, team=user, addrs=addrs, score=score, place=place, wrong_keys=wrong_keys)
    elif request.method == 'POST':
        admin_user = request.form.get('admin', "false")
        admin_user = 1 if admin_user == "true" else 0
        if admin:
            user.admin = 1
            user.banned = 1
            db.session.commit()
            return jsonify({'data': ['success']})

        name = request.form.get('name', None)
        password = request.form.get('password', None)
        email = request.form.get('email', None)
        website = request.form.get('website', None)
        affiliation = request.form.get('affiliation', None)
        country = request.form.get('country', None)

        errors = []

        name_used = Teams.query.filter(Teams.name == name).first()
        if name_used and int(name_used.id) != int(teamid):
            errors.append('That name is taken')

        email_used = Teams.query.filter(Teams.email == email).first()
        if email_used and int(email_used.id) != int(teamid):
            errors.append('That email is taken')

        if errors:
            db.session.close()
            return jsonify({'data':errors})
        else:
            user.name = name
            user.email = email
            if password:
                user.password = bcrypt_sha256.encrypt(password)
            user.website = website
            user.affiliation = affiliation
            user.country = country
            db.session.commit()
            db.session.close()
            return jsonify({'data':['success']})


@admin.route('/admin/team/<teamid>/mail', methods=['POST'])
@admins_only
def email_user(teamid):
    message = request.form.get('msg', None)
    team = Teams.query.filter(Teams.id == teamid).first()
    if message and team:
        if sendmail(team.email, message):
            return "1"
    return "0"


@admin.route('/admin/team/<teamid>/ban', methods=['POST'])
@admins_only
def ban(teamid):
    user = Teams.query.filter_by(id=teamid).first()
    user.banned = 1
    db.session.commit()
    return redirect('/admin/scoreboard')


@admin.route('/admin/team/<teamid>/unban', methods=['POST'])
@admins_only
def unban(teamid):
    user = Teams.query.filter_by(id=teamid).first()
    user.banned = None
    db.session.commit()
    return redirect('/admin/scoreboard')


@admin.route('/admin/team/<teamid>/delete', methods=['POST'])
@admins_only
def delete_team(teamid):
    user = Teams.query.filter_by(id=teamid).first()
    db.session.delete(user)
    db.session.commit()
    return '1'


@admin.route('/admin/graphs/<graph_type>')
@admins_only
def admin_graph(graph_type):
    if graph_type == 'categories':
        categories = db.session.query(Challenges.category, db.func.count(Challenges.category)).group_by(Challenges.category).all()
        json_data = {'categories':[]}
        for category, count in categories:
            json_data['categories'].append({'category':category, 'count':count})
        return jsonify(json_data)
    elif graph_type == "solves":
        solves = Solves.query.add_columns(db.func.count(Solves.chalid)).group_by(Solves.chalid).all()
        json_data = {}        
        for chal, count in solves:
            json_data[chal.chal.name] = count
        return jsonify(json_data)


@admin.route('/admin/scoreboard')
@admins_only
def admin_scoreboard():
    score = db.func.sum(Challenges.value).label('score')
    quickest = db.func.max(Solves.date).label('quickest')
    teams = db.session.query(Solves.teamid, Teams.name, Teams.banned, score).join(Teams).join(Challenges).group_by(Solves.teamid).order_by(score.desc(), quickest)
    db.session.close()
    return render_template('admin/scoreboard.html', teams=teams)


@admin.route('/admin/scores')
@admins_only
def admin_scores():
    score = db.func.sum(Challenges.value).label('score')
    quickest = db.func.max(Solves.date).label('quickest')
    teams = db.session.query(Solves.teamid, Teams.name, score).join(Teams).join(Challenges).filter(Teams.banned == None).group_by(Solves.teamid).order_by(score.desc(), quickest)
    db.session.close()
    json_data = {'teams':[]}
    for i, x in enumerate(teams):
        json_data['teams'].append({'place':i+1, 'id':x.teamid, 'name':x.name,'score':int(x.score)})
    return jsonify(json_data)


@admin.route('/admin/solves/<teamid>', methods=['GET'])
@admins_only
def admin_solves(teamid="all"):
    if teamid == "all":
        solves = Solves.query.all()
    else:
        solves = Solves.query.filter_by(teamid=teamid).all()
    db.session.close()
    json_data = {'solves':[]}
    for x in solves:
        json_data['solves'].append({'id':x.id, 'chal':x.chal.name, 'chalid':x.chalid,'team':x.teamid, 'value': x.chal.value, 'category':x.chal.category, 'time':unix_time(x.date)})
    return jsonify(json_data)


@admin.route('/admin/solves/<teamid>/<chalid>/delete', methods=['POST'])
@admins_only
def delete_solve(teamid, chalid):
    solve = Solves.query.filter_by(teamid=teamid, chalid=chalid).first()
    db.session.delete(solve)
    db.session.commit()
    return '1'


@admin.route('/admin/statistics', methods=['GET'])
@admins_only
def admin_stats():
    db.session.commit()
    
    teams_registered = db.session.query(db.func.count(Teams.id)).first()[0]
    wrong_count = db.session.query(db.func.count(WrongKeys.id)).first()[0]
    solve_count = db.session.query(db.func.count(Solves.id)).first()[0]
    challenge_count = db.session.query(db.func.count(Challenges.id)).first()[0]
    most_solved_chal = Solves.query.add_columns(db.func.count(Solves.chalid).label('solves')).group_by(Solves.chalid).order_by('solves DESC').first()
    least_solved_chal = Challenges.query.add_columns(db.func.count(Solves.chalid).label('solves')).outerjoin(Solves).group_by(Challenges.id).order_by('solves ASC').first()

    db.session.close()

    return render_template('admin/statistics.html', team_count=teams_registered,
        wrong_count=wrong_count,
        solve_count=solve_count,
        challenge_count=challenge_count,
        most_solved=most_solved_chal,
        least_solved=least_solved_chal
        )


@admin.route('/admin/wrong_keys/<page>', methods=['GET'])
@admins_only
def admin_wrong_key(page='1'):
    page = abs(int(page))
    results_per_page = 50
    page_start = results_per_page * ( page - 1 )
    page_end = results_per_page * ( page - 1 ) + results_per_page

    wrong_keys = WrongKeys.query.add_columns(WrongKeys.flag, WrongKeys.team, WrongKeys.date,\
                Challenges.name.label('chal_name'), Teams.name.label('team_name')).\
                join(Challenges).join(Teams).order_by('team_name ASC').slice(page_start, page_end).all()

    wrong_count = db.session.query(db.func.count(WrongKeys.id)).first()[0]
    pages = int(wrong_count / results_per_page) + (wrong_count % results_per_page > 0)

    return render_template('admin/wrong_keys.html', wrong_keys=wrong_keys, pages=pages)


@admin.route('/admin/correct_keys/<page>', methods=['GET'])
@admins_only
def admin_correct_key(page='1'):
    page = abs(int(page))
    results_per_page = 50
    page_start = results_per_page * (page - 1)
    page_end = results_per_page * (page - 1) + results_per_page

    solves = Solves.query.add_columns(Solves.chalid, Solves.teamid, Solves.date, Solves.flag, \
                Challenges.name.label('chal_name'), Teams.name.label('team_name')).\
                join(Challenges).join(Teams).order_by('team_name ASC').slice(page_start, page_end).all()

    solve_count = db.session.query(db.func.count(Solves.id)).first()[0]
    pages = int(solve_count / results_per_page) + (solve_count % results_per_page > 0)

    return render_template('admin/correct_keys.html', solves=solves, pages=pages)


@admin.route('/admin/fails/<teamid>', methods=['GET'])
@admins_only
def admin_fails(teamid='all'):
    if teamid == "all":
        fails = WrongKeys.query.count()
        solves = Solves.query.count()
        db.session.close()
        json_data = {'fails':str(fails), 'solves': str(solves)}
        return jsonify(json_data)
    else:
        fails = WrongKeys.query.filter_by(team=teamid).count()
        solves = Solves.query.filter_by(teamid=teamid).count()
        db.session.close()
        json_data = {'fails':str(fails), 'solves': str(solves)}
        return jsonify(json_data)


@admin.route('/admin/chal/new', methods=['POST'])
@admins_only
def admin_create_chal():
    files = request.files.getlist('files[]')

    ## TODO: Expand to support multiple flags
    flags = [{'flag':request.form['key'], 'type':int(request.form['key_type[0]'])}]

    # Create challenge
    chal = Challenges(request.form['name'], request.form['desc'], request.form['value'], request.form['category'], flags)
    db.session.add(chal)
    db.session.commit()

    for f in files:
        filename = secure_filename(f.filename)

        if len(filename) <= 0:
            continue

        md5hash = hashlib.md5(os.urandom(64)).hexdigest()

        if not os.path.exists(os.path.join(os.path.normpath(app.static_folder), 'uploads', md5hash)):
            os.makedirs(os.path.join(os.path.normpath(app.static_folder), 'uploads', md5hash))

        f.save(os.path.join(os.path.normpath(app.static_folder), 'uploads', md5hash, filename))
        db_f = Files(chal.id, os.path.join('static', 'uploads', md5hash, filename))
        db.session.add(db_f)

    db.session.commit()
    db.session.close()
    return redirect('/admin/chals')


@admin.route('/admin/chal/delete', methods=['POST'])
@admins_only
def admin_delete_chal():
    challenge = Challenges.query.filter_by(id=request.form['id']).first()
    if challenge:
        WrongKeys.query.filter_by(chalid=challenge.id).delete()
        Solves.query.filter_by(chalid=challenge.id).delete()
        Keys.query.filter_by(chal=challenge.id).delete()
        files = Files.query.filter_by(chal=challenge.id).all()
        Files.query.filter_by(chal=challenge.id).delete()
        for file in files:
            folder = os.path.dirname(file.location)
            rmdir(folder)
        Tags.query.filter_by(chal=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()
        db.session.close()
    return '1'


@admin.route('/admin/chal/update', methods=['POST'])
@admins_only
def admin_update_chal():
    challenge = Challenges.query.filter_by(id=request.form['id']).first()
    challenge.name = request.form['name']
    challenge.description = request.form['desc']
    challenge.value = request.form['value']
    challenge.category = request.form['category']
    db.session.add(challenge)
    db.session.commit()
    db.session.close()
    return redirect('/admin/chals')
