# Copyright 2017 MakeMyTrip (Kunal Aggarwal, Avinash Jain)
#
# This file is part of WebGuard.
#
# WebGuard is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# WebGuard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WebGuard.  If not, see <http://www.gnu.org/licenses/>.

from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from django.utils.text import slugify
from django.core.mail import send_mail, EmailMessage
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.contrib.auth.hashers import *

from api.models import *

from utils import login_ldap, client, login_check

from zapv2 import ZAPv2
from haikunator import Haikunator

import json, socket, uuid, requests, time, csv, os

# Create your views here.

def JsonResponse(data, status_code = 200):
	data = json.dumps(data)
	return HttpResponse(data, status = status_code, content_type = 'application/json')

@require_http_methods(["POST"])
@csrf_exempt
def zap_start(request):
	if request.method == "POST":
		if not login_check.is_logged_in(request):
			return JsonResponse({"message": "Please login first."}, 403)
		else:
			user = request.session['login_username']
			servers = ZAPServer.objects.filter(enabled = True)
			instances = ZAPInstance.objects.filter(enabled = True, user = user)
			if settings.ZAP_MULTIPLE_ALLOWED and len(instances) >= settings.ZAP_MULTIPLE_MAX_COUNT:
				return JsonResponse({"message": "You cannot start more ZAP Instances. Threshold exceeded."}, 403)
			elif not settings.ZAP_MULTIPLE_ALLOWED and len(instances) >= 1:
				return JsonResponse({"message": "You cannot start more ZAP Instances. Multiple ZAP not allowed."}, 403)
			else:
				if servers:
					valid_servers = []
					max_mem = 0
					best_server = None
					for server in servers:
						stats = client.get_server_stats(server.ip)
						if stats['free'] >= settings.ZAP_SERVER_MIN_FREE_MEMORY_THRESHOLD:
							valid_servers.append({"server": server, "stats": stats})

					if valid_servers:
						for server in valid_servers:
							if server['stats']['percentage'] > max_mem:
								max_mem = server['stats']['percentage']
								best_server = server['server']
						if best_server:
							port, api_key, pid = client.start_zap_instance(best_server.ip)
					
							instance_name = request.POST.get("name", None)
							if not instance_name:
								haikunator = Haikunator()
								instance_name = haikunator.haikunate(token_length=0, delimiter=' ').title()

							instance = ZAPInstance()
							instance.server = best_server
							instance.port = port
							instance.api_key = api_key
							instance.user = user
							instance.name = instance_name
							instance.session = request.session['session_id']
							instance.pid = pid
							instance.save()

							zap = ZAPv2(proxies={'http': 'http://%s:%s' % (best_server.ip, port), 'https': 'http://%s:%s' % (best_server.ip, port)})
							zap.ascan.set_option_max_scans_in_ui(600, apikey = api_key)
							zap.ascan.set_option_thread_per_host(5, apikey = api_key)
							zap.core.set_option_timeout_in_secs(180, apikey = api_key)

							return JsonResponse({"message": "ZAP Started", "server": best_server.ip, "port": port, "name": instance_name})
					else:
						return JsonResponse({"message": "All available servers are below defined Minimum Free Memory Threshold"}, 503)
				else:
					return JsonResponse({"message": "No servers running. Please register servers first."}, 503)

def check_user(request, port):
	try:
		instance = ZAPInstance.objects.get(user = request.session['login_username'], port = port, enabled = True)
		return True
	except:
		return False

@require_http_methods(["GET"])
def zap_hosts_list(request):
	if request.method == "GET":
		ip = request.GET.get("ip", None)
                port = request.GET.get("port", None)
		if ip and port:
			data = client.get_zap_hosts(ip, port)
			return JsonResponse(data)
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)	

@require_http_methods(["GET"])
def zap_hosts_write(request):
	if request.method == "GET":
		ip = request.GET.get("ip", None)
                port = request.GET.get("port", None)
		data = request.GET.get("data", None)
		if ip and port and data:
			response = client.write_zap_hosts(ip, port, data)
			return JsonResponse(response)
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)


@require_http_methods(["GET"])
def zap_get_logs(request, ip, port):
	if login_check.is_logged_in(request):
		if check_user(request, port):
			request.session['login_username']
			zap = ZAPv2(proxies={'http': 'http://%s:%s' % (ip, port), 'https': 'http://%s:%s' % (ip, port)})
			zap_urls = zap.search.urls_by_url_regex(".*")
                        zap_data = zap.search.messages_by_url_regex(".*")
			data = {}
			for url in zap_urls:
                                if not url['url'] in data:
                                    data[url['url']] = {}
                                data[url['url']]['id'] = url['id']
                                data[url['url']]['method'] = url['method']
                                if url['method'] == "POST":
                                        for z_data in zap_data:
                                                if z_data['id'] == url['id']:
                                                        data[url['url']]['data'] = z_data['requestBody']
                                else:
                                        data[url['url']]['data'] = ""
			return JsonResponse(data)
		else:
			return JsonResponse({"message": "Access Denied"}, 401)
	else:
		return JsonResponse({"message": "Access Denied"}, 401)

def get_scan_results(url, ip, port):
	zap = ZAPv2(proxies={'http': 'http://%s:%s' % (ip, port), 'https': 'http://%s:%s' % (ip, port)})
	return zap.core.alerts(url)

@require_http_methods(["GET"])
def zap_scan_report(request):
	if request.method == "GET":
                url = request.GET.get("url", None)
                ip = request.GET.get("ip", None)
                port = request.GET.get("port", None)
		
		if url and ip and port:
			alerts = get_scan_results(url, ip, port)
			return JsonResponse(alerts)
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)

def write_csv(url, alerts, ip, port, request):
	params = ["evidence","id","attack","messageId", "cweid", "wascid"]
	params = ["url", "param", "description", "solution", "reference", "alert", "risk"]
	if alerts:
		rows = []
		rows.append(params)
		for alert in alerts:
			row = []
			for param in params:
				row.append(alert[param])
			rows.append(row)

		filepath = settings.BASE_DIR
		component = static("reports/")
		filename = "%s_%s_%s.csv" % (request.session['login_username'], slugify(url), request.session['session_id'])

		myfile = open("%s%s%s" % (filepath, component, filename), 'wb')
		wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
		wr.writerows(rows)

		file_location = static('reports/%s' % filename)

		return True, file_location
	else:
		return False, ""

@require_http_methods(["GET"])
def zap_scan_report_email(request):
	email = request.GET.get("email", None)
	url = request.GET.get("url", None)
        ip = request.GET.get("ip", None)
        port = request.GET.get("port", None)

	if url and ip and port and email:
		alerts = get_scan_results(url, ip, port)
                status, response = write_csv(url, alerts, ip, port, request)
		if status:
			email = email.split(",")
			subject = "Vulnerability Report for %s" % url
			message = "PFA the vulnerability report for %s" % url
			
			mail = EmailMessage(subject, message, settings.EMAIL_FROM_EMAIL, email)
			fh = open("%s%s" % (settings.BASE_DIR, response))
			mail.attach(os.path.basename(response), fh.read(), 'text/csv')
			try:
				mail.send(fail_silently = False)
				fh.close()
				return JsonResponse({"message": "Sent email to %s successfully" % ", ".join(email)})
			except:
				fh.close()
				return JsonResponse({"message": "Something went wrong! Could not send email"}, 400)
		else:
			return JsonResponse({"message": "Something went wrong! Could not send email"}, 400)
        else:
                return JsonResponse({"message": "Invalid parameters recieved."}, 400)
	pass

@require_http_methods(["GET"])
def zap_scan_report_save(request):
	url = request.GET.get("url", None)
	ip = request.GET.get("ip", None)
        port = request.GET.get("port", None)
	
	if url and ip and port:
		alerts = get_scan_results(url, ip, port)
		status, response = write_csv(url, alerts, ip, port, request)
		if status:
			return JsonResponse({"file": response})
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)
	else:
		return JsonResponse({"message": "Invalid parameters recieved."}, 400)
	pass

@require_http_methods(["GET"])
@csrf_exempt
def zap_scan_url(request):
	if request.method == "GET":
		url = request.GET.get("url", None)
                ip = request.GET.get("ip", None)
                port = request.GET.get("port", None)

		if url and ip and port:
			status, scanId = zap_scan(request, ip, port, url, "GET", "", True)
			if status:
                                d = {"scanId": scanId, "message": "Scanning Started"}
                                return JsonResponse(d)
                        else:
                                return JsonResponse({"message": "No such instance found. Please check."}, 400)
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)

def zap_scan(request, ip, port, url, method, data, add_to_scan_tree = False):
	if add_to_scan_tree:
		proxies={'http': 'http://%s:%s' % (ip, port), 'https': 'http://%s:%s' % (ip, port)}
		r = requests.get(url, proxies = proxies, verify = False)
		print r
		time.sleep(1)

	zap = ZAPv2(proxies={'http': 'http://%s:%s' % (ip, port), 'https': 'http://%s:%s' % (ip, port)})
	try:
		instance = ZAPInstance.objects.get(server__ip = ip, port = port, enabled = True)
                if method == "POST":
                        scanId = zap.ascan.scan(url, apikey = instance.api_key, method = method, postdata = data)
                else:
        		scanId = zap.ascan.scan(url, apikey = instance.api_key)
		if not "scans" in request.session:
			request.session['scans'] = {}

		scan = ZAPScan()
		scan.instance = instance
		scan.scanId = scanId
		scan.user = request.session['login_username']
		scan.url = url
		scan.save()

		return True, scanId
	except Exception as e:
		return False, -1

@require_http_methods(["GET"])
@csrf_exempt
def zap_scan_start(request):
	if request.method == "GET":
		url = request.GET.get("url", None)
		ip = request.GET.get("ip", None)
		port = request.GET.get("port", None)
                method = request.GET.get("method", None)
                data = request.GET.get("data", None)

		if url and ip and port:
			status, scanId = zap_scan(request, ip, port, url, method, data)
			if status:
				d = {"scanId": scanId, "message": "Scanning Started"}
				return JsonResponse(d)
			else:
				return JsonResponse({"message": "No such instance found. Please check."}, 400)
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)

@require_http_methods(["GET"])
@csrf_exempt
def zap_scan_stop(request):
	if request.method == "GET":
		ip = request.GET.get("ip", None)
                port = request.GET.get("port", None)
		scanId = request.GET.get("scanid", None)

		if ip and port and scanId:
			try:
				instance = ZAPInstance.objects.get(server__ip = ip, port = port, enabled = True)
				apikey = instance.api_key
				zap = ZAPv2(proxies={'http': 'http://%s:%s' % (ip, port), 'https': 'http://%s:%s' % (ip, port)})
				response = zap.ascan.stop(scanId, apikey = apikey)
				if response == "OK":
					return JsonResponse({"status": True})
				else:
					return JsonResponse({"status": False}, 404)
			except:
				return JsonResponse({"message": "No such instance found. Please check."}, 400)
		else:
			return JsonResponse({"message": "Invalid parameters recieved."}, 400)

@require_http_methods(["GET"])
def zap_scan_list(request):
	port = request.GET.get("port", None)
	ip = request.GET.get("ip", None)
	if login_check.is_logged_in(request):
		if check_user(request, port):
			if port and ip:
				zap = ZAPv2(proxies={'http': 'http://%s:%s' % (ip, port), 'https': 'http://%s:%s' % (ip, port)})
				try:
					instance = ZAPInstance.objects.get(server__ip = ip, port = port, enabled = True)
					scans = zap.ascan.scans
					for i, scan in enumerate(scans):
                                                try:
                                                        zapscan = ZAPScan.objects.get(instance = instance, scanId = scan['id'], user = request.session['login_username'])
                                                        url = zapscan.url
                                                except:
                                                        url = "ERROR"
                                                scan['url'] = url
                                                scans[i] = scan
					return JsonResponse(scans)
				except Exception as e:
					return JsonResponse({"message": "No such instance found. Please check."}, 400)
			else:
				return JsonResponse({"message": "Invalid parameters recieved."}, 400)
		else:
                        return JsonResponse({"message": "Access Denied"}, 401)
        else:
                return JsonResponse({"message": "Access Denied"}, 401)
		

@require_http_methods(["POST"])
@csrf_exempt
def zap_stop(request, ip, port):
	if login_check.is_logged_in(request):
                if check_user(request, port):
			if request.method == "POST":
				servers = ZAPServer.objects.filter(ip = ip, enabled = True)
				if servers:
					response = client.stop_zap_instance(ip, port)
					if response['status']:
						try:
							instance = ZAPInstance.objects.get(port = port, enabled = True, server = servers[0])
							instance.enabled = False
							instance.save()
							return JsonResponse(response)
						except:
							return JsonResponse({"message": "No such instance found. Please check."}, 400)
					else:
						return JsonResponse({"message": "No such instance found. Please check."}, 400)
				else:
					return JsonResponse({"message": "No such server found. Please check."}, 400)
		else:
                        return JsonResponse({"message": "Access Denied"}, 401)
        else:
                return JsonResponse({"message": "Access Denied"}, 401)

def list_active_zap(username):
	instances = ZAPInstance.objects.filter(user = username, enabled = True)
	list_of_instances = []
	for instance in instances:
		status = client.get_zap_health(instance.server.ip, instance.port)
		if not status['status']:
			instance.enabled = False
			instance.save()
		else:
			d = {"ip": instance.server.ip, "port": instance.port, "status": status['status'], "name": instance.name}
			list_of_instances.append(d)
	return list_of_instances

@require_http_methods(["GET"])
def zap_list(request):
	if request.method == "GET":
		logged_in = request.session.get('logged_in', False)
		if logged_in:
			username = request.session['login_username']
			list_of_instances = list_active_zap(username)
			return JsonResponse(list_of_instances)
		else:
			return JsonResponse({"message": "No Instances found."}, 400)
			

@require_http_methods(["POST"])
@csrf_exempt
def login(request):
	if request.method == "POST":
		username = request.POST.get('username', None)
		password = request.POST.get('password', None)
		action   = request.POST.get('action', None)
		if username and password and action:
			try:
				method = settings.LOGIN_METHOD
			except:
				method = "LOCAL"

			if method.upper() == "LOCAL":
				username = username.strip().lower()
				password = password.strip().lower()
				if username and password:
					if action.lower() == "register":
						try:
							user = User()
							user.username = username
							user.password = make_password(password)
							user.save()
							request.session['logged_in'] = True
							request.session['session_id'] = str(uuid.uuid4())
							request.session['login_username'] = username
							return JsonResponse({"status": True, "message": "Login Success"})
						except Exception as e:
							return JsonResponse({"status": False, "message": "An error occured: %s" % str(e)}, 400)
					else:
						try:
							user = User.objects.get(username = username)
							if(check_password(password, user.password)):
								request.session['logged_in'] = True
	                                                        request.session['session_id'] = str(uuid.uuid4())
        	                                                request.session['login_username'] = username
                	                                        return JsonResponse({"status": True, "message": "Login Success"})
							else:
								return JsonResponse({"status": False, "message": "Incorrect Password"}, 400)
						except:
							return JsonResponse({"status": False, "message": "No such user found. Please register first!"}, 404)
				else:
					return JsonResponse({"status": False, "message": "Invalid Parameters"}, 400)
			else:
				response = login_ldap.login(username, password)
				if response['status']:
					request.session['logged_in'] = True
					request.session['session_id'] = str(uuid.uuid4())
					instances = ZAPInstance.objects.filter(enabled = True, user = username)
					for i in instances:
						i.session = request.session['session_id']
						i.save()
					request.session['login_username'] = username
					return JsonResponse(response)
				else:
					request.session['logged_in'] = False
					return JsonResponse(response, 401)
		else:
			return JsonResponse({"error": "Please provide credentials"}, 400)

@require_http_methods(["GET"])
@csrf_exempt
def logout(request):
	request.session['logged_in'] = False
	return JsonResponse({"message": "Logged Out"})

@require_http_methods(["POST"])
@csrf_exempt
def register(request):
	if request.method == "POST":
		zap_ip = request.POST.get("ip", None)
		if zap_ip:
			zap_server = ZAPServer.objects.filter(ip = zap_ip, enabled = True)
			if zap_server:
				j = {"status": 208, "message": "Server is already registered"}
				return JsonResponse(j, 208)
			else:
				zap_server = ZAPServer()
				zap_server.ip = zap_ip
				zap_server.save()
				j = {"status": 200, "message": "Server Registered"}
				return JsonResponse(j)
		else:
                        return JsonResponse({"error": "Invalid Request Content"}, 400)

@require_http_methods(["POST"])
@csrf_exempt
def unregister(request):
	if request.method == "POST":
                zap_ip = request.POST.get("ip", None)
                if zap_ip:
                        zap_server = ZAPServer.objects.filter(ip = zap_ip, enabled = True)
                        if zap_server:
				zap_server = zap_server[0]
				zap_server.enabled = False
				zap_server.save()
                                j = {"status": 200, "message": "Server De-registered"}
                                return JsonResponse(j)
                        else:
                                j = {"status": 404, "message": "No such server registered"}
                                return JsonResponse(j, 404)
                else:
                        return JsonResponse({"error": "Invalid Request Content"}, 400)

