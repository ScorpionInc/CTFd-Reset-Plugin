#!/usr/bin/env python3

# Path requires Python version 3.4+
from pathlib import Path

from flask import Blueprint, render_template, render_template_string, request, redirect, url_for, session, abort

#Requires @admin
from CTFd.api.v1.submissions import Submission as api_sub, SubmissionsList as api_sub_list

from CTFd.cache import cache, clear_challenges, clear_pages

from CTFd.plugins import challenges, register_plugin_assets_directory, register_user_page_menu_bar
from CTFd.models import db, Challenges, Awards, Submissions, Solves, Fails, Files, Tags, Users
from CTFd.schemas.submissions import SubmissionSchema

from CTFd import utils
from CTFd.utils import config as ctf_config
from CTFd.utils import get_app_config, get_config, set_config
from CTFd.utils.challenges import get_solve_ids_for_user_id
from CTFd.utils.config import is_setup
from CTFd.utils.decorators import admins_only, authed_only, during_ctf_time_only
from CTFd.utils.helpers import info_for, error_for, get_errors, get_infos
from CTFd.utils.helpers.models import build_model_filters
from CTFd.utils.modes import get_model
from CTFd.utils.plugins import override_template, register_script, register_stylesheet
from CTFd.utils.user import authed, get_current_user, get_current_team, get_user_score, get_team_score, is_admin, is_verified, get_ip
from CTFd.utils.security.auth import logout_user
from CTFd.utils.security.signing import hmac

from werkzeug.test import Client

import re
import os
import shutil
import logging

from .SiPluginTools import *
from .ResetChallenge import *
from .ResetChallengeType import load_type

# Used for debugging table structures (REMOVE FOR PROD)
def dump_tables() -> None:
	global Users, Challenge, Submissions, Solves, Fails
	print("[DEBUG]: dump_tables(): Starting data dump for CTFd Tables.") #!Debugging
	print("[DEBUG]: Users Query: '" + str(Users.query) + "' Value: '" + str(Users.query.all()) + "'.") #!Debugging
	print("[DEBUG]: Challenges Query: '" + str(Challenges.query) + "' Value: '" + str(Challenges.query.all()) + "'.") #!Debugging
	print("[DEBUG]: Submissions Query: '" + str(Submissions.query) + "' Value: '" + str(Submissions.query.all()) + "'.") #!Debugging
	print("[DEBUG]: Awards Query: '" + str(Awards.query) + "' Value: '" + str(Awards.query.all()) + "'.") #!Debugging
	print("[DEBUG]: Solves Query: '" + str(Solves.query) + "' Value: '" + str(Solves.query.all()) + "'.") #!Debugging
	print("[DEBUG]: Fails Query: '" + str(Fails.query) + "' Value: '" + str(Fails.query.all()) + "'.") #!Debugging
	print("[DEBUG]: ResetChallengeRules Query: '" + str(ResetChallengeRules.query) + "' Value: '" + str(ResetChallengeRules.query.all()) + "'.") #!Debugging
	print("[DEBUG]: ResetChallengeStats Query: '" + str(ResetChallengeStats.query) + "' Value: '" + str(ResetChallengeStats.query.all()) + "'.") #!Debugging
	print("[DEBUG]: dump_tables() Completed.") #!Debugging

def get_absolute_plugin_path() -> str:
	# Returns current plugins path on success.
	return Path(__file__).parent.resolve()

def get_plugin_folder_name() -> str:
	# Returns string of the directory name containing current script.
	return get_absolute_plugin_path().name

def get_absolute_theme_path(theme_name: str = get_config("ctf_theme")) -> str:
	# Returns string path to the target theme directory on success.
	plugins_dir = Path(get_absolute_plugin_path()).parent.resolve()
	ctfd_dir = Path(plugins_dir).parent.resolve()
	theme_dir = os.path.join(ctfd_dir, 'themes', theme_name, "templates")
	return theme_dir

def get_absolute_plugin_template_path() -> str:
	# Returns the string path to this plugins templates folder
	return os.path.join(get_absolute_plugin_path(), 'templates')

def get_relative_plugin_asset_path() -> str:
	# Returns the relative string path to this plugins assets directory
	base_path = os.path.join("plugins", get_plugin_folder_name(), "assets")
	slash_char = base_path[7:8:1]
	return (slash_char + base_path + slash_char)

def patch_theme_template(template_file: str = "challenge.html", theme_name:str = get_config("ctf_theme"), regex_match: str = ".", insert_value: str = "{% include 'challenge.html' %}", remove_line: bool = False, match_offset: int = 1) -> bool:
	# Initialize variables
	theme_dir = get_absolute_theme_path(str(theme_name))
	source = os.path.join(theme_dir, template_file)
	template_dir = get_absolute_plugin_template_path()
	target = os.path.join(template_dir, template_file)
	file_handle = {}
	lines = []
	insertion_line = -1
	# Copy source file into plugin templates directory.
	shutil.copyfile(source, target)
	# Buffer contents of copied file in plugin template directory into memory.
	for _ in (True,): #Used for break statement
		try:
			with open(str(target), 'r') as file_handle:
				lines = file_handle.readlines()
		except Error:
			print("[ERROR]: patch_theme_template() Failed to open file for matching.") #!Debugging
			break
	try:
		#Close if file_handle is still open. (Shouldn't be).
		file_handle.close()
	except AttributeError:
		#Close() is not defined at this point.
		pass
	if(len(lines) <= 0):
		print("[WARN]: patch_theme_template() Lacks search space for pattern matching.") #!Debugging
		return False
	# Edit file contents of file in plugin template directory stored in memory.
	for line in lines:
		if re.search(regex_match, line, re.MULTILINE) != None:
			insertion_line = (lines.index(line) + match_offset)
			if(remove_line):
				lines[insertion_line] = insert_value
			else:
				lines.insert(insertion_line, insert_value)
			break
	if(insertion_line == -1):
		print("[ERROR]: patch_theme_template() Failed to find match for regex: '" + str(regex_match) + "'.") #!Debugging
		return False
	# Write changes in memory to copied file(s)
	try:
		file_handle = open(str(target), "w")
		for line in lines:
			file_handle.write(str(line))
		file_handle.close()
	except Error:
		print("[ERROR]: patch_theme_template() Failed to write changes to file.") #!Debugging
		return False
	# Patch Applied now override route(as needed.)
	return True

#<!-- RESETCHALLENGE PLUGIN RESET BUTTON GOES HERE -->
DEFAULT_INSERT_COMMENT_REGEX=".*<!--\s+RESETCHALLENGE\s+PLUGIN\s+RESET\s+BUTTON\s+GOES\s+HERE\s+-->.*"
DEFAULT_CLOSE_BUTTON_REGEX = "^\s*<\s*button\s+(\s*(type|class|data-bs-dismiss|data-dismiss|aria-label)\s*=\s*['\"]\s*(button|(btn-close\sfloat-end|float-end\sbtn-close|modal|Close))\s*['\"]\s?){1,4}>\s*</button>\s*"
DEFAULT_CHALLENGE_INSERT_TEMPLATE = "resetChallengeBtn.html"
def patch_challenge_reset_btn() -> bool:
	global DEFAULT_INSERT_COMMENT_REGEX, DEFAULT_CLOSE_BUTTON_REGEX, DEFAULT_CHALLENGE_INSERT_TEMPLATE
	current_theme = get_config("ctf_theme")
	source_file = "challenge.html"
	target_file = os.path.join(get_absolute_plugin_template_path(), source_file)
	insert_str = "{% include '" + str(DEFAULT_CHALLENGE_INSERT_TEMPLATE) + "' %}\n"
	if(SiPluginTools.patch_theme_template(source_file, current_theme, DEFAULT_INSERT_COMMENT_REGEX, insert_str, True)):
		print("[DEBUG]: Patched challenge reset button based upon marker.") #!Debugging
		override_template(source_file, open(target_file).read())
	elif(SiPluginTools.patch_theme_template(source_file, current_theme, DEFAULT_CLOSE_BUTTON_REGEX, insert_str, False)):
		print("[DEBUG]: Patched challenge reset button based upon close button.") #!Debugging
		override_template(source_file, open(target_file).read())
	else:
		print("[ERROR]: Failed to patch theme file '" + str(source_file) + "' to include reset button.")
		return False
	#print("[DEBUG]: Finished patching in reset button into " + source_file + " theme.") #!Debugging
	return True

DEFAULT_CATEGORY_HEADER_REGEX = "^\s*<\s*h3\s+((x-text)=['\"](category)['\"]\s*){0,1}\s*(>\s*</h3>|/\s*>)\s*$"
DEFAULT_CHALLENGES_INSERT_TEMPLATE = "resetChallengesBtn.html"
def patch_challenges_reset_btn() -> bool:
	global DEFAULT_INSERT_COMMENT_REGEX, DEFAULT_CATEGORY_HEADER_REGEX, DEFAULT_CHALLENGES_INSERT_TEMPLATE
	current_theme = get_config("ctf_theme")
	source_file = "challenges.html"
	target_file = os.path.join(get_absolute_plugin_template_path(), source_file)
	insert_str = "{% include '" + str(DEFAULT_CHALLENGES_INSERT_TEMPLATE) + "' %}\n"
	if(patch_theme_template(source_file, current_theme, DEFAULT_INSERT_COMMENT_REGEX, insert_str, True)):
		print("[DEBUG]: Patched Category reset button based upon marker.") #!Debugging
		override_template(source_file, open(target_file).read())
	elif(patch_theme_template(source_file, current_theme, DEFAULT_CATEGORY_HEADER_REGEX, insert_str, False)):
		print("[DEBUG]: Patched Category reset button based upon DOM tag.") #!Debugging
		override_template(source_file, open(target_file).read())
	else:
		print("[ERROR]: Failed to patch theme file: '" + str(source_file) + "' to include reset button.") #!Debugging
		return False
	#print("[DEBUG]: Finished patching in reset button into " + source_file + " theme.") #!Debugging
	return True

def do_template_patches() -> None:
	# Attempts to patch current themes challenge and challenges templates to include reset button(s).
	# Returns None
	patch_challenge_reset_btn()
	patch_challenges_reset_btn()

def load(app):
	#print("[DEBUG]: Plugin ResetChallenge is being loaded...") #!Debugging
	# Create and initialize database table(s).
	app.db.create_all()
	dump_tables()
	# Create and initialize Blueprint
	resetChallenge = Blueprint('resetChallenge', __name__, template_folder='templates', static_folder='static')
	# Defaults option for route seems to prevent correct functioning of url parsing.
	@resetChallenge.route('/resetChallenge/<int:cid>', methods=['POST']) #, defaults={'cid':-1})
	@authed_only
	@during_ctf_time_only
	def handleResetChallenge(cid):
		challenges_endpoint = "listing" #str(request.endpoint)
		if request.method == 'GET':
			print("[WARN]: Invalid access attempt on route: /resetChallenge/" + str(cid) + ".") #!Debugging
			return redirect("/")
		#print("[DEBUG]: Reset Challenge Plugin Request: " + str(request.form) + ".\n") #!Debugging
		#allow_global_resets = get_config('resetChallenge_global')
		if(cid == None or cid <= 0):
			cid = request.args.get("cid")
			if(cid == None or cid <= 0):
				cid = request.form.getlist("cid")
				if(len(cid) <= 0):
					print("[ERROR]: Challenge ID is missing or invalid.") #!Debugging
					error_for(challenges_endpoint, "Reset failed due to bad ID.")
					return redirect("/challenges")
				cid = int(cid[0])
		uid = request.args.get("uid")
		if(uid == None or uid <= 0):
			uid = request.form.getlist("uid")
			if(len(uid) <= 0):
				print("[ERROR]: Target User ID is missing or invalid.") #!Debugging
				error_for(challenges_endpoint, "Reset failed due to bad User.")
				return redirect("/challenges")
			uid = int(uid[0])
		#print("[DEBUG]: Attempting to reset challenge: '" + str(cid) + "' for user: '" + str(uid) + "'.") #!Debugging
		ResetChallenge.reset(uid, cid)
		#print("[DEBUG]: Plugin has finished reset attempt.") #!Debugging
		info_for(challenges_endpoint, "Challenge[" + str(cid) + "] was reset.")
		return redirect("/challenges")
	@resetChallenge.route('/resetChallenges', methods=['POST'])
	@authed_only
	@during_ctf_time_only
	def handleResetChallenges():
		#print("[DEBUG]: Reset Category function called.") #!Debugging
		challenges_endpoint = "listing" #str(request.endpoint)
		if request.method == 'GET':
			print("[WARN]: Invalid access method foroute + r function handleResetChallenges().") #!Debugging
			return redirect("/")
		cid = request.args.get("cid")
		if(cid == None or cid == ""):
			cid = request.form.getlist("cid")
			if(len(cid) <= 0):
				print("[ERROR]: Category is missing or invalid.") #!Debugging
				error_for(challenges_endpoint, "Invalid Category.")
				return redirect("/challenges")
			cid = str(cid[0])
		uid = request.args.get("uid")
		if(uid == None or uid <= 0):
			uid = request.form.getlist("uid")
			if(len(uid) <= 0):
				print("[ERROR]: Target User ID is missing or invalid.") #!Debugging
				error_for(challenges_endpoint, "Invalid User ID.")
				return redirect("/challenges")
			uid = int(uid[0])
		#print("[DEBUG]: Attempting to reset category: '" + cid + "' for user: '" + str(uid) + "'.") #!Debugging
		ResetChallenge.resetCategory(cid, uid)
		#print("[DEBUG]: Attempt completed.") #!Debugging
		info_for(challenges_endpoint, "Category: '" + cid + "' was reset.")
		return redirect("/challenges")
	@resetChallenge.route('/resetAllChallenges', methods=['GET', 'POST'])
	@authed_only
	@during_ctf_time_only
	def handleResetAllChallenges():
		challenges_endpoint = "listing" #str(request.endpoint)
		if(request.method == 'GET'):
				return render_template("resetAllChallenges.html")
		elif(request.method == 'POST'):
			uid = request.args.get("uid")
			if(uid == None or uid < 0):
				uid = request.form.getlist("uid")
				if(len(uid) <= 0):
					print("[ERROR]: Target User ID is missing or invalid.") #!Debugging
					error_for(challenges_endpoint, "User ID is missing or invalid.")
					return redirect("/challenges")
				uid = int(uid[0])
			ResetChallenge.resetAll(uid)
			info_for(challenges_endpoint, "Challenge(s) for user[" + str(uid) + "] was/were reset.")
			return redirect("/challenges")
		else:
			print("[ERROR]: Request method of unknown type: '" + str(request.method) + "' for reset all challenges page.") #!Debugging
			return redirect('/')
		#Unreachable Code
		return "", 404
	@resetChallenge.route('/admin/plugins/resetChallenge', methods=['GET', 'POST'])
	@admins_only
	def handleResetChallengeAdministration():
		#print("[DEBUG]: ResetChallenge Plugin admin page accessed.") #!Debugging
		args = dict(request.args)
		if(not is_admin()):
			print("[WARN]: Attempt to access admin only page: /admin/plugins/resetChallenge by non-admin.") #!Debugging
			return redirect('/')
		page = args.pop("page", 1)
		if(request.method == "GET"):
			rules = (
				ResetChallengeRules.query
				.order_by(ResetChallengeRules.priority.desc())
				.paginate(page=page, per_page=50)
			)
			# Make values pretty
			for r in rules.items:
				r.type = ResetChallengeRules.type_to_str(r.type) # + "[" + str(r.type) + "]"
				r.test = ResetChallengeRules.test_to_str(r.test) # + "[" + str(r.test) + "]"
				r.action = ResetChallengeRules.action_to_str(r.action) # + "[" + str(r.action) + "]"
			# Render Settings Page
			return render_template(
				"resetChallengeAdmin.html",
				assets=get_relative_plugin_asset_path(),
				max_priority=ResetChallengeRules.MAX_PRIORITY,
				rules=rules,
				type_names=ResetChallengeRules.type_names,
				test_names=ResetChallengeRules.test_names,
				action_names=ResetChallengeRules.action_names,
				prev_page=url_for(
					request.endpoint,
					page=rules.prev_num
				),
				next_page=url_for(
					request.endpoint,
					page=rules.next_num
				)
			), 200
		elif(request.method == "POST"):
			#print("[DEBUG]: POST request method used to access ResetChallenge Plugin Admin Page.") #!Debugging
			task = args.get("task")
			if(task == None or task == ""):
				task = request.form.getlist("task")
				if(task == None or len(task) == 0):
					print("[ERROR]: task is either missing or invalid.") #!Debugging
					return redirect('/admin/plugins/resetChallenge')
				task = task[0]
			#match statement requires Python Version >= 3.10
			match task:
				case "priorityUp":
					# Increase Priority of current rule to be higher than the rule above it.
					rid = args.get("rid")
					if(rid == None or rid < 0):
						rid = request.form.getlist("rid")
						if(rid == None or len(rid) <= 0):
							print("[ERROR]: rid id either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						rid = int(rid[0])
					ResetChallengeRules.increase_priority(rid)
				case "priorityDown":
					# Increase Priority of current rule to be higher than the rule above it.
					rid = args.get("rid")
					if(rid == None or rid < 0):
						rid = request.form.getlist("rid")
						if(rid == None or len(rid) <= 0):
							print("[ERROR]: rid id either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						rid = int(rid[0])
					ResetChallengeRules.decrease_priority(rid)
				case "delete":
					rid = args.get("rid")
					if(rid == None or rid < 0):
						rid = request.form.getlist("rid")
						if(rid == None or len(rid) <= 0):
							print("[ERROR]: rid is either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						rid = rid[0]
					#print("[DEBUG]: RID: " + str(rid) + ".") #!Debugging
					args = { "id":rid }
					ts = ResetChallengeRules.query.filter_by(**args)
					for r in ts.all():
						db.session.delete(r)
					db.session.commit()
					db.session.close()
				case "add":
					newPriority = args.get("newPriority")
					if(newPriority == None or newPriority == ""):
						newPriority = request.form.getlist("newPriority")
						if(newPriority == None or len(newPriority) <= 0):
							print("[ERROR]: newPriority is either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						newPriority = newPriority[0]
					newType = args.get("newType")
					if(newType == None or newType == ""):
						newType = request.form.getlist("newType")
						if(newType == None or len(newType) <= 0):
							print("[ERROR]: newType is either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						newType = newType[0]
					newTest = args.get("newTest")
					if(newTest == None or newTest == ""):
						newTest = request.form.getlist("newTest")
						if(newTest == None or len(newTest) <= 0):
							print("[ERROR]: newTest is either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						newTest = newTest[0]
					newValue = args.get("newValue")
					if(newValue == None or newValue == ""):
						newValue = request.form.getlist("newValue")
						if(newValue == None or len(newValue) <= 0):
							print("[ERROR]: newValue is either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						newValue = newValue[0]
					newAction = args.get("newAction")
					if(newAction == None or newAction == ""):
						newAction = request.form.getlist("newAction")
						if(newAction == None or len(newAction) <= 0):
							print("[ERROR]: newAction is either missing or invalid.") #!Debugging
							return redirect('/admin/plugins/resetChallenge')
						newAction = newAction[0]
					#print("[DEBUG]: ADD RULE[" + str(newPriority) + "] " + str(newType) + " " + str(newTest) + " '" + str(newValue) + "' then " + str(newAction) + ".") #!Debugging
					#ResetChallengeRule(priority, type, test, value, action)
					newRule = ResetChallengeRules(
						priority=int(newPriority),
						type=int(ResetChallengeRules.type_names.index(newType)),
						test=int(ResetChallengeRules.test_names.index(newTest)),
						value=str(newValue),
						action=int(ResetChallengeRules.action_names.index(newAction))
					)
					db.session.add(newRule)
					db.session.commit()
					db.session.close()
				case _:
					print("[ERROR]: Task '" + str(task) + "' is unknown.") #!Debugging
			return redirect('/admin/plugins/resetChallenge')
		else:
			print("[ERROR]: resetChallengeAdministration Encountered invalid request method.") #!Debugging
			return render_template('base.html'), 404
	app.register_blueprint(resetChallenge)
	#Register Assets
	register_plugin_assets_directory(app, base_path=get_relative_plugin_asset_path())
	# Add user page for reset
	if(is_setup()):
		#print("[DEBUG]: Instance has been setup, adding user reset page.") #!Debugging
		register_user_page_menu_bar("Reset Challenges", "/resetAllChallenges")
	else:
		print("[WARN]: Instance is doing/hasn't completed setup. Skipping add of user reset page.") #!Debugging
	#Override template(s)
	do_template_patches()
	load_type(app)
