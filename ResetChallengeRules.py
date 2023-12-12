#!/usr/bin/env python3

from datetime import datetime

from flask import request, redirect, url_for, session, abort

from CTFd.models import db, Users, Challenges
from CTFd.utils.security.signing import hmac
from CTFd.utils.user import authed

class ResetChallengeRules(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	MAX_PRIORITY=9223372036854775807
	priority = db.Column(db.Integer)
	type = db.Column(db.Integer)
	test = db.Column(db.Integer)
	value = db.Column(db.Text)
	action = db.Column(db.Integer)
	type_names = ["UserID", "Username", "ChallengeID", "ChallengeName", "Category", "DateTime", "Date", "Time", "FileExists"]
	test_names = ["==", "!=", "<", "<=", ">", ">="]
	action_names = ["Disabled", "Allow", "Deny"]
	def __init__(self, priority: int, type: int, test: int, value: str, action: int):
		self.priority = priority
		self.type = type
		self.test = test
		self.value = value
		self.action = action
	#@classmethod
	@staticmethod
	def index_valid(arry, idx : int) -> bool:
		if(str(type(idx)) != "<class 'int'>"):
			#print("[DEBUG]: ResetChallengeRules.index_valid() idx is of invalid type '" + str(type(idx)) + "'.") #!Debugging
			return False
		else:
			#print("[DEBUG]: ResetChallengeRules.index_valid() idx is valid type.") #!Debugging
			pass
		if(idx < 0):
			#print("[DEBUG]: ResetChallengeRules.index_valid() idx is below 0.") #!Debugging
			return False
		else:
			#print("[DEBUG]: ResetChallengeRules.index_valid() idx is positive.") #!Debugging
			pass
		arry_len = len(arry)
		if(idx >= arry_len):
			#print("[DEBUG]: ResetChallengeRules.index_valid() idx is to large.") #!Debugging
			return False
		else:
			#print("[DEBUG]: ResetChallengeRules.index_valid() idx is valid.") #!Debugging
			pass
		return True
	@staticmethod
	def type_to_str(p_type: int) -> str:
		#Returns string value of typeID on success
		#Returns empty string on fail/error.
		if(not ResetChallengeRules.index_valid(ResetChallengeRules.type_names, p_type)):
			return ""
		return ResetChallengeRules.type_names[p_type]
	@staticmethod
	def test_to_str(p_test: int) -> str:
		#Returns string value of testID on success
		#Returns empty string on fail/error.
		if(not ResetChallengeRules.index_valid(ResetChallengeRules.type_names, p_test)):
			return ""
		return ResetChallengeRules.test_names[p_test]
	@staticmethod
	def action_to_str(p_action: int) -> str:
		#Returns string value of actionID on success
		#Returns empty string on fail/error.
		if(not ResetChallengeRules.index_valid(ResetChallengeRules.type_names, p_action)):
			return ""
		return ResetChallengeRules.action_names[p_action]
	@staticmethod
	def test_rule(p_test:int, p_value:str, test_value:str) -> bool:
		#Compares value against test_value by test operation. Returns True on Success.
		#Returns False otherwise.
		#Test:
		#"==", "!=", "<", "<=", ">", ">=",
		#   0,    1,   2,    3,   4,    5,
		#match statement requires Python Version >= 3.10
		match p_test:
			case 0:
				return (p_value == test_value)
			case 1:
				return(not p_value == test_value)
			case 2:
				return(p_value < test_value)
			case 3:
				return(p_value <= test_value)
			case 4:
				return(p_value > test_value)
			case 5:
				return(p_value >= test_value)
			case _:
				print("[ERROR]: test_rule() encountered unknown/invalid test type: '" + str(self.type) + "'.") #!Debugging
				return False
		#Unreachable Code
		return False
	@staticmethod
	def test_rule_by_id(p_id: int, p_value: str) -> bool:
		#Helper Function
		#Returns test value of rule by id against value p_value.
		args = {"id":p_id}
		value = ResetChallengeRules.query.filter_by(**args).first_or_404()
		v_test = value.test
		v_value = value.value
		#print("[DEBUG]: test_rule_by_id() Rule value: '"+str(value)+"', test '"+str(v_test)+"', test type: '"+str(type(v_test))+"'.") #!Debugging
		#print("[DEBUG]: test_rule_by_id() Test Value: '"+str(v_value)+"'\t Test type: '"+str(type(v_value))+"'.") #!Debugging
		return(ResetChallengeRules.test_rule(p_test=int(v_test), p_value=str(p_value), test_value=str(v_value)))
	@staticmethod
	def test_rule_type(p_type:int, value:str, default_allow:bool = True) -> bool:
		#Returns first action of all rules of type p_type tested against string value.
		#Returns default_allow otherwise.
		args = { "type":p_type }
		ts = ResetChallengeRules.query.filter_by(**args).order_by(ResetChallengeRules.priority.desc())
		for r in ts.all():
			print("[DEBUG]: test_rule_type() testing value: '"+value+"' vs '"+r.value+"'.") #!Debugging
			match r.action:
				case 0:
					#Disabled
					break
				case 1:
					#Allow
					if(ResetChallengeRules.test_rule(p_test=r.test,p_value=value,test_value=r.value)):
						return True
				case 2:
					#Deny
					if(ResetChallengeRules.test_rule(p_test=r.test,p_value=value,test_value=r.value)):
						return False
				case _:
					print("[ERROR]: test_rule_type() encountered invalid action type: '" + str(r.action) + "'.") #!Debugging
		return default_allow
	@staticmethod
	def find_user_by_id(uid:int):
		# Modified from source function get_current_user() from CTFd.utils.user
		# Returns first user data entry where id equals uid.
		# Returns None or aborts on error.
		if authed():
			user = Users.query.filter_by(id=uid).first()
			print("[DEBUG]: find_user_by_id() User query: '" + str(user) + "'.") #!Debugging
			# Check if the session is still valid
			session_hash = session.get("hash")
			if session_hash:
				if session_hash != hmac(user.password):
					#logout_user()
					if request.content_type == "application/json":
						error = 401
					else:
						error = redirect(url_for("auth.login", next=request.full_path))
					abort(error)
			return user
		else:
			return None
	@staticmethod
	def find_user_by_name(uid: str):
		# Names are not unique so may return inaccurate results.
		# Modified from source function get_current_user() from CTFd.utils.user
		# Returns user information for first matching username of uid.
		# Returns None or aborts on error
		args = {"name":uid}
		if authed():
			user = Users.query.filter_by(**args).first()
			print("[DEBUG]: find_user_by_name() User query '" + str(user) + "'.") #!Debugging
			# Check if the session is still valid
			session_hash = session.get("hash")
			if session_hash:
				if session_hash != hmac(user.password):
					if(request.content_type == "application/json"):
						error = 401
					else:
						error = redirect(url_for("auth.login", next=request.full_path))
					abort(error)
			return user
		else:
			return None
	@staticmethod
	def can_reset_user_id(uid: int, default_allow:bool = True) -> bool:
		# Helper Function
		# Returns action value when rule passes for user with id of uid to reset.
		# Returns default_allow otherwise.
		return ResetChallengeRules.test_rule_type(p_type=0, value=str(uid), default_allow=default_allow)
	@staticmethod
	def can_reset_user_name(uid: str, default_allow:bool = True) -> bool:
		# Helper Function
		# Returns action value when first rule passes for user with name of uid to reset.
		# return default_allow otherwise.
		return ResetChallengeRules.test_rule_type(p_type=1, value=uid, default_allow=default_allow)
	@staticmethod
	def can_reset_user(uid, default_allow:bool = True) -> bool:
		# Helper Function
		# Returns action value when first rule passes for user with id of int value of uid to reset.
		# Returns action value when first rule passes for user with name of string value of uid to reset.
		# Returns default_allow otherwise.
		int_type_str = "<class 'int'>"
		str_type_str = "<class 'str'>"
		u_param_type = str(type(uid))
		if(u_param_type == int_type_str):
			target_username = ResetChallengeRules.find_user_by_id(int(uid)).name
			#print("[DEBUG]: can_reset_user() Target Username: " + str(target_username) + ".") #!Debugging
			return ResetChallengeRules.can_reset_user_id(int(uid)) and ResetChallengeRules.can_reset_user_name(str(target_username))
		elif(u_param_type == str_type_str):
			target_id = ResetChallengeRules.find_user_by_name(str(uid))
			#print("[DEBUG]: can_reset_user() Target UID: " + str(target_id) + ".") #!Debugging
			print("[WARN]: Using can_reset_user() with username can give unexpected results.") #!Debugging
			return ResetChallengeRules.can_reset_user_id(int(target_id)) and ResetChallenceRules.can_reset_user_name(str(uid))
		print("[ERROR]: can_reset_user() encountered invalid parameter type of: '" + u_param_type + "'.") #!Debugging
		return default_allow
	@staticmethod
	def find_challenge_by_id(cid: int):
		# Helper Function
		args = {"id":cid}
		c = Challenges.query.filter_by(**args).first()
		return c
	@staticmethod
	def find_challenge_by_name(cid: str):
		# Helper Function
		# Challenge Names aren't unique this may return unexpected results.
		args = {"name":cid}
		c = Challenges.query.filter_by(**args).first()
		return c
	@staticmethod
	def can_reset_challenge_id(cid: int, default_allow:bool = True) -> bool:
		# Helper Function
		# Returns action value when first rule passes for challenge with id of cid to be reset.
		# Returns default_allow otherwise.
		return ResetChallengeRules.test_rule_type(p_type=2, value=str(cid), default_allow=default_allow)
	@staticmethod
	def can_reset_challenge_name(cid: str, default_allow: bool = True) -> bool:
		# Helper Function
		# Returns action value when first rule passes for challenge with name of cid to be reset.
		# Returns default_allow otherwise.
		return ResetChallengeRules.test_rule_type(p_type=3, value=cid, default_allow=default_allow)
	@staticmethod
	def can_reset_challenge(cid, default_allow:bool = True) -> bool:
		# Helper Function
		# Returns action value when first rule passes for challenge named string value of cid to be reset.
		# Returns action value when first rule passes for challenge with id of integer value of cid to be reset.
		# Returns default_allow otherwise.
		int_type_str = "<class 'int'>"
		str_type_str = "<class 'str'>"
		c_param_type = str(type(cid))
		if(c_param_type == int_type_str):
			c_name = ResetChallengeRules.find_challenge_by_id(int(cid)).name
			#print("[DEBUG]: can_reset_challenge() c_name: '" + str(c_name) + "'.") #!Debugging
			return can_reset_challenge_id(int(cid)) and can_reset_challenge_name(str(c_name))
		elif(c_param_type == str_type_str):
			c_id = ResetChallengeRules.find_challenge_by_name(str(cid)).id
			#print("[DEBUG]: can_reset_challenge() c_id: " + str(c_id) + ".") #!Debugging
			print("[WARN]: using can_reset_challenge() via challenge name may give unexpected results.") #!Debugging
			return can_reset_challenge_id(int(c_id)) and can_reset_challenge_name(str(cid))
		print("[ERROR]: can_reset_challenge() encountered invalid parameter type of: '" + c_param_type + "'.") #!Debug>
		return default_allow
	@staticmethod
	def find_category_by_challenge_id(cid: int):
		# Helper Funtion
		return ResetChallengeRules.find_challenge_by_id(cid).category
	@staticmethod
	def can_reset_category(category: str, default_allow:bool = True) -> bool:
		# Helper Function
		# Returns action value if the string value of category is an allowed category name to be reset.
		# Returns default_allow otherwise.
		return ResetChallengeRules.test_rule_type(p_type=4, value=category, default_allow=default_allow)
	@staticmethod
	def is_reset_allowed(userID = -1, userName:str = "", challengeID: int = -1, challengeName: str = "", category: str = "", default_allow:bool = True):
		#TODO Implement rule types 5 -> 8
		# Requires either an id or name for tested user, and challenge(both prefered),
		# Optionally category(prefered).
		# Returns rule action when first matching rule passes for a reset of challenge.
		# Returns default_allow otherwise.
		#Handle missing inputs.
		if(userID < 0 and userName != ""):
			#Get userID from userName
			userID = ResetChallengeRules.find_user_by_name(userName).id
			print("[WARN]: using is_reset_allowed() without user id may lead to unexpected results.") #!Debugging
		if(userID < 0):
			print("[ERROR]: is_reset_allowed() Invalid UserID: " + str(userID) + ".") #!Debugging
			return default_allow
		if(userName == "" and userID >= 0):
			#Get userName from userID
			userName = ResetChallengeRules.find_user_by_id(userID).name
		if(userName == ""):
			print("[ERROR]: is_reset_allowed() Invalid username: '" + str(userName) + "'.") #!Debugging
			return default_allow
		if(challengeID < 0 and challengeName != ""):
			#Get challengeID from challengeName.
			challengeID = ResetChallengeRules.find_challenge_by_name(str(challengeName)).id
			print("[WARN]: using is_reset_allowed() without challenge id may lead to unexpected results.") #!Debugging
		if(challengeID < 0):
			print("[ERROR]: is_reset_allowed() Invalid challengeID: " + str(challengeID) + ".") #!Debugging
			return default_allow
		if(challengeName == "" and challengeID >= 0):
			#Get challengeName from challengeID.
			challengeName = ResetChallengeRules.find_challenge_by_id(challengeID).name
		if(challengeName == ""):
			print("[ERROR]: is_reset_allowed() Invalid challengeName: '" + str(challengeName) + "'.") #!Debugging
			return default_allow
		if(category == ""):
			#Get category from challengeID
			category = ResetChallengeRules.find_category_by_challenge_id(challengeID)
		rules = ResetChallengeRules.query.order_by(ResetChallengeRules.priority.desc())
		for rule in rules:
			if(rule.action == 0):
				# Skip Disabled rules
				continue
			elif(rule.action >= 3):
				print("[WARN]: is_reset_allowed() encountered an invalid rule action.") #!Debugging
				continue
			match rule.type:
				case 0:
					#UserID
					if(ResetChallengeRules.test_rule(p_test=rule.test,p_value=str(userID),test_value=rule.value)):
						return(rule.action == 1)
					break
				case 1:
					#Username
					if(ResetChallengeRules.test_rule(p_test=rule.test,p_value=userName,test_value=rule.value)):
						return (rule.action == 1)
					break
				case 2:
					#ChallengeID
					if(ResetChallengeRules.test_rule(p_test=rule.test,p_value=str(challengeID),test_value=rule.value)):
						return (rule.action == 1)
					break
				case 3:
					#ChallengeName
					if(ResetChallengeRules.test_rule(p_test=rule.test,p_value=challengeName,test_value=rule.value)):
						return (rule.action == 1)
					break
				case 4:
					#Category
					if(ResetChallengeRules.test_rule(p_test=rule.test,p_value=category,test_value=rule.value)):
						return (rule.action == 1)
					break
				case 5:
					#Datetime
					break
				case 6:
					#Date
					break
				case 7:
					#Time
					break
				case 8:
					#FileExists
					break
				case _:
					print("[WARN]: is_reset_allowed() encountered an unknown rule type: " + str(rule.type) + ".") #!Debugging
					continue
		#Default Allow
		return default_allow
	@staticmethod
	def get_visible_challenges_allowed_to_reset(userID = -1, userName:str = "", default_allow:bool = True) -> list:
		# Tests all challenges / categories for user of id/name.
		# Returns True or False for each challenge in a List of Sets on success.
		# Returns None on Error.
		#Handle missing inputs.
		if(userID < 0 and userName != ""):
			#Get userID from userName
			userID = ResetChallengeRules.find_user_by_name(userName).id
			print("[WARN]: using get_visible_challenges_allowed_to_reset() without user id may lead to unexpected results.") #!Debugging
		if(userID < 0):
			print("[ERROR]: get_visible_challenges_allowed_to_reset() Invalid UserID: " + str(userID) + ".") #!Debugging
			return default_allow
		if(userName == "" and userID >= 0):
			#Get userName from userID
			userName = ResetChallengeRules.find_user_by_id(userID).name
		if(userName == ""):
			print("[ERROR]: get_visible_challenges_allowed_to_reset() Invalid username: '" + str(userName) + "'.") #!Debugging
			return default_allow
		# Initialize Variable(s)
		rlv = []
		# Iterate Challenges
		ts = Challenges.query
		for c in ts.all():
			print("[DEBUG]: get_visible_challenges_allowed_to_reset() is testing Challenge ID: " + str(c.id) + "\tType: "  + str(c.type) + "\tState: " + str(c.state) + ".") #!Debugging
			if(str(c.state) != "visible"):
				continue;
			can_reset = ResetChallengeRules.is_reset_allowed(userID=userID, userName=userName, challengeID=c.id, challengeName=c.name, category=c.category, default_allow=default_allow)
			reset_data = {"id":c.id,"category":c.category,"canReset":can_reset}
			rlv.append(reset_data)
		return rlv
	@staticmethod
	def get_visible_categories_allowed_to_reset(challengeResetList:list) -> list:
		# Uses List from get_visible_challenges_allowed_to_reset() to get all visible categories that can be reset.
		# Returns List on success.
		rlv = []
		for r in challengeResetList:
			if(not r["canReset"]):
				continue
			next_cat = r["category"]
			try:
				cat_index = rlv.index(next_cat)
				continue
			except ValueError:
				# We don't already have this category
				rlv.append(next_cat)
		return rlv
	@staticmethod
	def set_priority(p_rid: int, p_priority: int) -> None:
		#Requires active db session.
		#Modifies rule by id where priority now equals priority.
		rid = int(p_rid)
		p = int(p_priority)
		#Clamp priority value.
		if(p < 0):
			p = 0
		elif(p > ResetChallengeRules.MAX_PRIORITY):
			p = ResetChallengeRules.MAX_PRIORITY
		#Do update
		ts = ResetChallengeRules.query.filter(ResetChallengeRules.id == rid)
		ts.update({"priority":p})
		db.session.commit()
		db.session.close()
	@staticmethod
	def increase_priority(rid: int, step: int = 1) -> None:
		#Requires active db session.
		#Modifies rule by id where priority is increased relative to next highest rule(s) by step amount.
		rid = int(rid)
		step = int(step)
		ts = ResetChallengeRules.query.order_by(ResetChallengeRules.priority.desc())
		lastHighestPriority = -1
		for r in ts.all():
			if(str(r.id) == str(rid)):
				break
			else:
				lastHighestPriority = r.priority
		db.session.close()
		if(lastHighestPriority >= 0):
			ResetChallengeRules.set_priority(p_rid=rid,p_priority=(lastHighestPriority + step))
	@staticmethod
	def decrease_priority(rid: int, step: int = 1) -> None:
		#Requires active db session.
		#Modifies rule by id where priority is decreased relative to next lowest rule(s) by step ammount.
		rid = int(rid)
		step = int(step)
		ts = ResetChallengeRules.query.order_by(ResetChallengeRules.priority.asc())
		lastLowestPriority = -1
		for r in ts.all():
			if(str(r.id) == str(rid)):
				break
			else:
				lastLowestPriority = r.priority
		db.session.close()
		if(lastLowestPriority >= 0):
			ResetChallengeRules.set_priority(p_rid=rid,p_priority=(lastLowestPriority - step))

