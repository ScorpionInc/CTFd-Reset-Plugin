#!/usr/bin/env python3

from flask import session

from CTFd.cache import clear_challenges
from CTFd.models import db, Submissions, Challenges, Awards, Solves, Fails
from CTFd.utils.user import authed, is_admin

from .ResetChallengeRules import *
from .ResetChallengeStats import *
from .ResetChallengeAPI import *

class ResetChallenge(object):
	#@classmethod
	@staticmethod
	def reset(userid: int, challengeid: int) -> None:
		#Deletes correct submission for specific challenge for user from database.
		print("[DEBUG]: reset() Called. UserID Parameter: '" + str(type(userid)) + "':" + str(userid) + " \tChallengeID Parameter: '" + str(type(challengeid)) + "':" + str(challengeid) + ".") #!Debugging
		#Validate user session
		if(not authed()):
			return
		if(session["id"] != userid):
			#Trying to reset someone elses challenges...
			if(is_admin()):
				#Admin can reset anyone
				pass
			else:
				#Log Attempt(?)
				print("[WARN]: Reset was blocked due to resetee not matching reseter.") #!Debugging
				return
		#Validate rules
		if(not ResetChallengeRules.is_reset_allowed(userID=userid,challengeID=challengeid)):
			print("[DEBUG]: reset() was blocked by Rules for user: " + str(userid) + " on challenge: " + str(challengeid) + ".") #!Debugging
			return
		args = {"challenge_id":challengeid, "user_id":userid, "type":"correct"}
		ts = Submissions.query.filter_by(**args)
		print("[DEBUG]: Awards Value: '" + str(Awards.query.all()) + "'.") #!Debugging
		print("[DEBUG]: Solves Value: '" + str(Solves.query.all()) + "'.") #!Debugging
		print("[DEBUG]: Fails  Value: '" + str(Fails.query.all())  + "'.") #!Debugging
		print("[DEBUG]: Submissions Query: '" + str(ts) + "' \tValue: '" + str(ts.all()) + "'.") #!Debugging
		for s in ts.all():
			db.session.delete(s)
		ResetChallengeStats.step_counter_by_ids(cid=challengeid,uid=userid)
		db.session.commit()
		db.session.close()
		clear_challenges()
	@staticmethod
	def resetCategory(category: str, userid: int) -> None:
		#Deletes all correct submissions made by user in category from database.
		#Validate user session
		if(not authed()):
			return
		if(session["id"] != userid):
			#Trying to reset someone elses challenges...
			if(is_admin()):
				#Admin can reset anyone
				pass
			else:
				#Log Attempt(?)
				print("[WARN]: Reset Category was blocked due to resetee not matching reseter.") #!Debugging
				return
		#Do Reset
		#print("[DEBUG]: resetCategory() called, category: '" + str(category) + "' userid: '" + str(userid) + "'.") #!Debugging
		args = {"user_id":userid, "type":"correct"}
		userName = ResetChallengeRules.find_user_by_id(userid).name
		argsc = {"category":category}
		ts = Submissions.query.filter_by(**args).join(Challenges).filter_by(**argsc)
		#print("[DEBUG]: Submissions Query: '" + str(ts) + "' \tValue: '" + str(ts.all()) + "'.") #!Debugging
		for s in ts.all():
			#Validate rules
			if(not ResetChallengeRules.is_reset_allowed(userID=userid,userName=userName,challengeID=s.challenge_id,category=category)):
				continue
			db.session.delete(s)
		db.session.commit()
		db.session.close()
		clear_challenges()
	@staticmethod
	def resetAll(userid: int) -> None:
		#Deletes all correct submissions made by user from database.
		#Validate user session
		if(not authed()):
			return
		if(session["id"] != userid):
			#Trying to reset someone elses challenges...
			if(is_admin()):
				#Admin can reset anyone
				pass
			else:
				#Log attempt(?)
				print("[WARN]: ResetChallenge.resetAll() was called with mismatching userID. Is someone trying to do a heckin hax?") #!Debugging
				return
		#Do Reset
		args = {"user_id":userid, "type":"correct"}
		userName = ResetChallengeRules.find_user_by_id(userid).name
		ts = Submissions.query.filter_by(**args)
		for s in ts.all():
			print("[DEBUG]: resetAll() s: '"+str(s)+"'.") #!Debugging
			#Validate Rules
			if(not ResetChallengeRules.is_reset_allowed(userID=userid,userName=userName,challengeID=s.challenge_id)):
				continue
			db.session.delete(s)
		db.session.commit()
		db.session.close()
		clear_challenges()
