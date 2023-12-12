#!/usr/bin/env python3

from CTFd.models import db

class ResetChallengeStats(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	challenge_id = db.Column(db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"))
	user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
	reset_count = db.Column(db.Integer)
	solve_count = db.Column(db.Integer)
	fail_count = db.Column(db.Integer)
	def __init__(self, challenge_id: int, count: int):
		self.challenge_id = challenge_id
		self.count = count
	@staticmethod
	def has_stats_by_ids(cid: int, uid: int) -> bool:
		# Returns True when an entry for challenge by cid for user by userid exists within stats table.
		# Returns False otherwise.
		args = {"challenge_id":cid,"user_id":uid}
		ts = ResetChallengeStats.query.filter_by(**args)
		return (len(ts.all()) > 0)
	@staticmethod
	def get_solve_count_by_ids(cid:int, uid:int) -> int:
		#TODO
		pass
	@staticmethod
	def get_fail_count_by_ids(cid:int, uid:int) -> int:
		#TODO
		pass
	@staticmethod
	def generate_next_stats_by_ids(cid:int, uid:int):
		#TODO
		# Returns object containing stats of next reset for challenge of id cid and user of uid.
		# Returns None on error.
		args = {"challenge_id":cid,"user_id":uid}
		ts = ResetChallengeStats.query.filter_by(**args).all()
		ts_len = len(ts)
		if(ts_len <= 0):
			# Generate new object value.
			return {"reset_count":1,"solve_count":(0),"fail_count":(0)}
		if(ts_len > 1):
			print("[WARN]: ResetChallengeStats.generate_next_stats_by_ids() encountered multiple results.") #!Debugging
		ts = ts[0]
		# Return modified entry value.
		return {"reset_count":(ts.reset_count + 1),"solve_count":(ts.solve_count+0),"fail_count":(ts.solve_count+0)}
	@staticmethod
	def step_counter_by_ids(cid: int, uid: int, step_amount:int = 1) -> None:
		# Increases count value for entries in stats table where challenge_id = cid
		print("[DEBUG]: ResetChallengeStats.step_counter_by_challenge_id() was called.") #!Debugging
		args = {"challenge_id":cid,"user_id":uid}
		ts = ResetChallengeStats.query.filter_by(**args)
		ss = ts.all()
		if(len(ss) <= 0):
			# No counter exists for challenge of id.
			print("[DEBUG]: Challenge stats for id: " + str(cid) + " was not found! Creating entry with value: '" + str(step_amount) + "'.") #!Debugging
			stat = ResetChallengeStats(challenge_id=cid, user_id=uid, count=step_amount)
			db.session.add(stat)
		else:
			# At least one entry has matching challenge id. (Should only have one.)
			for s in ss:
				new_count = (s.count + step_amount)
				print("[DEBUG]: Found challenge stats entry[" + str(s.id) + "] with count: " + str(s.count) + "\t new count: " + str(new_count) + ".") #!Debugging
				ResetChallengeStats.query.filter_by(**args).update({"count":new_count})
		db.session.commit()
		db.session.close()
