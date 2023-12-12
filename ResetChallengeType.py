#!/usr/bin/env python3

import os

# Path requires Python version 3.4+
from pathlib import Path

from flask import Blueprint

from CTFd.models import db, Challenges
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.plugins.migrations import upgrade

from .ResetChallengeRules import *

class ResetableChallenge(Challenges):
	__mapper_args__ = {"polymorphic_identity": "resetable"}
	id = db.Column(db.Integer, db.ForeignKey('challenges.id', ondelete="CASCADE"), primary_key=True)
	def __init__(self, *args, **kwargs):
		self.value = 0
		super(ResetableChallenge, self).__init__(**kwargs)
	#def __init__(self, name, description, value, category, type='resetable'):
	#	self.name = name
	#	self.description = description
	#	self.value = value
	#	self.category = category
	#	self.type = type

class ResetableBaseChallenge(BaseChallenge):
	@staticmethod
	def get_absolute_plugin_path() -> str:
		# Returns current plugins path on success.
		return Path(__file__).parent.resolve()
	@classmethod
	def get_plugin_folder_name(cls) -> str:
		# Returns string of the directory name containing current script.
		return cls.get_absolute_plugin_path().name
	@classmethod
	def get_relative_plugin_asset_path(cls) -> str:
		# Returns the relative string path to this plugins assets directory
		base_path = os.path.join("plugins", cls.get_plugin_folder_name(), "assets")
		slash_char = base_path[7:8:1]
		return (slash_char + base_path + slash_char)
	id = "resetable"
	name = "resetable"
	#route = get_relative_plugin_asset_path()
	route = "/" + os.path.join("plugins", get_absolute_plugin_path().name, "assets") + "/"
	templates = (
		{
			"create":(route + "html/create.html"),
			"update":(route + "html/update.html"),
			"view"  :(route + "html/view.html"  ),
		}
	)
	scripts = {
		"create":(route + "js/create.js"),
		"update":(route + "js/update.js"),
		"view"  :(route + "js/view.js"  ),
	}
	challenge_model = ResetableChallenge
	blueprint = Blueprint(
		"resetChallengeType",
		__name__,
		template_folder="templates",
		static_folder="assets",
	)
	"""
	@classmethod
	def create(cls, request):
		print("[DEBUG]: ResetableBaseChallenge.create() was called.") #!Debugging
		return super().create(request)
		#data = request.form or request.get_json()
		#challenge = cls.challenge_model(**data)
		#db.session.add(challenge)
		#db.session.commit()
		#return challenge
	"""
	@classmethod
	def read(cls, challenge):
		print("[DEBUG]: ResetableBaseChallenge.read() was called.") #!Debugging
		#print("[DEBUG]: challenge: " + str(challenge)) #!Debugging
		#print("[DEBUG]: challenge.id: " + str(challenge.id)) #!Debugging
		#print("[DEBUG]: cls.challenge_model All Contents: ", cls.challenge_model.query.all()) #!Debugging
		args = { "id":challenge.id }
		c = cls.challenge_model.query.filter_by(**args).first()  # id=challenge.id
		if c is None:
			print("[WARN]: Reading Resetable challenge information failed(?).") #!Debugging
			data = {
				"id":             challenge.id,
				"name":           challenge.name,
				"value":          challenge.value,
				"description":    challenge.description,
				"connection_info":challenge.connection_info,
				"next_id":        challenge.next_id,
				"category":       challenge.category,
				"state":          challenge.state,
				"max_attempts":   challenge.max_attempts,
				"type":           challenge.type,
				"can_reset":      "True",
				"type_data":      {
					"id":         cls.id,
					"name":       cls.name,
					"templates":  cls.templates,
					"scripts":    cls.scripts,
				},
			}
		else:
			data = {
				"id":             c.id,
				"name":           c.name,
				"value":          c.value,
				"description":    c.description,
				"connection_info":c.connection_info,
				"next_id":        c.next_id,
				"category":       c.category,
				"state":          c.state,
				"max_attempts":   c.max_attempts,
				"type":           c.type,
				"can_reset":      "True",
				"type_data":      {
					"id":         cls.id,
					"name":       cls.name,
					"templates":  cls.templates,
					"scripts":    cls.scripts,
				},
			}
		return data
	@classmethod
	def update(cls, challenge, request):
		print("ResetableBaseChallenge.update() was called.") #!Debugging
		data = request.form or request.get_json()
		for k,v in data.items():
			if k in ("can_reset",):
				# Can't set a read-only value.
				continue
			setattr(challenge, k, v)
		db.session.commit()
		return challenge
	"""
	@classmethod
	def delete(cls, challenge):
		print("[DEBUG]: ResetableBaseChallenge.delete() was called.") #!Debugging
		return super().delete(challenge)
	@classmethod
	def attempt(cls, challenge, request):
		print("[DEBUG]: ResetableBaseChallenge.attempt() was called.") #!Debugging
		return super().attempt(challenge, request)
	@classmethod
	def solve(cls, team, challenge, request):
		print("[DEBUG]: ResetableBaseChallenge.solve() was called.") #!Debugging
		return super().solve(team, challenge, request)
	@classmethod
	def fail(cls, team, challenge, request):
		print("[DEBUG]: ResetableBaseChallenge.fail() was called.") #!Debugging
		return super().fail(team, challenge, request)
	"""

def load_type(app):
	app.db.create_all()
	upgrade(plugin_name=ResetableBaseChallenge.get_plugin_folder_name())
	CHALLENGE_CLASSES[str(ResetableBaseChallenge.id)] = ResetableBaseChallenge
