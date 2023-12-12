#Reference Code: ./CTFd/api/v1/submissions.py
#Access API: http://127.0.0.1:8000/api/v1/resets

from marshmallow import fields
from flask_restx import Namespace, Resource

from CTFd.api import CTFd_API_v1
from CTFd.api.v1.helpers.request import validate_args
from CTFd.api.v1.helpers.schemas import sqlalchemy_to_pydantic
from CTFd.api.v1.schemas import (APIDetailedSuccessResponse, PaginatedAPIListSuccessResponse,)
from CTFd.models import db #TODO
from CTFd.schemas.challenges import ChallengeSchema
from CTFd.schemas.submissions import SubmissionSchema
from CTFd.schemas.teams import TeamSchema
from CTFd.schemas.users import UserSchema
from CTFd.utils.decorators import admins_only

from .ResetChallengeStats import *

resetchallenge_namespace = Namespace("resets", description="Endpoint to Submission Reset Data")
ResetChallengeStatsModel = sqlalchemy_to_pydantic(ResetChallengeStats)
TransientResetChallengeModel = sqlalchemy_to_pydantic(ResetChallengeStats, exclude=["id"])

class ResetStatsDetailedSuccessResponse(APIDetailedSuccessResponse):
	data: ResetChallengeStatsModel
class ResetStatsListSuccessResponse(PaginatedAPIListSuccessResponse):
	data: TransientResetChallengeModel

resetchallenge_namespace.schema_model("ResetStatsDetailedSuccessResponse", ResetStatsDetailedSuccessResponse.apidoc())
resetchallenge_namespace.schema_model("ResetStatsListSuccessResponse", ResetStatsListSuccessResponse.apidoc())

from CTFd.models import ma
class ResetChallengeStatSchema(ma.ModelSchema):
	submission = fields.Nested(ChallengeSchema, only=["id", "name", "category", "value"])
	class Meta:
		model = ResetChallengeStats
		include_fk = True
		dump_only = ("id",)
	def __init__(self, *args, **kwargs):
		super(ResetChallengeStatSchema, self).__init__(*args, **kwargs)

@resetchallenge_namespace.route("")
class ResetStatsList(Resource):
	@admins_only
	@resetchallenge_namespace.doc(
		description="Endpoint to get ResetStatsObj objects in bulk",
		responses={
			200: ("Success", "ResetStatsListSuccessResponse"),
			400: (
				"An error occured processing the provided or stored data",
				"APISimpleErrorResponse",
			),
		},
	)
	@validate_args(
		{
			"challenge_id": (int, None),
		},
		location="query",
	)
	def get(self, query_args):
		print("[DEBUG]: ResetStatsList.get() was called, query_args: '" + str(query_args) + "'.") #!Debugging
		rcs = (ResetChallengeStats.query.paginate(max_per_page=100))
		schema = ResetChallengeStatSchema(many=True)
		response = schema.dump(rcs.items)
		if response.errors:
			return {"success": False, "errors": response.errors}, 400
		return {
            "meta": {
                "pagination": {
                    "page": rcs.page,
                    "next": rcs.next_num,
                    "prev": rcs.prev_num,
                    "pages": rcs.pages,
                    "per_page": rcs.per_page,
                    "total": rcs.total,
                }
            },
            "success": True,
            "data": response.data,
        }
	def post(self, json_args):
		print("[DEBUG]: ResetStatsList.post() was called, json_args: '" + str(json_args) + "'.") #!Debugging

@resetchallenge_namespace.route("/<resetchallengestats_id>")
@resetchallenge_namespace.param("resetchallengestats_id", "A Reset Challenge Stats ID")
class ResetStatsObj(Resource):
	@admins_only
	@resetchallenge_namespace.doc(
		description="Endpoint to get a ResetStatsObj object",
		responses={
			200: ("Success", "ResetStatsDetailedSuccessResponse"),
			400: (
				"An error occured processing the provided or stored data",
				"APISimpleErrorResponse",
			),
		},
	)
	def get(self, resetchallengestats_id):
		print("[DEBUG]: ResetStatsObj.get() was called with id: '" + str(resetchallengestats_id) + "'.") #!Debugging
	@admins_only
	@resetchallenge_namespace.doc(
		description="Endpoint to edit a ResetStatsObj object",
		responses={
			200: ("Success", "ResetStatsDetailedSuccessResponse"),
			400: (
				"An error occured processing the provided or stored data",
				"APISimpleErrorResponse",
			),
		},
	)
	def patch(self, resetchallengestats_id):
		print("[DEBUG]: ResetStatsObj.patch() was called with id: '" + str(resetchallengestats_id) + "'.") #!Debugging
	@admins_only
	@resetchallenge_namespace.doc(
		description="Endpoint to delete a ResetStatsObj object",
		responses={
			200: ("Success", "APISimpleSuccessResponse"),
			400: (
				"An error occured processing the provided or stored data",
				"APISimpleErrorResponse",
			),
		},
	)
	def delete(self, resetchallengestats_id):
		print("[DEBUG]: ResetStatsObj.delete() was called with id: '" + str(resetchallengestats_id) + "'.") #!Debugging

CTFd_API_v1.add_namespace(resetchallenge_namespace, "/resets")
