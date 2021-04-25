from marshmallow import fields
from flaskbb.extensions import ma


class UserProfileSchema(ma.Schema):
    id = fields.Integer()
    username = fields.String()
    email = fields.String()
    language = fields.String()
    group = fields.Int(missing=4, attribute="primary_group_id")
    lastseen = fields.DateTime()
    birthday = fields.DateTime()
    gender = fields.String()
    website = fields.String()
    location = fields.String()
    avatar = fields.String()
    notes = fields.String()
    post_count = fields.Integer()
    days_registered = fields.Integer()


class UserProfileFullSchema(UserProfileSchema):
    last_failed_login = fields.DateTime()
    login_attempts = fields.DateTime()
    activated = fields.Boolean()
    theme = fields.String()
    language = fields.String()
    date_joined = fields.DateTime()
