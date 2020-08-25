from marshmallow import fields
from flaskbb.extensions import ma


class UserBasicSchema(ma.Schema):
    id = fields.Int()
    username = fields.String()
    email = fields.Str()
    language = fields.Str()
    postCount = fields.Int(attribute='post_count')
    activated = fields.Bool()
