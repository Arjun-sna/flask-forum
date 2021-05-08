from marshmallow import fields
from marshmallow.validate import Length
from flaskbb.extensions import ma, db

from flaskbb.forum.models import Forum, Category
from flaskbb.user.models import Group


class ForumInputSchema(ma.Schema):
    category = fields.Integer(required=True)
    title = fields.String(required=True, validate=Length(3))
    description = fields.String(required=True, validate=Length(5))
    position = fields.Integer(default=1)
    locked = fields.Boolean(default=False)
    show_moderators = fields.Boolean(default=False)
    external = fields.String()
    groups = fields.List(fields.Integer(), required=True,
                         validate=Length(min=1))


class ForumUpdateSchema(ma.Schema):
    id = fields.Integer(required=True)
    category = fields.Integer()
    title = fields.String(validate=Length(3))
    description = fields.String(validate=Length(5))
    position = fields.Integer()
    locked = fields.Boolean()
    show_moderators = fields.Boolean()
    external = fields.String()
    groups = fields.List(fields.Integer(), validate=Length(min=1))


class ForumSchema(ma.Schema):
    id = fields.Integer()
    title = fields.String()
    description = fields.String()
    position = fields.Integer()
    locked = fields.Boolean()
    show_moderators = fields.Boolean()
    post_count = fields.Integer()
    topic_count = fields.Integer()
    last_post_title = fields.String()
    last_post_username = fields.String()
    last_post_created = fields.DateTime()


class CategorySchema(ma.Schema):
    id = fields.Integer()
    title = fields.String()
    description = fields.String()
    position = fields.Integer()
    forums = fields.List(fields.Nested(ForumSchema))
