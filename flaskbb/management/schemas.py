from marshmallow import fields
from flaskbb.extensions import ma


class ForumInputSchema(ma.SQLAlchemySchema):
    class Meta:
        load_instance = True


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
