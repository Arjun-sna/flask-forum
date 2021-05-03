from marshmallow import fields
from flaskbb.extensions import ma, db

from flaskbb.forum.models import Forum
from flaskbb.user.models import Group


class GroupSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Group
        load_instance = True
        sqla_session = db.session


class ForumInputSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Forum
        load_instance = True
        sqla_session = db.session

    category_id = fields.Integer()
    title = fields.String()
    description = fields.String()
    position = fields.Integer()
    locked = fields.Boolean()
    show_moderators = fields.Boolean()
    external = fields.String()
    groups = fields.Nested("GroupSchema", many=True, only=('id',))


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
