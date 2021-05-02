from marshmallow import fields
from marshmallow.validate import Length
from flaskbb.extensions import ma
from flaskbb.user.models import User


class UserRegistrationInputSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = True

    username = fields.String()
    password = fields.String(load_only=True, repr=False, validate=Length(min=8))
    email = fields.String()
    language = fields.String()
    group = fields.Int(missing=4, attribute="primary_group_id")
