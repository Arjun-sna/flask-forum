from flask.views import MethodView
from flaskbb.extensions import allows

from flaskbb.forum.models import Category
from ..schemas import CategorySchema

category_schema = CategorySchema()


class Forum(MethodView()):
    decorators = [
        allows.requires(
            IsAdmin,
            on_fail=FlashAndRedirect(
                message=_("You are not allowed to modify forums."),
                level="danger",
                endpoint="management.overview"
            )
        )
    ]

    def get(self):
        categories = Category.query.order_by(Category.position.asc()).all()
        return category_schema.dump(categories)
