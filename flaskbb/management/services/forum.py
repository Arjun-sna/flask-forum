from ..schemas import ForumInputSchema
from ...forum.models import Forum, Category
from ...user.models import Group
from ...core.exceptions import ValidationError


class ForumManager():
    def __init__(self):
        self.forum_input_schema = ForumInputSchema()

    def validate_category(self, category_id):
        category = Category.query.get(category_id)

        if not category:
            raise ValidationError(
                "category", "The provided category does not exist")

        return category

    def fetch_groups(self, groups_ids):
        groups = Group.query.filter(Group.id.in_(groups_ids)).all()
        if len(groups_ids) != len(groups):
            raise ValidationError(
                "groups", "The provided groups either does not exist or not active")
        return groups

    def addForum(self, forum_data):
        data = self.forum_input_schema.load(forum_data)
        data['category'] = self.validate_category(data['category'])
        data['groups'] = self.fetch_groups(data['groups'])
        return self.save(data)

    def save(self, forum_data):
        forum = Forum(**forum_data)
        return forum.save()
