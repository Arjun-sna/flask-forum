from sqlalchemy.orm.session import make_transient, make_transient_to_detached

from ..schemas import ForumInputSchema, ForumUpdateSchema
from ...forum.models import Forum, Category
from ...user.models import Group
from ...core.exceptions import ValidationError


class ForumManager():
    def __init__(self):
        self.forum_input_schema = ForumInputSchema()
        self.forum_update_schema = ForumUpdateSchema()

    def __fetch_category(self, category_id):
        category = Category.query.get(category_id)

        if not category:
            raise ValidationError(
                "category", "The provided category does not exist")

        return category

    def __fetch_groups(self, groups_ids):
        groups = Group.query.filter(Group.id.in_(groups_ids)).all()
        if len(groups_ids) != len(groups):
            raise ValidationError(
                "groups", "The provided groups either does not exist or not active")
        return groups

    def addForum(self, forum_data):
        data = self.forum_input_schema.load(forum_data)
        data['category'] = self.__fetch_category(data['category'])
        data['groups'] = self.__fetch_groups(data['groups'])
        return self.save(data)

    def updateForum(self, forum_data):
        data = self.forum_update_schema.load(forum_data)
        if 'category' in data:
            data['category'] = self.__fetch_category(data['category'])
        if 'groups' in data:
            data['groups'] = self.__fetch_groups(data['groups'])
        return self.save(data, transient=True)

    def save(self, forum_data, transient=False):
        forum = Forum(**forum_data)
        return forum.save()
