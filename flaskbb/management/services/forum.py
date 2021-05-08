from sqlalchemy.orm.session import make_transient, make_transient_to_detached

from ..schemas import ForumInputSchema, ForumUpdateSchema, CategorySchema
from ...forum.models import Forum, Category, Topic, Post
from ...user.models import Group, User
from ...core.exceptions import ValidationError


class ForumManager():
    def __init__(self):
        self.forum_input_schema = ForumInputSchema()
        self.forum_update_schema = ForumUpdateSchema()
        self.category_schema = CategorySchema(many=True)

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

    def get_all_forums(self):
        categories = Category.query.order_by(Category.position.asc()).all()
        return self.category_schema.dump(categories)

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

    def delete_forum(self, forum_id):
        forum = Forum.query.filter_by(id=forum_id).first()
        if not forum:
            raise ValidationError('Forum', 'Forum not found')

        involved_users = User.query.filter(
            Topic.forum_id == forum.id, Post.user_id == User.id).all()

        forum.delete(involved_users)

    def save(self, forum_data, transient=False):
        forum = Forum(**forum_data)
        if transient:
            make_transient(forum)
            make_transient_to_detached(forum)
        return forum.save()
