from .models import UserProfile


class CustomSystemAdminAuth(object):

    def authenticate(self, username=None, password=None):
        try:
            user = UserProfile.objects.get(email=username)
            if user.check_password(password) and user.is_superuser:
                return user
        except UserProfile.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            user = UserProfile.objects.get(pk=user_id)
            if user is not None:
                if user.is_active:
                    return user
                else:
                    return None
            return None
        except UserProfile.DoesNotExist:
            return None
