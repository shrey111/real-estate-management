from bootstrap_modal_forms.mixins import PopRequestMixin, CreateUpdateAjaxMixin
from django import forms

from .models import UserProfile, Property, PropertyImages, RoleCode, RolePermission, PermissionType, UserRole, \
    Advertisement, City, Country, Province
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, UserChangeForm


class LoginForm(forms.Form):
    username = forms.CharField(error_messages={'required': 'Please enter a valid email'}, widget=forms.EmailInput(
        attrs={"placeholder": "Username",
               "class": "form-control",
               "name": "username",
               "id": "username"}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "placeholder": "Password",
        "class": "form-control",
        "name": "password",
        "id": "password"
    }), error_messages={'required': 'Please enter password'})

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        try:
            user = UserProfile.objects.get(email=username)
            if user.check_password(password):
                return user
            else:
                raise forms.ValidationError("Password does not match, please try again")
        except UserProfile.DoesNotExist:
            raise forms.ValidationError("Username does not match, please try again")


class UserCreateForm(UserCreationForm):
    class Meta:
        model = UserProfile
        fields = ["first_name", "last_name", "email", "username"]


class UserCreateSystemForm(PopRequestMixin, CreateUpdateAjaxMixin, UserCreationForm):
    class Meta:
        model = UserProfile
        fields = ["first_name", "last_name", "email", "username"]


class PropertyCreateForm(PopRequestMixin, CreateUpdateAjaxMixin, forms.ModelForm):
    class Meta:
        model = Property
        exclude = ['users']


class PropertyMainCreateForm(forms.ModelForm):
    class Meta:
        model = Property
        exclude = ['users']


class PropertyImageForm(forms.ModelForm):
    class Meta:
        model = PropertyImages
        exclude = ['propertyID']


class CustomUserChangeForm(PopRequestMixin, CreateUpdateAjaxMixin, UserChangeForm):

    class Meta:
        model = UserProfile
        fields = ["first_name", "last_name", "email", "username"]

    def clean_password(self):
        return self.initial["password"]


class RoleForm(PopRequestMixin, CreateUpdateAjaxMixin, forms.ModelForm):
    class Meta:
        model = RoleCode
        fields = ["roleCodeID", "name"]


class PermissionForm(PopRequestMixin, CreateUpdateAjaxMixin, forms.ModelForm):
    class Meta:
        model = PermissionType
        fields = ["permissionTypeID", "name"]


class UserRoleForm(forms.ModelForm):
    role = forms.ModelChoiceField(queryset=RoleCode.objects.all())

    class Meta:
        model = UserRole
        fields = ["dateAssigned"]

    def __init__(self, *args, **kwargs):
        if kwargs.get('instance'):
            initial = kwargs.setdefault('initial', {})

            if kwargs['instance'].rolecode_set.all():
                initial['role'] = kwargs['instance'].rolecode_set.all()[0]
            else:
                initial['role'] = None
        forms.ModelForm.__init__(self, *args, **kwargs)


class RolePermissionForm(forms.ModelForm):
    permissions = forms.ModelMultipleChoiceField(queryset=PermissionType.objects.all())

    class Meta:
        model = RolePermission
        fields = ["dateAssigned"]

    def __init__(self, *args, **kwargs):
        if kwargs.get('instance'):
            initial = kwargs.setdefault('initial', {})

            if kwargs['instance'].permissiontype_set.all():
                initial['permissions'] = kwargs['instance'].permissiontype_set.all()
            else:
                initial['permissions'] = None
        forms.ModelForm.__init__(self, *args, **kwargs)


class Advertise(forms.ModelForm):
    users = forms.ModelChoiceField(queryset=UserProfile.objects.all().filter(is_active=True))

    class Meta:
        model = Advertisement
        fields = ["dateCreated"]

    def __init__(self, *args, **kwargs):
        if kwargs.get('instance'):
            initial = kwargs.setdefault('initial', {})

            if kwargs['instance'].users.select_related():
                initial['users'] = kwargs['instance'].users.select_related()[0]
            else:
                initial['users'] = None
        forms.ModelForm.__init__(self, *args, **kwargs)


class CountryForm(PopRequestMixin, CreateUpdateAjaxMixin, forms.ModelForm):
    class Meta:
        model = Country
        fields = '__all__'


class ProvinceForm(PopRequestMixin, CreateUpdateAjaxMixin, forms.ModelForm):
    class Meta:
        model = Province
        fields = '__all__'


class CityForm(PopRequestMixin, CreateUpdateAjaxMixin, forms.ModelForm):
    class Meta:
        model = City
        fields = '__all__'
