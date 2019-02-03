from django.contrib import admin

from .models import Property, PropertyCategory, PropertySector, PropertyFacing, PropertyImages, Country, City, Province

from .models import UserProfile, Advertisement
from django.contrib.auth.admin import UserAdmin
from .forms import UserCreateForm


class CustomUserAdmin(UserAdmin):
    model = UserProfile
    add_form = UserCreateForm
    form = UserCreateForm

# Register your models here.


admin.site.register(Property)
admin.site.register(PropertyCategory)
admin.site.register(PropertySector)
admin.site.register(PropertyFacing)
admin.site.register(PropertyImages)
admin.site.register(Country)
admin.site.register(Province)
admin.site.register(City)
admin.site.register(UserProfile, CustomUserAdmin)
admin.site.register(Advertisement)
