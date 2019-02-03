import csv, io
import random, string

from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic import CreateView, DeleteView, UpdateView
from django.core.mail import EmailMessage
from eproperty.backends import CustomUserAuth
from eproperty.systembackends import CustomSystemAdminAuth
from eproperty.tokens import account_activation_token
from .models import PropertyImages, Property, UserProfile, Advertisement, Country, Province, City, PropertyCategory, PropertyFacing, PropertySector, UserRole, PermissionType, RolePermission, RoleCode
from django.contrib.messages.views import SuccessMessageMixin
from django.urls import reverse_lazy
from bootstrap_modal_forms.mixins import PassRequestMixin, DeleteAjaxMixin
from .forms import LoginForm, UserCreateForm, PropertyCreateForm, PropertyImageForm, PermissionForm, RolePermissionForm, \
    UserRoleForm, CustomUserChangeForm, RoleForm, Advertise, UserCreateSystemForm, PropertyMainCreateForm, CountryForm, \
    ProvinceForm, CityForm
from django.db.models import Q

# Create your views here.


def home(request):
    obj = PropertyImages.objects.all().select_related('propertyID')
    context = {
        'object': obj
    }
    return render(request, 'property/home.html', context)


def about(request):
    return render(request, 'property/about.html')


def thankyou(request):
    return render(request, 'property/thankyou.html')


def advertise(request):
    obj = PropertyImages.objects.all().select_related('propertyID').filter(propertyID__advertisement__user=request.user)
    context = {
        'object': obj
    }
    return render(request, 'property/advertise.html', context)


@csrf_exempt
def login(request):
    template_name = 'property/login.html'
    if request.method == 'POST':
        my_form = LoginForm(request.POST)
        if my_form.is_valid():
            username = request.POST.get('username', '')
            password = request.POST.get('password', '')
            user = CustomUserAuth.authenticate(request, username=username, password=password)
            if user is not None and user.is_active:
                auth.login(request, user)
                return HttpResponseRedirect('/advertise/')
            else:
                print("else")
                return render(request, template_name, {'form': my_form, 'password_is_wrong': True})
        else:
            return render(request, template_name, {'form': my_form})

    else:
        my_form = LoginForm()
        return render(request, template_name, {'form': my_form})


@csrf_exempt
def register(request):
    if request.method == 'POST':
        form = UserCreateForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('property/acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'token': account_activation_token.make_token(user),
            })
            to_email = settings.ADMIN_EMAIL
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            return HttpResponseRedirect(reverse_lazy('thankyou'))
        else:
            return render(request, 'property/signup.html', {'form': form})
    else:
        form = UserCreateForm()
        return render(request, 'property/signup.html', {'form': form})


def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(data=request.POST, user=request.user)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return redirect('/advertise/')
        else:
            return render(request, 'property/change_password.html', {'form': form})
    else:
        form = PasswordChangeForm(user=request.user)
        context = {'form': form}
        return render(request, 'property/change_password.html', context)


def create_property(request):
    user = UserProfile.objects.get(pk=request.user.userID)
    if request.method == 'POST':
        form1 = PropertyMainCreateForm(request.POST)
        form2 = PropertyImageForm(request.POST)
        if form1.is_valid() and form2.is_valid():
            property_obj = form1.save(commit=True)
            image_obj = form2.save(commit=False)
            image_obj.ImageName = request.FILES['ImageName']
            image_obj.propertyID = property_obj
            image_obj.save()

            advertisement_obj = Advertisement(property=property_obj, user=user)
            advertisement_obj.save()
            return redirect('/advertise/')
    else:
        form1 = PropertyMainCreateForm()
        form2 = PropertyImageForm()
        context = {'form1': form1, 'form2': form2}
        return render(request, 'property/create_property.html', context)


def property_detail(request, id):
    obj = PropertyImages.objects.select_related('propertyID').get(propertyID_id=id)
    userobj = obj.propertyID.users.get()
    context = {'object': obj, 'user_obj': userobj}
    return render(request, 'property/property_detail.html', context)


class PropertyDelete(DeleteAjaxMixin, DeleteView):
    model = Property
    template_name = 'property/delete_property.html'
    success_message = 'Success: Property was deleted.'
    success_url = reverse_lazy('advertise')


def update_property(request, id):
    user = UserProfile.objects.get(pk=request.user.userID)
    instance = get_object_or_404(Property, pk=id)
    instance1 = get_object_or_404(PropertyImages, propertyID=instance)
    form1 = PropertyMainCreateForm(request.POST or None, instance=instance)
    form2 = PropertyImageForm(request.POST or None, instance=instance1)
    if request.method == 'POST':
        if form1.is_valid() and form2.is_valid():
            property_obj = form1.save(commit=False)
            property_obj.save()

            if request.FILES:
                image_obj = form2.save(commit=False)
                image_obj.ImageName = request.FILES['ImageName']
                image_obj.propertyID = property_obj
                image_obj.save()
            else:
                form2.save()

            advertisement_obj = Advertisement(property=property_obj, user=user)
            advertisement_obj.save()
            return redirect('/advertise/')
    else:
        context = {'form1': form1, 'form2': form2}
        return render(request, 'property/update_property.html', context)


def search(request):
    if request.method == 'GET':
        query = request.GET.get('q')
        if query is not None and query:
            lookups = Q(propertyID__propertyTitle__icontains=query) | \
                      Q(propertyID__propertyCountry__countryName__iexact=query) | \
                      Q(propertyID__propertyProvince__provinceName__iexact=query) | \
                      Q(propertyID__propertyCity__cityName__iexact=query) | \
                      Q(propertyID__propertyCategory__CategoryName__icontains=query)
            results = PropertyImages.objects.select_related('propertyID').filter(lookups)
            context = {'results': results, }
            return render(request, "property/search.html", context)
        else:
            return render(request, "property/search.html", {})
    else:
        return render(request, "property/search.html", {})


def advanced_search(request):
    if request.method == 'GET':
        country_list = Country.objects.all()
        province_list = Province.objects.all()
        city_list = City.objects.all()
        propertySector_list = PropertySector.objects.all()
        propertyFacing_list = PropertyFacing.objects.all()
        propertyCategory_list = PropertyCategory.objects.all()

        q1 = request.GET.get('country')
        q2 = request.GET.get('province')
        q3 = request.GET.get('city')
        q4 = request.GET.get('category')
        q5 = request.GET.get('facing')
        q6 = request.GET.get('sector')
        q7 = request.GET.get('bedroom')
        q8 = request.GET.get('bathroom')
        q9 = request.GET.get('minPrice')
        q10 = request.GET.get('maxPrice')

        lookups = ''
        if q1 is not None and q1 is not '0':
            print('q1', q1)
            lookups = Q(propertyID__propertyCountry__countryID__exact=q1)

        if q2 is not None and q2 is not '0':
            print('q2', q2)
            if lookups:
                lookups = lookups & Q(propertyID__propertyProvince__provinceID__exact=q2)
            else:
                lookups = Q(propertyID__propertyProvince__provinceID__exact=q2)

        if q3 is not None and q3 is not '0':
            print('q3', q3)
            if lookups:
                lookups = lookups & Q(propertyID__propertyCity__cityID__exact=q3)
            else:
                lookups = Q(propertyID__propertyCity__cityID__exact=q3)

        if q4 is not None and q4 is not '0':
            print('q4', q4)
            if lookups:
                lookups = lookups & Q(propertyID__propertyCategory__PropertyCategoryId__icontains=q4)
            else:
                lookups = Q(propertyID__propertyCategory__PropertyCategoryId__icontains=q4)

        if q5 is not None and q5 is not '0':
            if lookups:
                lookups = lookups & Q(propertyID__propertyFacing__PropertyFacingId__icontains=q5)
            else:
                lookups = Q(propertyID__propertyFacing__PropertyFacingId__icontains=q5)

        if q6 is not None and q6 is not '0':
            if lookups:
                lookups = lookups & Q(propertyID__propertySector__PropertySectorId__icontains=q6)
            else:
                lookups = Q(propertyID__propertySector__PropertySectorId__icontains=q6)

        if q7 is not None and q7:
            print('test1')
            if lookups:
                lookups = lookups & Q(propertyID__propertyNumberOfRooms=q7)
            else:
                lookups = Q(propertyID__propertyNumberOfRooms=q7)

        if q8 is not None and q8:
            print('test2')
            if lookups:
                lookups = lookups & Q(propertyID__propertyNoofBathrooms=q8)
            else:
                lookups = Q(propertyID__propertyNoofBathrooms=q8)

        if q9 is not None and q9:
            if lookups:
                lookups = lookups & Q(propertyID__propertySellingPrice__gte=q9)
            else:
                lookups = Q(propertyID__propertySellingPrice__gte=q9)

        if q10 is not None and q10:
            print('test2')
            if lookups:
                lookups = lookups & Q(propertyID__propertySellingPrice__lte=q10)
            else:
                lookups = Q(propertyID__propertySellingPrice__lte=q10)

        if lookups:
            print(lookups)
            results = PropertyImages.objects.select_related('propertyID').filter(lookups)
            context = {'country_list': country_list,
                       'province_list': province_list,
                       'city_list': city_list,
                       'propertySector_list': propertySector_list,
                       'propertyFacing_list': propertyFacing_list,
                       'propertyCategory_list': propertyCategory_list,
                       'results': results
                       }
            return render(request, "property/advanced_search.html", context)

        context = {'country_list': country_list,
                   'province_list': province_list,
                   'city_list': city_list,
                   'propertySector_list': propertySector_list,
                   'propertyFacing_list': propertyFacing_list,
                   'propertyCategory_list': propertyCategory_list,
                   }
        return render(request, "property/advanced_search.html", context)


def dashboard(request):
    template_name = 'system/dashboard.html'
    return render(request, template_name)


@csrf_exempt
def loginsystem(request):
    template_name = 'system/login.html'
    if request.method == 'POST':
        my_form = LoginForm(request.POST)
        if my_form.is_valid():
            username = request.POST.get('username', '')
            password = request.POST.get('password', '')
            user = CustomSystemAdminAuth.authenticate(request, username=username, password=password)
            if user is not None and user.is_superuser:
                auth.login(request, user)
                return HttpResponseRedirect('/system/dashboard/')
            else:
                print("else")
                return render(request, template_name, {'form': my_form, 'password_is_wrong': True})
        else:
            return render(request, template_name, {'form': my_form})

    else:
        my_form = LoginForm()
        return render(request, template_name, {'form': my_form})


@csrf_exempt
def Signup(request):
    if request.method == 'POST':
        form = UserCreateForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.is_superuser = True
            user.is_staff = True
            user.save()
            return HttpResponseRedirect(reverse_lazy('login_system'))
        else:
            return render(request, 'system/signup.html', {'form': form})
    else:
        form = UserCreateForm()
        return render(request, 'system/signup.html', {'form': form})


def change_password_system(request):
    if request.method == 'POST':
        form = PasswordChangeForm(data=request.POST, user=request.user)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return redirect('/system/users')
        else:
            return render(request, 'system/change_password.html', {'form': form})
    else:
        form = PasswordChangeForm(user=request.user)
        context = {'form': form}
        return render(request, 'system/change_password.html', context)


def user_list(request):
    obj = UserProfile.objects.all()
    context = {
        'userList': obj
    }
    return render(request, 'system/users.html', context)


def properties(request):
    obj = Property.objects.all()
    context = {
        'propertyList': obj
    }
    return render(request, 'system/properties.html', context)


class UserCreateView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/create_user.html'
    form_class = UserCreateSystemForm
    success_message = 'Success: User was created.'
    success_url = reverse_lazy('user_list')


class UserUpdateView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = UserProfile
    template_name = 'system/update_user.html'
    form_class = CustomUserChangeForm
    success_message = 'Success: User was updated.'
    success_url = reverse_lazy('user_list')


class UserDeleteView(DeleteAjaxMixin, DeleteView):
    model = UserProfile
    template_name = 'system/delete_user.html'
    success_message = 'Success: User was deleted.'
    success_url = reverse_lazy('user_list')


def role_list(request):
    obj = RoleCode.objects.all()
    context = {
        'roleList': obj
    }
    return render(request, 'system/roles.html', context)


class RoleCreateView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/role_create.html'
    form_class = RoleForm
    success_url = reverse_lazy('role_list')


class RoleUpdateView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = RoleCode
    template_name = 'system/role_update.html'
    form_class = RoleForm
    success_message = 'Success: Role was updated.'
    success_url = reverse_lazy('role_list')


class RoleDeleteView(DeleteAjaxMixin, DeleteView):
    model = RoleCode
    template_name = 'system/role_delete.html'
    success_message = 'Success: Role was deleted.'
    success_url = reverse_lazy('role_list')


def permission_list(request):
    obj = PermissionType.objects.all()
    context = {
        'featuresList': obj
    }
    return render(request, 'system/permission.html', context)


class PermissionCreateView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/permission_create.html'
    form_class = PermissionForm
    success_url = reverse_lazy('permission_list')


class PermissionUpdateView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = PermissionType
    template_name = 'system/permission_update.html'
    form_class = PermissionForm
    success_message = 'Success: Permission was updated.'
    success_url = reverse_lazy('permission_list')


class PermissionDeleteView(DeleteAjaxMixin, DeleteView):
    model = PermissionType
    template_name = 'system/permission_delete.html'
    success_message = 'Success: Permission was deleted.'
    success_url = reverse_lazy('permission_list')


def permission_upload(request):
    template = "system/permission_upload.html"

    prompt = {
        'order': 'CSV must contain only name'
    }

    if request.method == 'GET':
        return render(request, template, prompt)

    csv_file = request.FILES['file']

    if not csv_file.name.endswith('.csv'):
        messages.error(request, 'This is not a csv file')

    data_set = csv_file.read().decode('UTF-8')
    io_string = io.StringIO(data_set)
    next(io_string)
    for column in csv.reader(io_string, delimiter=',', quotechar="|"):
        _, created = PermissionType.objects.update_or_create(
            name=column[0]
        )
    context = {}
    messages.add_message(request, messages.SUCCESS, 'File Uploaded Successfully')
    return render(request, "system/permission.html", context)


def assign_roles(request, pk, template_name='system/assign_roles.html'):
    user = get_object_or_404(UserProfile, pk=pk)
    user_role = UserRoleForm(instance=user)
    if request.method == "POST":
        user_role = UserRoleForm(request.POST, instance=user)
        if user_role.is_valid():
            role = request.POST.get('role', '')
            roleobj = get_object_or_404(RoleCode, roleCodeID=role)
            user.rolecode_set.clear()
            user_role_obj = UserRole(roleCodeID=roleobj, userID=user)
            user_role_obj.save()
            return redirect('user_list')
        else:
            return render(request, template_name, {"first_name": user.first_name, "last_name": user.last_name,
                                                   "role_form": user_role})
    context = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role_form": user_role
    }
    return render(request, template_name, context)


def assign_property(request, pk, template_name='system/assign_property.html'):
    property_obj = get_object_or_404(Property, pk=pk)
    advertisement = Advertise(instance=property_obj)
    if request.method == 'POST':
        advertisement = Advertise(request.POST, instance=property_obj)
        if advertisement.is_valid():
            users = request.POST.get('users', '')
            userobj = get_object_or_404(UserProfile, userID=users)
            property_obj.users.clear()
            advertisement_obj = Advertisement(property=property_obj, user=userobj)
            advertisement_obj.save()
            return redirect('property_list')
        else:
            return render(request, template_name, {'form': advertisement})

    context = {
         "form": advertisement
    }
    return render(request, template_name, context)


def assign_permission(request, pk, template_name='system/assign_features.html'):
    role = get_object_or_404(RoleCode, pk=pk)
    role_permission = RolePermissionForm(instance=role)
    if request.method == "POST":
        role_permission = RolePermissionForm(request.POST, instance=role)
        if role_permission.is_valid():
            permissions = role_permission.cleaned_data.pop('permissions')
            role.permissiontype_set.clear()
            for obj in permissions:
                permission = PermissionType.objects.get(permissionTypeID=obj.permissionTypeID)
                user_role_obj = RolePermission(permissionTypeID=permission, code=role)
                user_role_obj.save()

            return redirect('role_list')
        else:
            return render(request, template_name, {"name": role.name, "role_form": role_permission})
    context = {
        "name": role.name,
        "role_form": role_permission
    }
    return render(request, template_name, context)


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = UserProfile.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, UserProfile.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        auth.login(request, user)
        return redirect('home')
        # return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def update_status(request, pk):
    template_name = 'system/update_status.html'
    if request.method == 'POST':
        user = UserProfile.objects.get(pk=pk)
        if user.is_active:
            user.is_active = False
        else:
            user.is_active = True

        current_site = get_current_site(request)
        mail_subject = 'Account Activation'
        temp_password = randomword(10)
        message = render_to_string('property/user_acc_active_email.html', {
            'user': user,
            'domain': current_site.domain,
            'temp_password': temp_password,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode()
        })

        to_email = user.email
        email = EmailMessage(
            mail_subject, message, to=[to_email]
        )
        email.send()

        user.set_password(temp_password)
        user.save()
        return HttpResponseRedirect('/system/users/')
    else:
        return render(request, template_name)


class PropertyCreateView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/create_property.html'
    form_class = PropertyCreateForm
    success_message = 'Success: Property was created.'
    success_url = reverse_lazy('property_list')


class PropertyUpdateView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = Property
    template_name = 'system/update_property.html'
    form_class = PropertyCreateForm
    success_message = 'Success: Property was updated.'
    success_url = reverse_lazy('property_list')


class PropertyDeleteView(DeleteAjaxMixin, DeleteView):
    model = Property
    template_name = 'system/delete_property.html'
    success_message = 'Success: Property was deleted.'
    success_url = reverse_lazy('property_list')


@csrf_exempt
def property_image(request, pk):
    property_obj = Property.objects.get(pk=pk)
    instance1 = PropertyImages.objects.filter(propertyID=property_obj).first()
    if request.method == 'POST':
        if instance1:
            form = PropertyImageForm(request.POST or None, instance=instance1)
        else:
            form = PropertyImageForm(request.POST or None)

        if form.is_valid():
            if request.FILES:
                image_obj = form.save(commit=False)
                image_obj.ImageName = request.FILES['ImageName']
                image_obj.propertyID = property_obj
                image_obj.save()
            else:
                form.save()

            return redirect('property_list')
        else:
            return render(request, 'system/image_property.html', {'form': form})
    else:
        if instance1:
            form = PropertyImageForm(request.POST or None, instance=instance1)
        else:
            form = PropertyImageForm()

        return render(request, 'system/image_property.html', {'form': form})


def country_list(request):
    obj = Country.objects.all()
    context = {
        'countryList': obj
    }
    return render(request, 'system/country.html', context)


class CreateCountryView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/create_country.html'
    form_class = CountryForm
    success_message = 'Success: Country was created.'
    success_url = reverse_lazy('country_list')


class UpdateCountryView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = Country
    template_name = 'system/update_country.html'
    form_class = CountryForm
    success_message = 'Success: Country was updated.'
    success_url = reverse_lazy('country_list')


class DeleteCountryView(DeleteAjaxMixin, DeleteView):
    model = Country
    template_name = 'system/delete_country.html'
    success_message = 'Success: Country was deleted.'
    success_url = reverse_lazy('country_list')


def province_list(request):
    obj = Province.objects.all()
    context = {
        'provinceList': obj
    }
    return render(request, 'system/province.html', context)


class CreateProvinceView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/create_province.html'
    form_class = ProvinceForm
    success_message = 'Success: Province was created.'
    success_url = reverse_lazy('province_list')


class UpdateProvinceView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = Province
    template_name = 'system/update_province.html'
    form_class = ProvinceForm
    success_message = 'Success: Province was updated.'
    success_url = reverse_lazy('province_list')


class DeleteProvinceView(DeleteAjaxMixin, DeleteView):
    model = Province
    template_name = 'system/delete_province.html'
    success_message = 'Success: Province was deleted.'
    success_url = reverse_lazy('province_list')


def city_list(request):
    obj = City.objects.all()
    context = {
        'cityList': obj
    }
    return render(request, 'system/city.html', context)


class CreateCityView(PassRequestMixin, SuccessMessageMixin, CreateView):
    template_name = 'system/create_city.html'
    form_class = CityForm
    success_message = 'Success: City was created.'
    success_url = reverse_lazy('city_list')


class UpdateCityView(PassRequestMixin, SuccessMessageMixin, UpdateView):
    model = City
    template_name = 'system/update_city.html'
    form_class = CityForm
    success_message = 'Success: City was updated.'
    success_url = reverse_lazy('city_list')


class DeleteCityView(DeleteAjaxMixin, DeleteView):
    model = City
    template_name = 'system/delete_city.html'
    success_message = 'Success: City was deleted.'
    success_url = reverse_lazy('city_list')
