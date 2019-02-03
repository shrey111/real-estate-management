from django.db import models
from django.contrib.auth.models import User, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
import datetime
from django.contrib.auth.models import UserManager
from eproperty.managers.manager import UserManager
# Create your models here.


class BaseClass(models.Model):
    def __str__(self):
        return

    class Meta:
        abstract = True


class Country(BaseClass, models.Model):
    countryID = models.AutoField(primary_key=True)
    countryName = models.CharField(max_length=50)

    def __str__(self):
        return self.countryName


class Province(BaseClass, models.Model):
    provinceID = models.AutoField(primary_key=True)
    provinceName = models.CharField(max_length=50)
    country_id = models.ForeignKey(Country, on_delete=models.CASCADE)

    def __str__(self):
        return self.provinceName


class City(BaseClass, models.Model):
    cityID = models.AutoField(primary_key=True)
    cityName = models.CharField(max_length=50)
    province_id = models.ForeignKey(Province, on_delete=models.CASCADE)

    def __str__(self):
        return self.cityName


class PropertyCategory(BaseClass, models.Model):
    PropertyCategoryId = models.IntegerField(primary_key=True)
    CategoryName = models.CharField(max_length=100)

    def __str__(self):
        return self.CategoryName


class PropertySector(BaseClass, models.Model):
    PropertySectorId = models.IntegerField(primary_key=True)
    SectorName = models.CharField(max_length=100)

    def __str__(self):
        return self.SectorName


class PropertyFacing(BaseClass, models.Model):
    PropertyFacingId = models.IntegerField(primary_key=True)
    PropertyFacingName = models.CharField(max_length=100)

    def __str__(self):
        return self.PropertyFacingName


class CustomUserManager(UserManager):
    pass


class UserProfile(AbstractBaseUser, BaseClass, PermissionsMixin):
    userID = models.AutoField(primary_key=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique=True)
    username = models.CharField(max_length=50)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['first_name', 'last_name', 'username', 'password']

    objects = UserManager()

    def __str__(self):
        return "User ID = " + str(self.userID) + ", First Name = " + str(self.first_name) + ", Last Name = " + \
               str(self.last_name) + \
                ", Email ID = " + str(self.email)

    @property
    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser


class Property(BaseClass, models.Model):
    propertyID = models.AutoField(primary_key=True)
    propertyTitle = models.CharField(max_length=50)
    propertyCategory = models.ForeignKey(PropertyCategory, null=True, on_delete=models.SET_NULL)
    propertySector = models.ForeignKey(PropertySector, null=True, on_delete=models.SET_NULL)
    propertyFacing = models.ForeignKey(PropertyFacing, null=True, on_delete=models.SET_NULL)
    propertyCountry = models.ForeignKey(Country, null=True, on_delete=models.SET_NULL)
    propertyProvince = models.ForeignKey(Province, null=True, on_delete=models.SET_NULL)
    propertyCity = models.ForeignKey(City, null=True, on_delete=models.SET_NULL)
    propertyStreet = models.TextField()
    propertyPostalCode = models.CharField(max_length=10)
    propertyStreetNumber = models.CharField(max_length=20)
    propertyConstructionDate = models.DateField()
    propertyRegistrationDate = models.DateField()
    propertyNumberOfHalls = models.IntegerField()
    propertyNumberOfRooms = models.IntegerField()
    propertyNoofBathrooms = models.IntegerField()
    propertyNoofFloors = models.IntegerField()
    propertyTotalArea = models.FloatField()
    propertyAskingPrice = models.FloatField()
    propertySellingPrice = models.FloatField()
    users = models.ManyToManyField(UserProfile, through='Advertisement')

    def __str__(self):
        return self.propertyTitle + ", " + str(self.propertyFacing.PropertyFacingName) + ", Asking Price = $" \
               + str(self.propertyAskingPrice) + ", " + self.propertyCountry.countryName + ", Total Area = " \
               + str(self.propertyTotalArea) + ", " + self.propertyCity.cityName + ", " \
               + self.propertyCategory.CategoryName

    def operation1(self):
        return self.propertyID

    def operation2(self):
        return self.propertyTitle


class PropertyImages(BaseClass, models.Model):
    propertyID = models.ForeignKey(Property, on_delete=models.CASCADE)
    ImageName = models.ImageField(blank=True, null=True)
    propertyImageID = models.AutoField(primary_key=True)
    propertyImageDescription = models.TextField()

    def __str__(self):
        return str(self.propertyImageID)

    def add_image(self, parm1):
        self.ImageName = parm1

    def get_image(self):
        return self.ImageName


class Advertisement(BaseClass, models.Model):
    advertisementID = models.AutoField(primary_key=True)
    property = models.ForeignKey(Property, on_delete=models.CASCADE)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    dateCreated = models.DateField(default=datetime.date.today)

    def __str__(self):
        return "" + str(self.advertisementID)


class RoleCode(BaseClass, models.Model):
    roleCodeID = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    users = models.ManyToManyField(UserProfile, through='UserRole')

    def __str__(self):
        return self.name


class UserRole(models.Model):
    userRoleID = models.AutoField(primary_key=True)
    userID = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    roleCodeID = models.ForeignKey(RoleCode, on_delete=models.CASCADE)
    dateAssigned = models.DateField(default=datetime.date.today)


class PermissionType(BaseClass, models.Model):
    permissionTypeID = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    permissions = models.ManyToManyField(RoleCode, through='RolePermission')

    def __str__(self):
        return self.name


class RolePermission(models.Model):
    rolePermissionID = models.AutoField(primary_key=True)
    permissionTypeID = models.ForeignKey(PermissionType, on_delete=models.CASCADE)
    code = models.ForeignKey(RoleCode, on_delete=models.CASCADE)
    dateAssigned = models.DateField(default=datetime.date.today)
