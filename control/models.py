from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


# Create your models here.
class AccountUserManager(BaseUserManager):
    def create_user(self, username, email=None, password=None, **extra_fields):
        user = self.model(username=username, email=email)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        user = self.create_user(
            username=username,
            password=password,
            email=email
        )
        user.is_superuser = True
        user.role = 'admin'
        user.save(using = self._db)
        return user


class NguyenThanhSon36User(PermissionsMixin,AbstractBaseUser):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=30, unique=True)
    password = models.CharField(max_length=512, null=False)
    role = models.CharField(
        max_length=40,
        choices=[
            ('admin', 'admin'),
            ('librarian', 'librarian'),
            ('student/teacher', 'student/teacher'),
        ]
    )
    email = models.CharField(max_length=512, null=False, unique=True)
    address = models.CharField(max_length=512)
    phone = models.CharField(max_length=512)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)
    REQUIRED_FIELDS = ['email']
    USERNAME_FIELD = 'username'
    objects = AccountUserManager()


class NguyenThanhSon36Category(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=512, unique=True)

    def get_category(self):
        return self.name


class NguyenThanhSon36Books(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=512, unique=True)
    author = models.CharField(max_length=512)
    year = models.CharField(max_length=5)
    company = models.CharField(max_length=512)
    category = models.ForeignKey(NguyenThanhSon36Category, on_delete=models.CASCADE)
    description = models.CharField(max_length=512)
    stock = models.IntegerField()
    max_stock = models.IntegerField(default=0)
    price = models.IntegerField()

    def get_book_name(self):
        return self.name


class NguyenThanhSon36Order(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.OneToOneField(NguyenThanhSon36User, on_delete=models.CASCADE)
    book_list = models.CharField(max_length=512)
    # price = models.IntegerField()


class NguyenThanhSon36Ordered(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.OneToOneField(NguyenThanhSon36User, on_delete=models.CASCADE)
    book_list = models.CharField(max_length=512)
    # price = models.IntegerField()

