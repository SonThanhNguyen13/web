import re
import random
import string
from django.shortcuts import render, redirect
from django.contrib.auth import update_session_auth_hash
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.utils import IntegrityError
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.views.generic.edit import DeleteView
from django.contrib import messages
from django.http import HttpResponseRedirect
from . import models


def check_username(username):
    """
    Check if username contain special characters
    :param username: username
    :return: boolean. If contain: False else True
    """
    special = list(string.punctuation)
    special.append(' ')
    for i in special:
        if i in username:
            return False
    else:
        return True


def to_lowercase(s):
    """
    Convert a string to lowercase
    :param s: string
    :return: lowercase version of string
    """
    return s.lower()


def get_or_none(classmodel, **kwargs):
    """
    Get 1 object from model. If not exists, return None
    :param classmodel: model
    :param kwargs: model parameters to get
    :return: object or None
    """
    try:
        return classmodel.objects.get(**kwargs)
    except classmodel.DoesNotExist:
        return None


def random_password():
    upper = random.choice(string.ascii_uppercase)
    special = random.choice(string.punctuation)
    number = random.choice(string.digits)
    new_password = upper + special + number
    for i in range(5):
        new_password += random.choice(string.ascii_lowercase)
    new_password = list(new_password)
    random.shuffle(new_password)
    new_password = ''.join(new_password)
    return new_password


def send_email(password, receivers):
    """
    Send new password
    :param password: password
    :param receivers: list of email
    :return: None
    """
    subject = '<no reply> Reset Password'
    message = 'Hello. Your new password to login is : {}'.format(password)
    email_from = settings.EMAIL_HOST_USER
    send_mail(subject, message, email_from, receivers)


def check_username_len(username):
    """ This function check username's length between 3 and 25 characters """
    if len(username) < 3 or len(username) > 25:
        return False
    else:
        return True


def check_confirm_pass(password, cnf_password):
    """
    This function validate the password and the confirm password
    user entered
    """
    if password != cnf_password:
        return False
    else:
        return True


def check_pass_len(password):
    """ This function check password's length more than 8 characters """
    if len(password) < 8:
        return False
    else:
        return True


def check_complexity_pass(password):
    """ This function check password's complexity """
    if re.fullmatch(r"^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$])[\w\d@#$]{8,}$", password):
        return True
    else:
        return False


def check_username_in_password(username, password):
    if username in password:
        return False
    return True


def check_book_name(book_name):
    for i in string.punctuation:
        if i in book_name:
            return False
    return True


class AdminLogin(View):
    def get(self, request):
        return render(
            request,
            'control/adminLogin.html',
        )

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        username = to_lowercase(username)
        print(username)
        role = request.POST.get('role')
        user = authenticate(username=username, password=password)
        print(user)
        if not user:
            return render(
                request,
                'control/adminLogin.html',
                context={
                    'message': 'Invalid username or password'
                }
            )
        else:
            if user.role != 'admin' and user.role != 'librarian':
                logout(request)
                return render(
                    request,
                    'control/adminLogin.html',
                    context={
                        'message': 'Invalid username or password'
                    }
                )
            elif user.role != role:
                logout(request)
                return render(
                    request,
                    'control/adminLogin.html',
                    context={
                        'message': 'Please select correct role'
                    }
                )
            else:
                if user.role == 'admin':
                    login(request, user)
                    return redirect(
                        '/manage/admin/'
                    )
                else:
                    login(request, user)
                    return redirect(
                        '/manage/librarian/'
                    )


class Admin1(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request):
        if request.user.role != 'admin':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You have no permission'}
            )
        return render(
            request,
            'control/adminIndex.html',
            context={
                'name': '{}'.format(request.user.username)
            }
        )


class AdminSignOut(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request):
        logout(request)
        return render(
            request,
            'control/adminLogin.html',
            context={
                'message': 'You have just logged out'
            }
        )


class ChangePassAdmin(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request):
        if request.user.role != 'admin':
            return redirect(
                '/manage/login/'
            )
        return render(
            request,
            'control/changePassAdmin.html'
        )

    def post(self, request):
        if request.user.role != 'admin':
            return redirect(
                '/manage/login/'
            )
        password = request.POST.get('password')
        new_pass = request.POST.get('new_password')
        cnf_pass = request.POST.get('cnf_password')
        user = models.NguyenThanhSon36User.objects.get(username=request.user.username)
        if not user.check_password(password):
            return render(
                request,
                'control/changePassAdmin.html',
                context={'message': 'Invalid password'}
            )
        elif not check_confirm_pass(new_pass, cnf_pass):
            return render(
                request,
                'control/changePassAdmin.html',
                context={'message': 'Password not match'}
            )
        elif not check_pass_len(new_pass):
            return render(
                request,
                'control/changePassAdmin.html',
                context={'message': 'New password\'s length must be more than 8'}
            )
        elif not check_username_in_password(request.user.username, new_pass):
            return render(
                request,
                'control/changePassAdmin.html',
                context={'message': 'Password should not contain username'}
            )
        elif not check_complexity_pass(new_pass):
            return render(
                request,
                'control/changePassAdmin.html',
                context={'message': 'Password must have at least 1 uppercase, 1 lowercase and 1 special character'}
            )
        else:
            password = make_password(new_pass, hasher='pbkdf2_sha256')
            user.password = password
            user.save()
            update_session_auth_hash(request, user)
            return render(
                request,
                'control/changePassAdmin.html',
                context={'message': 'Success'}
            )


class AdminAddUser(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request):
        if request.user.role != 'admin':
            logout(request)
            return redirect(
                '/manage/login/'
            )
        else:
            return render(
                request,
                'control/addUser.html'
            )

    def post(self, request):
        """Get information & check & register"""
        if request.user.role != 'admin':
            logout(request)
            return redirect(
                '/manage/login/'
            )
        else:
            username = request.POST.get('username')
            password = request.POST.get('password')
            role = request.POST.get('role')
            email = request.POST.get('email')
            phone = request.POST.get('phone')
            address = request.POST.get('address')
            username = to_lowercase(username)
            if not check_username_len(username):  # check username's length
                return render(
                    request,
                    'control/addUser.html',
                    context={'message': 'Username must be between 8 and 25 characters'}
                )
            elif not check_username(username):
                return render(
                    request,
                    'control/addUser.html',
                    context={'message': 'Username only contain letters and numbers'}
                )
            elif not check_pass_len(password):  # check password's length
                return render(
                    request,
                    'control/addUser.html',
                    context={'message': 'Password must be more than 8 characters'}
                )
            elif not check_username_in_password:
                return render(
                    request,
                    'control/addUser.html',
                    context={
                        'message': 'Password should not contain username'
                    }
                )
            elif not check_complexity_pass(password):  # check password's complexity
                return render(
                    request,
                    'control/addUser.html',
                    context={
                        'message': '''
                               Password must have at least 1 uppercase,
                               1 lowercase & 1 special character
                               '''
                    }
                )
            else:  # if pass all, try register
                password = make_password(password, salt=None, hasher='pbkdf2_sha256')
                try:  # check username or email already exists
                    if role == 'admin':
                        is_superuser = True
                    else:
                        is_superuser = False
                    new_user = models.NguyenThanhSon36User.objects.create(
                        username=username,
                        password=password,
                        email=email,
                        phone=phone,
                        address=address,
                        is_superuser=is_superuser,
                        role=role,
                    )
                    new_user.save()  # if not, register
                    return render(
                        request,
                        'control/addUser.html',
                        context={
                            'message': 'Hello {}'.format(new_user.username)
                        }
                    )
                except IntegrityError as e:  # else, show error
                    error = str(e)[str(e).find('.') + 1:].capitalize()
                    return render(
                        request,
                        'control/addUser.html',
                        context={
                            'message': '{} already exists'.format(error)
                        }
                    )


class UserList(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request):
        if request.user.role != 'admin':
            logout(request)
            return redirect(
                '/manage/login/'
            )
        else:
            users = models.NguyenThanhSon36User.objects.all()
            return render(
                request,
                'control/userList.html',
                context={'users': users}
            )


class EditUser(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request, id):
        if request.user.role != 'admin':
            logout(request)
            return redirect(
                '/manage/login/'
            )
        else:
            user = models.NguyenThanhSon36User.objects.get(id=id)
            return render(
                request,
                'control/editUser.html',
                context={'user':user}
            )

    def post(self, request, id):
        if request.user.role != 'admin':
            logout(request)
            return redirect(
                '/manage/login/'
            )
        else:
            role = request.POST.get('role')
            email = request.POST.get('email')
            address = request.POST.get('address')
            phone = request.POST.get('phone')
            user = models.NguyenThanhSon36User.objects.get(id=id)
            try:
                user.email = email
                user.role = role
                if role == 'admin':
                    user.is_superuser = True
                else:
                    user.is_superuser = False
                user.address = address
                user.phone = phone
                user.save()
                return render(
                    request,
                    'control/editUser.html',
                    context={
                        'message': 'Success'
                    }
                )

            except IntegrityError as e:
                return render(
                    request,
                    'control/editUser.html',
                    context={
                        'message': 'Email already exists'
                    }
                )


class DeleteUser(LoginRequiredMixin,DeleteView):
    model = models.NguyenThanhSon36User
    success_url = '/manage/admin/userList/'

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        check_object = get_or_none(models.NguyenThanhSon36Ordered, username=self.object)
        if check_object:
            messages.warning(request, "Can not delete user {0}. {0} still have order".format(self.object.username))
            return redirect(
                '/manage/admin/userList'
            )
        else:
            success_url = self.get_success_url()
            self.object.delete()
            return HttpResponseRedirect(success_url)



class ResetPassword(LoginRequiredMixin, View):
    def get(self, request, id):
        if request.user.role != 'admin':
            logout(request)
            return redirect(
                '/manage/login/'
            )
        else:
            user = models.NguyenThanhSon36User.objects.get(id=id)
            new_password = random_password()
            password = make_password(password=new_password, hasher='pbkdf2_sha256')
            user.password = password
            user.save()
            send_email(new_password, [user.email])
            return redirect(
                '/manage/admin/userList/'
            )

# Start Librarian


class Librarian(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You don\'t have permission'}
            )
        return render(
            request,
            'control/librarianIndex.html',
            context={
                'name': '{}'.format(request.user.username)
            }
        )


class AddCategory(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': "You don't have permission"}
            )
        else:
            return render(
                request,
                'control/addBookType.html',
            )

    def post(self, request):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You don\'t have permission'}
            )
        else:
            category = request.POST.get('type')
            if not check_book_name(category):
                return render(
                    request,
                    'control/addBookType.html',
                    context={'message': 'Book\'s name can not contain special character'}
                )
            try:
                book_type = models.NguyenThanhSon36Category.objects.create(
                    name=category
                )
                book_type.save()
                return render(
                    request,
                    'control/addBookType.html',
                    context={'message': 'Success'}
                )
            except IntegrityError:
                return render(
                    request,
                    'control/addBookType.html',
                    context={'message': 'Category already exists'}
                )


class AddBook(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You don\'t have permission'}
            )
        else:
            cate = models.NguyenThanhSon36Category.objects.all()
            cate = [i.name for i in cate]
            return render(
                request,
                'control/addBook.html',
                context={'type': cate}
            )

    def post(self, request):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You don\'t have permission'}
            )
        else:
            cate = models.NguyenThanhSon36Category.objects.all()
            cate = [i.name for i in cate]
            name = request.POST.get('name')
            if not check_book_name(name):
                return render(
                    request,
                    'control/addBook.html',
                    context={'message': 'Book\'s name can not contain special character'}
                )
            author = request.POST.get('author')
            if not check_book_name(author):
                return render(
                    request,
                    'control/addBook.html',
                    context={'message': 'Book\'s author can not contain special character'}
                )
            year = request.POST.get('year')
            company = request.POST.get('company')
            type = request.POST.get('type')
            category = models.NguyenThanhSon36Category.objects.get(name=type)
            description = request.POST.get('description')
            max_stock = int(request.POST.get('num'))
            stock = max_stock
            price = int(request.POST.get('price'))
            try:
                book = models.NguyenThanhSon36Books.objects.create(
                    name=name,
                    author=author,
                    year=year,
                    company=company,
                    category=category,
                    description=description,
                    stock=stock,
                    max_stock=max_stock,
                    price=price
                )
                book.save()
                return render(
                    request,
                    'control/addBook.html',
                    context={'type': cate, 'message': 'Success'}
                )
            except IntegrityError:
                return render(
                    request,
                    'control/addBook.html',
                    context={'type': cate, 'message': 'Book already exists'}
                )


class BookList(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You don\'t have permission'}
            )
        else:
            books = models.NguyenThanhSon36Books.objects.all()
            return render(
                request,
                'control/bookList.html',
                context={'books': books}
            )


class EditBook(LoginRequiredMixin, View):
    login_url = '/manage/login'

    def get(self, request, id):
        cate = models.NguyenThanhSon36Category.objects.all()
        book = models.NguyenThanhSon36Books.objects.get(id=id)
        return render(
            request,
            'control/editBook.html',
            context={'book': book, 'type': cate}
        )

    def post(self, request, id):
        if request.user.role != 'librarian':
            logout(request)
            return render(
                request,
                'control/adminLogin.html',
                context={'message': 'You don\'t have permission'}
            )
        else:
            book = models.NguyenThanhSon36Books.objects.get(id=id)
            name = request.POST.get('name')
            if not check_book_name(name):
                messages.error(request, 'Book\'s name can not contain special characters')
                return redirect(
                    '/manage/librarian/editBook/{}'.format(id)
                )
            author = request.POST.get('author')
            if not check_book_name(author):
                messages.error(request, 'Book\'s author can not contain special characters')
                return redirect(
                    '/manage/librarian/editBook/{}'.format(id)
                )
            year = request.POST.get('year')
            company = request.POST.get('company')
            type = request.POST.get('type')
            category = models.NguyenThanhSon36Category.objects.get(name=type)
            description = request.POST.get('description')
            stock = int(request.POST.get('num'))
            max_stock = int(request.POST.get('max_stock'))
            price = int(request.POST.get('price'))
            if max_stock < stock:
                messages.error(request, 'Max stock must be bigger than stock')
                return redirect(
                    '/manage/librarian/editBook/{}'.format(id)
                )
            try:
                book.name = name
                book.author = author
                book.year = year
                book.company = company
                book.category = category
                book.description = description
                book.stock = stock
                book.max_stock = max_stock
                book.price = price
                book.save()
                messages.info(request,'Success edit book {}'.format(book.name))
                return redirect(
                    '/manage/librarian/bookList/'
                )
            except IntegrityError:
                messages.error(request, 'Already have that book')
                return redirect(
                    '/manage/librarian/editBook/{}'.format(id)
                )


class DeleteBook(LoginRequiredMixin, DeleteView):
    model = models.NguyenThanhSon36Books
    success_url = '/manage/librarian/bookList/'

    def delete(self,request, *args, **kwargs):
        self.object = self.get_object()
        if self.object.max_stock != self.object.stock:
            messages.warning(request, "Can't delete book {}. User has not returned all book.".format(self.object.name))
            return redirect(
                '/manage/librarian/bookList'
            )
        else:
            success_url = self.get_success_url()
            self.object.delete()
            return HttpResponseRedirect(success_url)


class EditType(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request, id):
        if request.user.role != 'librarian':
            return redirect(
                '/manage/login/'
            )
        type = models.NguyenThanhSon36Category.objects.get(id=id)
        return render(
            request,
            'control/editType.html',
            context={'i': type}
        )

    def post(self, request, id):
        if request.user.role != 'librarian':
            return redirect(
                '/manage/login/'
            )
        book_type = models.NguyenThanhSon36Category.objects.get(id=id)
        new = request.POST.get('type')
        if not check_book_name(new):
            return request(
                request,
                'control/editType.html',
                context={'message': 'Can not contain special charater'}
            )
        try:
            book_type.name = new
            book_type.save()
            return redirect(
                '/manage/librarian/typeList'
            )
        except IntegrityError:
            return render(
                request,
                'control/editType.html',
                context={'message': 'Already have that type'}
            )


class TypeList(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request):
        if request.user.role != 'librarian':
            return redirect(
                '/manage/login/'
            )
        types = models.NguyenThanhSon36Category.objects.all()
        return render(
            request,
            'control/typeList.html',
            context={'types': types}
        )


class DeleteType(LoginRequiredMixin, DeleteView):
    model = models.NguyenThanhSon36Category
    success_url = '/manage/librarian/typeList/'


class ChangePassLibrarian(LoginRequiredMixin, View):
    login_url = '/manage/login/'

    def get(self, request):
        if request.user.role != 'librarian':
            return redirect(
                '/manage/login/'
            )
        return render(
            request,
            'control/changePass.html'
        )

    def post(self, request):
        if request.user.role != 'librarian':
            return redirect(
                '/manage/login/'
            )
        password = request.POST.get('password')
        new_pass = request.POST.get('new_password')
        cnf_pass = request.POST.get('cnf_password')
        user = models.NguyenThanhSon36User.objects.get(username=request.user.username)
        if not user.check_password(password):
            return render(
                request,
                'control/changePass.html',
                context={'message': 'Invalid password'}
            )
        elif not check_confirm_pass(new_pass, cnf_pass):
            return render(
                request,
                'control/changePass.html',
                context={'message': 'Password not match'}
            )
        elif not check_pass_len(new_pass):
            return render(
                request,
                'control/changePass.html',
                context={'message': 'New password\'s length must be more than 8'}
            )
        elif not check_username_in_password(request.user.username, new_pass):
            return render(
                request,
                'control/changePass.html',
                context={'message': 'Password should not contain username'}
            )
        elif not check_complexity_pass(new_pass):
            return render(
                request,
                'control/changePass.html',
                context={'message': 'Password must have at least 1 uppercase, 1 lowercase and 1 special character'}
            )
        else:
            password = make_password(new_pass, hasher='pbkdf2_sha256')
            user.password = password
            user.save()
            update_session_auth_hash(request, user)
            return render(
                request,
                'control/changePass.html',
                context={'message': 'Success'}
            )


class CartList(LoginRequiredMixin,View):
    login_url = '/manage/login/'

    def get(self, request):
        if request.user.role != 'librarian':
            return redirect(
                '/manage/login/'
            )
        else:
            carts = models.NguyenThanhSon36Ordered.objects.all()
            for cart in carts:
                book_list = cart.book_list.split()
                cart.book_list = [models.NguyenThanhSon36Books.objects.get(id=int(i)).name for i in book_list]
                cart.book_list = '; '.join(cart.book_list)
            return render(
                request,
                'control/cartList.html',
                context={'carts':carts}
            )


class ReturnBook(LoginRequiredMixin,View):

    def get(self,request, id):
        cart = models.NguyenThanhSon36Ordered.objects.get(id=id)
        books_list = cart.book_list.split()
        for i in books_list:
            book = models.NguyenThanhSon36Books.objects.get(id=int(i))
            book.stock += 1
            book.save()
        cart.delete()
        messages.info(request,'Success')
        return redirect(
            '/manage/librarian/cartList/'
        )
