import re
import random
import string
from django.contrib import messages
from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.utils import IntegrityError
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import update_session_auth_hash
from django.core.mail import send_mail
from django.conf import settings
from control import models
from django.views.generic.edit import DeleteView

# Create your views here.

def to_lowercase(s):
    """
    Convert a string to lowercase
    :param s: string
    :return: lowercase version of string
    """
    return s.lower()

def check_username_len(username):
    """ This function check username's length between 3 and 25 characters """
    if len(username) < 3 or len(username) > 25:
        return False
    else:
        return True

def check_username(username):
    """
    Check if username contain special characters
    :param username: username
    :return: boolean. If contain: False else True
    """
    special = list(string.punctuation)
    # string.punctuation = !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~
    special.append(' ')
    for i in special:
        if i in username:
            return False
    else:
        return True


def random_password():
    """
    :return: random strong password
    """
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
    Send password to receiver
    :param password: strong password
    :param receivers: list of email receiver
    :return: None
    """
    subject = '<no reply> Reset Password'
    message = 'Hello. Your new password to login is : {}'.format(password)
    email_from = settings.EMAIL_HOST_USER
    send_mail(subject, message, email_from, receivers)


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
    """
    Check if username in password
    :return: boolean
    """
    if username in password:
        return False
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


def transform_text(text):
    text = text.replace("<", '%3C')
    text = text.replace(">", '%3E')
    return text


class UserLogin(View):
    def get(self, request):
        return render(request, 'books/login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        username = to_lowercase(username)
        user = authenticate(username=username, password=password)
        if user:
            if user.role != 'student/teacher':
                return render(
                    request,
                    'books/login.html',
                    context={'message': 'Admin can not log in'}
                )
            else:
                login(request, user)
                return redirect(
                    '/'
                )
        else:
            return render(
                request,
                'books/login.html',
                context={'message': "Invalid username or password"}
            )


class Register(View):
    def get(self, request):
        """ This function return register page """
        return render(request, 'books/register.html')

    def post(self, request):
        """Get information & check & register"""
        username = request.POST.get('username')
        password = request.POST.get('password')
        conf_pass = request.POST.get('cnf_password')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        if not check_username_len(username):  # check username's length
            return render(
                request,
                'books/register.html',
                context={'message': 'Username must be between 8 and 25 characters'}
            )
        elif not check_username(username):
            return render(
                request,
                'books/register.html',
                context={'message': 'Username can not contain any special character'}
            )
        elif not check_confirm_pass(password, conf_pass):  # check confirm pass
            return render(
                request,
                'books/register.html',
                context={'message': 'Password does not match'}
            )
        elif not check_pass_len(password):  # check password's length
            return render(
                request,
                'books/register.html',
                context={'message': 'Password must be more than 8 characters'}
            )
        elif not check_username_in_password(username, password):
            return render(
                request,
                'books/register.html',
                context={
                    'message': 'Password should not contain username'
                }
            )
        elif not check_complexity_pass(password):  # check password's complexity
            return render(
                request,
                'books/register.html',
                context={
                    'message': '''
                        Password must have at least 1 uppercase,
                        1 lowercase & 1 special character
                        '''
                }
            )
        else:  # if pass all, try register
            username = to_lowercase(username)
            password = make_password(password, salt=None, hasher='pbkdf2_sha256')
            try:  # check username or email already exists
                new_user = models.NguyenThanhSon36User.objects.create(
                    username=username,
                    password=password,
                    email=email,
                    phone=phone,
                    address=address,
                    is_staff=True,
                    role='student/teacher',
                )
                new_user.save()  # if not, register
                return render(
                    request,
                    'books/register.html',
                    context={
                        'message': 'Success. Hello {}'.format(new_user.username)
                    }
                )
            except IntegrityError as e:  # else, show error
                error = str(e)[str(e).find('.') + 1:].capitalize()
                return render(
                    request,
                    'books/register.html',
                    context={
                        'message': '{} already exists'.format(error)
                    }
                )


class Forgot(View):
    def get(self, request):
        return render(
            request,
            'books/forget.html'
        )

    def post(self, request):
        email = request.POST.get('email')
        try:
            user = models.NguyenThanhSon36User.objects.get(email=email)
            if user.is_superuser and user.role == 'admin':
                return render(
                    request,
                    'books/forget.html',
                    context={'message': 'Admin can not reset password here'}
                )
            elif user.role == 'librarian':
                return render(
                    request,
                    'books/forget.html',
                    context={'message': 'Librarian can not reset password here'}
                )
            # comeback later
            new_password = random_password()
            password = make_password(password=new_password, hasher='pbkdf2_sha256')
            user.password = password
            user.save()
            send_email(new_password, [user.email])
            return render(
                request,
                'books/forget.html',
                context={'message': 'Done'}
            )
        except ObjectDoesNotExist:
            return render(
                request,
                'books/forget.html',
                context={'message': 'invalid email'}
            )


class Index(LoginRequiredMixin, View):
    login_url = '/login/'

    def get(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect(
                '/login/'
            )
        return render(
            request,
            'books/index.html',
            context={
                'name': '{}'.format(request.user.username)
            }
        )


class BookList(LoginRequiredMixin, View):
    def get(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect('/login/')
        else:
            books = models.NguyenThanhSon36Books.objects.all()
            return render(
                request,
                'books/bookList.html',
                context={'books': books}
            )

    def post(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect('/login/')
        else:
            search_item = request.POST.get('search')
            data = models.NguyenThanhSon36Books.objects.filter(name__contains=search_item)
            if not data.exists() :
                search_item = transform_text(search_item)
                return render(
                    request,
                    'books/bookList.html',
                    context={'messages': ['Not found {}'.format(search_item)]}
                )
            search_item = transform_text(search_item)
            return render(
                    request,
                    'books/bookList.html',
                    context={
                        'books': data,
                        'messages': ['Found books with {}'.format(search_item)]
                    }
                )


class CancelOrder(LoginRequiredMixin, DeleteView):
    model = models.NguyenThanhSon36Order
    success_url = '/cart/'


class AddToCart(LoginRequiredMixin, View):
    def get(self, request, id):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect('/login/')
        else:
            book = models.NguyenThanhSon36Books.objects.get(id=id)  # get book info
            user = models.NguyenThanhSon36User.objects.get(username=request.user.username)  # get user
            try:
                order = models.NguyenThanhSon36Order.objects.get(username=user)  # get order from order model
                books_list = order.book_list
                books_list = books_list.split()  # split into list
                books_list = [int(i) for i in books_list]
                if book.id not in books_list:  # if book not in list, add
                    books_list.append(book.id)
                books_list = [str(i) for i in books_list]
                books_list = ' '.join(books_list)  # back to string
                order.book_list = books_list
                order.save()  # save & commit
                messages.info(request, 'Success add {} to borrow list'.format(book.name))
                return redirect(
                    '/bookList/'
                )
            except ObjectDoesNotExist:  # if order not exists, create new
                books_list = '{}'.format(book.id)
                order = models.NguyenThanhSon36Order.objects.create(
                    username=user,
                    book_list=books_list
                )
                messages.info(request, 'Success add {} to cart'.format(book.name))
                order.save()
                return redirect(
                    '/bookList/'
                )


class Cart(LoginRequiredMixin, View):
    def get(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect('/login/')
        else:
            user = models.NguyenThanhSon36User.objects.get(username=request.user.username)  # get user
            cart = get_or_none(models.NguyenThanhSon36Order, username=user)  # get cart if exists
            books_info = []
            submitted_books_info = []
            if cart is not None:
                books = cart.book_list.split()
                for i in books:
                    books_info.append(models.NguyenThanhSon36Books.objects.get(id=i))  # get book info to show
            submitted_cart = get_or_none(models.NguyenThanhSon36Ordered, username=user)  # get cart if exists
            if submitted_cart is not None:
                submitted_books = submitted_cart.book_list.split()
                for i in submitted_books:
                    submitted_books_info.append(models.NguyenThanhSon36Books.objects.get(id=i))  # get book info to show
            if cart:
                return render(
                    request,
                    'books/cart.html',
                    context={'books': books_info, 'submitted_books': submitted_books_info, 'cart_id' : cart.id}
                )
            else:
                return render(
                    request,
                    'books/cart.html',
                    context={'books': books_info, 'submitted_books': submitted_books_info}
                )


class RemoveFromCart(LoginRequiredMixin, View):
    def get(self, request, id):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect('/login/')
        else:
            book = models.NguyenThanhSon36Books.objects.get(id=id)
            user = models.NguyenThanhSon36User.objects.get(username=request.user.username)
            cart = models.NguyenThanhSon36Order.objects.get(username=user)
            books_list = cart.book_list
            books_list = books_list.split()  # split into list
            books_list = [int(i) for i in books_list]  # convert to int
            books_list.remove(book.id)  # remove id
            books_list = [str(i) for i in books_list]
            books_list = ' '.join(books_list)  # back to string
            cart.book_list = books_list
            cart.save()  # save & commit
            messages.info(request, 'Success remove {}'.format(book.name))
            return redirect(
                '/cart/'
            )


class SubmitCart(LoginRequiredMixin, View):
    def get(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect('/login/')
        else:
            user = models.NguyenThanhSon36User.objects.get(username=request.user.username)
            cart = get_or_none(models.NguyenThanhSon36Order, username=user)
            if cart is None:
                messages.error(request, 'Nothing to submit')
                return redirect(
                    '/cart/'
                )
            try:
                books_list = cart.book_list
                books_list = books_list.split()
                for i in books_list:
                    book = models.NguyenThanhSon36Books.objects.get(id=int(i))
                    if book.stock <= 0:  # check book in cart if out of stock
                        messages.error(request, 'Book "{}" is out of stock, please remove from cart'.format(book.name))
                        return redirect(
                            '/cart/',
                        )
                #  if not, create order cart
                submit_cart = models.NguyenThanhSon36Ordered.objects.create(
                    username=cart.username,
                    book_list=cart.book_list,
                )
                # stock = stock - 1 for each book
                for i in books_list:
                    book = models.NguyenThanhSon36Books.objects.get(id=int(i))
                    book.stock -= 1
                    book.save()
                submit_cart.save()  # commit order
                cart.delete()  # delete cart
                messages.info(request, 'Success')
                return redirect(
                    '/cart/'
                )
            except IntegrityError:  # Each user can't have more than 1 oreder
                messages.error(request, 'You need to return all books before submit again')
                return redirect(
                    '/cart/'
                )


class SignOut(LoginRequiredMixin, View):
    login_url = '/login/'

    def get(self, request):
        logout(request)
        return render(
            request,
            'books/login.html',
            context={
                'message': 'You have just logged out'
            }
        )


class ChangePassword(LoginRequiredMixin, View):
    login_url = '/login/'

    def get(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect(
                '/login/'
            )
        return render(
            request,
            'books/changePassword.html'
        )

    def post(self, request):
        if request.user.role != 'student/teacher':
            logout(request)
            return redirect(
                'login/'
            )
        password = request.POST.get('password')
        new_pass = request.POST.get('new_password')
        cnf_pass = request.POST.get('cnf_password')
        user = models.NguyenThanhSon36User.objects.get(username=request.user.username)
        if not user.check_password(password):
            return render(
                request,
                'books/changePassword.html',
                context={'message': 'Invalid password'}
            )
        elif not check_confirm_pass(new_pass, cnf_pass):
            return render(
                request,
                'books/changePassword.html',
                context={'message': 'Password not match'}
            )
        elif not check_pass_len(new_pass):
            return render(
                request,
                'books/changePassword.html',
                context={'message': 'New password\'s length must be more than 8'}
            )
        elif not check_username_in_password(request.user.username, new_pass):
            return render(
                request,
                'books/changePassword.html',
                context={'message': 'Password should not contain username'}
            )
        elif not check_complexity_pass(new_pass):
            return render(
                request,
                'books/changePassword.html',
                context={'message': 'Password must have at least 1 uppercase, 1 lowercase and 1 special character'}
            )
        else:
            password = make_password(new_pass, hasher='pbkdf2_sha256')
            user.password = password
            user.save()
            update_session_auth_hash(request, user)
            return render(
                request,
                'books/changePassword.html',
                context={'message': 'Success'}
            )
