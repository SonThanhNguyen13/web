from django.urls import path
from . import views

app_name = 'manage'
urlpatterns = [
    path('login/', views.AdminLogin.as_view(), name='admin_login'),
    path('admin/', views.Admin1.as_view(), name='admin_index'),
    path('logout/', views.AdminSignOut.as_view(), name='admin_logout'),
    path('admin/changePassword/', views.ChangePassAdmin.as_view(), name='admin_change_pass'),
    path('admin/addUser/', views.AdminAddUser.as_view(), name='admin_add_user'),
    path('admin/userList/', views.UserList.as_view(), name='user_list'),
    path('admin/editUser/<int:id>/', views.EditUser.as_view(), name='edit_user'),
    path('admin/deleteUser/<pk>/', views.DeleteUser.as_view(), name='delete_user'),
    path('admin/resetPassword/<int:id>/', views.ResetPassword.as_view(), name='reset_password'),
    path('librarian/', views.Librarian.as_view(), name='librarian_index'),
    path('librarian/addBookType/', views.AddCategory.as_view(), name='add_category'),
    path('librarian/addBook/', views.AddBook.as_view(), name='add_book'),
    path('librarian/bookList/', views.BookList.as_view(), name='book_list'),
    path('librarian/editBook/<int:id>/', views.EditBook.as_view(), name='edit_book'),
    path('librarian/delete/<pk>/', views.DeleteBook.as_view(), name='delete_book'),
    path('librarian/changePass/', views.ChangePassLibrarian.as_view(), name='librarian_change_pass'),
    path('librarian/typeList/', views.TypeList.as_view(), name='type_list'),
    path('librarian/editType/<int:id>', views.EditType.as_view(), name='edit_type'),
    path('librarian/deleteType/<pk>/', views.DeleteType.as_view(), name='delete_type'),
    path('librarian/cartList/', views.CartList.as_view(), name='cart_list'),
    path('librarian/returnBook/<int:id>/', views.ReturnBook.as_view(), name='return_book')
    ]