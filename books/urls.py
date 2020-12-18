from django.urls import path
from . import views

app_name = 'user'
urlpatterns = [
    path('login/', views.UserLogin.as_view(), name='login'),
    path('register/', views.Register.as_view(), name='register'),
    path('forgot/', views.Forgot.as_view(), name='forgot'),
    path('', views.Index.as_view(), name='index'),
    path('logout/', views.SignOut.as_view(), name='logout'),
    path('bookList/', views.BookList.as_view(), name='book_list'),
    path('bookList/add/<int:id>', views.AddToCart.as_view(), name='add_to_cart'),
    path('cart/', views.Cart.as_view(), name='cart'),
    path('cart/remove/<int:id>', views.RemoveFromCart.as_view(), name='remove_from_cart'),
    path('cart/submit/', views.SubmitCart.as_view(), name='submit_cart'),
    path('changePassword/', views.ChangePassword.as_view(), name='change_password'),
    path('cancelOrder/<pk>', views.CancelOrder.as_view(), name='cancel_order'),
]
