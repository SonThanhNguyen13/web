from django.contrib import admin

# Register your models here.
from .models import NguyenThanhSon36User, NguyenThanhSon36Books, NguyenThanhSon36Ordered, NguyenThanhSon36Order

class NguyenThanhSonAdmin(admin.ModelAdmin):
    list_display = ['username', 'password', 'email', 'address', 'phone', 'role']
    list_editable = ['role']

admin.site.register(NguyenThanhSon36User, NguyenThanhSonAdmin)
admin.site.register(NguyenThanhSon36Books)
admin.site.register(NguyenThanhSon36Ordered)
admin.site.register(NguyenThanhSon36Order)