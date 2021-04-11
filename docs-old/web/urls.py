from django.urls import path
from django.conf.urls import url
from django.views.generic import TemplateView
from .views import UploadScanView
from . import views
app_name = 'web'

urlpatterns = [
    path('about/', TemplateView.as_view(template_name='about.html'), name='about'),
    path('quickstart/', TemplateView.as_view(template_name='quickstart.html'), name='quickstart'),
    path('coverage/', TemplateView.as_view(template_name='coverage.html'), name='coverage'),
    path('report/', UploadScanView, name='report'),
]
