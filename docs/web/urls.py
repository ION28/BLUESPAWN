from django.urls import path
from django.conf.urls import url
from django.views.generic import TemplateView
# from .views import ViewName
from . import views
app_name = 'web'

urlpatterns = [
    path('about/', TemplateView.as_view(template_name='about.html'), name='about'),
]
