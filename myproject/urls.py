
from django.urls import path

from rsa_signature_generator import views

urlpatterns = [
    path('', views.index, name='index'),
    path('generate_rsa_key/', views.generate_rsa_key, name='generate_rsa_key'),
    path('calculate_hash_and_sign/', views.calculate_hash_and_sign, name='calculate_hash_and_sign'),
    path('verify_signature/', views.verify_signature, name='verify_signature'),

]

