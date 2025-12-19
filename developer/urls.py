from django.urls import path
from . import views

app_name = 'developer'

urlpatterns = [
    # ダッシュボード
    path('', views.dashboard, name='dashboard'),
    
    # アプリケーション管理
    path('applications/', views.applications_list, name='applications_list'),
    path('applications/create/', views.application_create, name='application_create'),
    path('applications/<int:app_id>/edit/', views.application_edit, name='application_edit'),
    path('applications/<int:app_id>/delete/', views.application_delete, name='application_delete'),
    path('applications/<int:app_id>/stats/', views.application_stats, name='application_stats'),
    
    # APIキー管理
    path('api-keys/', views.api_keys_list, name='api_keys_list'),
    path('api-keys/create/', views.api_key_create, name='api_key_create'),
    path('api-keys/<int:key_id>/delete/', views.api_key_delete, name='api_key_delete'),
    path('api-keys/<int:key_id>/regenerate/', views.api_key_regenerate, name='api_key_regenerate'),
    
    # ログ
    path('logs/', views.api_logs, name='api_logs'),
    
    # ドキュメント
    path('docs/', views.documentation, name='documentation'),
]
