from django.urls import path, include
from . import views

urlpatterns = [
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.profile_edit_view, name='profile_edit'),
    
    # セッション管理
    path('session/logout/', views.logout_session, name='logout_session'),
    
    # パスキー管理
    path('passkey/delete/', views.delete_passkey, name='delete_passkey'),
    path('passkey/rename/', views.rename_passkey, name='rename_passkey'),
    
    # WebAuthn API
    path('webauthn/register/begin/', views.webauthn_register_begin, name='webauthn_register_begin'),
    path('webauthn/register/complete/', views.webauthn_register_complete, name='webauthn_register_complete'),
    path('webauthn/login/begin/', views.webauthn_login_begin, name='webauthn_login_begin'),
    path('webauthn/login/complete/', views.webauthn_login_complete, name='webauthn_login_complete'),
    path('webauthn/check/', views.check_passkey, name='check_passkey'),
        # ... 既存のURL ...
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    
    # OAuth API エンドポイント
    path('api/oauth/authorize/', views.oauth_authorize, name='oauth_authorize'),
    path('api/oauth/token/', views.oauth_token, name='oauth_token'),
    path('api/oauth/userinfo/', views.oauth_userinfo, name='oauth_userinfo'),
    path('api/oauth/revoke/', views.oauth_revoke, name='oauth_revoke'),
    # TOTP
    path('setup-totp/', views.setup_totp, name='setup_totp'),
    path('disable-totp/', views.disable_totp, name='disable_totp'),
    
    # WebAuthn デバイス管理（統一: webauthn/）
    path('webauthn/devices/', views.webauthn_devices, name='webauthn_devices'),
    path('webauthn/devices/<int:device_id>/rename/', views.rename_webauthn_device, name='rename_webauthn_device'),
    path('webauthn/devices/<int:device_id>/primary/', views.set_primary_webauthn_device, name='set_primary_webauthn_device'),
    path('webauthn/devices/<int:device_id>/delete/', views.delete_webauthn_device, name='delete_webauthn_device'),
    
    # OAuth アプリ
    path('oauth-applications/', views.oauth_applications, name='oauth_applications'),
    path('oauth-applications/<int:token_id>/revoke/', views.revoke_oauth_application, name='revoke_oauth_application'),
    
    # メール確認
    path('verify-email/', views.verify_email, name='verify_email'),
    path('verify-email/<str:token>/', views.verify_email_token, name='verify_email_token'),
    path('backup-codes/', views.backup_codes, name='backup_codes'),
    path('backup-codes/regenerate/', views.regenerate_backup_codes, name='regenerate_backup_codes'),
    # Django標準の認証URL
    path('', include('django.contrib.auth.urls')),
]
