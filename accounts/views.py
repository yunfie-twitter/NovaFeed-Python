from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.views.generic import CreateView
from django.urls import reverse_lazy
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.db.models import Count, Q
from django.core.mail import send_mail

from datetime import timedelta
import json
import base64
import logging
import secrets
import string
import pyotp

from oauth2_provider.models import AccessToken, RefreshToken, Application

from .forms import (
    CustomUserCreationForm,
    CustomUserChangeForm,
    CustomLoginForm,
)

from .models import (
    CustomUser,
    LoginHistory,
    ActiveSession,
    WebAuthnCredential,
    WebAuthnChallenge,
    TOTPDevice,
    BackupCode,
    WebAuthnDevice,
    EmailVerification,
)

from .utils import get_device_info, get_location_info

from .webauthn_utils import (
    get_registration_options,
    verify_registration,
    get_authentication_options,
    verify_authentication,
)

from webauthn import options_to_json


logger = logging.getLogger(__name__)


class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    template_name = 'accounts/signup.html'
    success_url = reverse_lazy('login')
    
    def form_valid(self, form):
        user = form.save()
        messages.success(self.request, 'アカウントが作成されました。ログインしてください。')
        return super().form_valid(form)


# ログイン処理（ログイン履歴を記録）
def login_view(request):
    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            
            # デバイス情報と位置情報を取得
            device_info = get_device_info(request)
            location_info = get_location_info(request)
            
            if user is not None:
                login(request, user)
                
                # ログイン履歴を記録
                LoginHistory.objects.create(
                    user=user,
                    ip_address=location_info['ip_address'],
                    user_agent=device_info['user_agent'],
                    device_type=device_info['device_type'],
                    device_name=device_info['device_name'],
                    browser=device_info['browser'],
                    os=device_info['os'],
                    location_city=location_info['city'],
                    location_country=location_info['country'],
                    status='success'
                )
                
                messages.success(request, f'{user.get_display_name()}さん、ようこそ！')
                return redirect('home')
            else:
                # 失敗したログイン試行も記録
                try:
                    user_obj = CustomUser.objects.get(username=username)
                    LoginHistory.objects.create(
                        user=user_obj,
                        ip_address=location_info['ip_address'],
                        user_agent=device_info['user_agent'],
                        device_type=device_info['device_type'],
                        device_name=device_info['device_name'],
                        browser=device_info['browser'],
                        os=device_info['os'],
                        location_city=location_info['city'],
                        location_country=location_info['country'],
                        status='failed'
                    )
                except CustomUser.DoesNotExist:
                    pass
    else:
        form = CustomLoginForm()
    
    return render(request, 'accounts/login.html', {'form': form})


# ログアウト
@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'ログアウトしました')
    return redirect('login')


# プロフィール表示
@login_required
def profile_view(request):
    return render(request, 'accounts/profile.html', {'user': request.user})


# プロフィール編集
@login_required
def profile_edit_view(request):
    if request.method == 'POST':
        form = CustomUserChangeForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'プロフィールを更新しました')
            return redirect('profile')
        else:
            messages.error(request, 'エラーが発生しました。入力内容を確認してください。')
    else:
        form = CustomUserChangeForm(instance=request.user)
    return render(request, 'accounts/profile_edit.html', {'form': form})


# ホームビュー（ダッシュボード）
@login_required
def home(request):
    user = request.user
    
    # 統計情報を取得
    active_sessions_count = ActiveSession.objects.filter(user=user).count()
    
    # 過去30日間のログイン回数
    thirty_days_ago = timezone.now() - timedelta(days=30)
    login_count = LoginHistory.objects.filter(
        user=user,
        status='success',
        timestamp__gte=thirty_days_ago
    ).count()
    
    # パスキー数
    passkey_count = WebAuthnCredential.objects.filter(user=user).count()
    
    # アクティブセッション一覧
    active_sessions = ActiveSession.objects.filter(user=user).order_by('-last_activity')
    
    # ログイン履歴
    login_history = LoginHistory.objects.filter(user=user).order_by('-timestamp')[:20]
    
    # パスキー一覧
    passkeys = WebAuthnCredential.objects.filter(user=user).order_by('-created_at')
    
    # 最終ログイン情報
    last_login = LoginHistory.objects.filter(
        user=user,
        status='success'
    ).exclude(
        timestamp=user.last_login
    ).order_by('-timestamp').first()
    
    # デバッグ用
    logger.debug(f"Active sessions count: {active_sessions_count}")
    logger.debug(f"Login history count: {login_history.count()}")
    logger.debug(f"Passkeys count: {passkey_count}")
    
    context = {
        'active_sessions_count': active_sessions_count,
        'login_count': login_count,
        'passkey_count': passkey_count,
        'active_sessions': active_sessions,
        'login_history': login_history,
        'passkeys': passkeys,
        'last_login': last_login,
    }
    
    return render(request, 'home.html', context)


# セッションログアウト
@login_required
@require_POST
def logout_session(request):
    """特定のセッションをログアウト"""
    session_key = request.POST.get('session_key')
    
    if not session_key:
        return JsonResponse({'error': 'セッションキーが必要です'}, status=400)
    
    # 現在のセッションは削除できない
    if session_key == request.session.session_key:
        return JsonResponse({'error': '現在のセッションは削除できません'}, status=400)
    
    try:
        # セッションを削除
        session = ActiveSession.objects.get(
            user=request.user,
            session_key=session_key
        )
        
        # Djangoのセッションテーブルからも削除
        try:
            Session.objects.get(session_key=session_key).delete()
        except Session.DoesNotExist:
            pass
        
        session.delete()
        
        return JsonResponse({'success': True, 'message': 'セッションをログアウトしました'})
    except ActiveSession.DoesNotExist:
        return JsonResponse({'error': 'セッションが見つかりません'}, status=404)


# パスキー削除
@login_required
@require_POST
def delete_passkey(request):
    """パスキーを削除"""
    passkey_id = request.POST.get('passkey_id')
    
    if not passkey_id:
        return JsonResponse({'error': 'パスキーIDが必要です'}, status=400)
    
    try:
        passkey = WebAuthnCredential.objects.get(
            id=passkey_id,
            user=request.user
        )
        device_name = passkey.device_name
        passkey.delete()
        
        return JsonResponse({
            'success': True,
            'message': f'{device_name}を削除しました'
        })
    except WebAuthnCredential.DoesNotExist:
        return JsonResponse({'error': 'パスキーが見つかりません'}, status=404)


# パスキー名前変更
@login_required
@require_POST
def rename_passkey(request):
    """パスキーの名前を変更"""
    passkey_id = request.POST.get('passkey_id')
    new_name = request.POST.get('new_name')
    
    if not passkey_id or not new_name:
        return JsonResponse({'error': 'パスキーIDと新しい名前が必要です'}, status=400)
    
    try:
        passkey = WebAuthnCredential.objects.get(
            id=passkey_id,
            user=request.user
        )
        passkey.device_name = new_name
        passkey.save()
        
        return JsonResponse({
            'success': True,
            'message': '名前を変更しました'
        })
    except WebAuthnCredential.DoesNotExist:
        return JsonResponse({'error': 'パスキーが見つかりません'}, status=404)

# パスキー登録開始
@login_required
@require_http_methods(["POST"])
def webauthn_register_begin(request):
    """パスキー登録を開始"""
    try:
        user = request.user
        
        # 登録オプションを生成
        result = get_registration_options(user)
        
        # チャレンジを保存
        WebAuthnChallenge.objects.create(
            user=user,
            challenge=result['challenge'],
            challenge_type='registration'
        )
        
        # オプションをJSON形式で返す
        options_json = options_to_json(result['options'])
        
        return JsonResponse({
            'success': True,
            'options': json.loads(options_json)
        })
        
    except Exception as e:
        logger.error(f"Error in webauthn_register_begin: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


# パスキー登録完了
@login_required
@require_http_methods(["POST"])
def webauthn_register_complete(request):
    """パスキー登録を完了"""
    try:
        user = request.user
        data = json.loads(request.body)
        
        # チャレンジを取得
        challenge_obj = WebAuthnChallenge.objects.filter(
            user=user,
            challenge_type='registration'
        ).order_by('-created_at').first()
        
        if not challenge_obj:
            return JsonResponse({
                'success': False,
                'error': 'チャレンジが見つかりません'
            }, status=400)
        
        # 登録を検証
        verification = verify_registration(
            user=user,
            credential_data=data,
            challenge=challenge_obj.challenge
        )
        
        # デバイス名を生成
        device_name = data.get('device_name', f"パスキー {timezone.now().strftime('%Y%m%d')}")
        
        # 認証情報を保存
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id=verification['credential_id'],
            public_key=verification['public_key'],
            sign_count=verification['sign_count'],
            device_name=device_name,
            device_type='platform',
        )
        
        # チャレンジを削除
        challenge_obj.delete()
        
        logger.info(f"Passkey registered for user: {user.username}")
        
        return JsonResponse({
            'success': True,
            'message': 'パスキーが登録されました',
            'credential_id': credential.id
        })
        
    except Exception as e:
        logger.error(f"Error in webauthn_register_complete: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


# パスキー認証開始
@require_http_methods(["POST"])
def webauthn_login_begin(request):
    """パスキー認証を開始"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        
        if not username:
            return JsonResponse({
                'success': False,
                'error': 'ユーザー名が必要です'
            }, status=400)
        
        # ユーザーを取得
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'ユーザーが見つかりません'
            }, status=404)
        
        # 登録済みの認証情報を取得
        credentials = WebAuthnCredential.objects.filter(user=user)
        
        if not credentials.exists():
            return JsonResponse({
                'success': False,
                'error': '登録されたパスキーがありません'
            }, status=400)
        
        # 認証オプションを生成
        result = get_authentication_options(user, credentials)
        
        # チャレンジを保存
        WebAuthnChallenge.objects.create(
            user=user,
            challenge=result['challenge'],
            challenge_type='authentication'
        )
        
        # オプションをJSON形式で返す
        options_json = options_to_json(result['options'])
        
        return JsonResponse({
            'success': True,
            'options': json.loads(options_json),
            'user_id': user.id
        })
        
    except Exception as e:
        logger.error(f"Error in webauthn_login_begin: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


# パスキー認証完了
@require_http_methods(["POST"])
def webauthn_login_complete(request):
    """パスキー認証を完了"""
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        
        logger.info(f"Login complete request for user_id: {user_id}")
        logger.info(f"Credential data keys: {data.keys()}")
        
        if not user_id:
            return JsonResponse({
                'success': False,
                'error': 'ユーザーIDが必要です'
            }, status=400)
        
        # ユーザーを取得
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'ユーザーが見つかりません'
            }, status=404)
        
        # チャレンジを取得
        challenge_obj = WebAuthnChallenge.objects.filter(
            user=user,
            challenge_type='authentication'
        ).order_by('-created_at').first()
        
        if not challenge_obj:
            return JsonResponse({
                'success': False,
                'error': 'チャレンジが見つかりません'
            }, status=400)
        
        # 認証情報を取得（credential.idを直接使用）
        credential_id_from_client = data.get('id')
        logger.info(f"Credential ID from client: {credential_id_from_client}")
        
        # データベースに保存されているcredential_idと照合
        # Base64URLエンコードされたIDで検索
        stored_credential = None
        all_credentials = WebAuthnCredential.objects.filter(user=user)
        
        for cred in all_credentials:
            # credential_idをBase64URLデコードしてから比較
            try:
                # クライアントから来たIDをBase64URLエンコードして比較
                if cred.credential_id == credential_id_from_client or \
                   base64.urlsafe_b64encode(
                       base64.urlsafe_b64decode(cred.credential_id + '=' * (4 - len(cred.credential_id) % 4))
                   ).decode('utf-8').rstrip('=') == credential_id_from_client:
                    stored_credential = cred
                    break
            except Exception as e:
                logger.error(f"Error comparing credential ID: {e}")
                continue
        
        if not stored_credential:
            logger.error(f"No matching credential found for ID: {credential_id_from_client}")
            logger.error(f"Available credentials: {[c.credential_id for c in all_credentials]}")
            return JsonResponse({
                'success': False,
                'error': '認証情報が見つかりません'
            }, status=404)
        
        logger.info(f"Found matching credential: {stored_credential.device_name}")
        
        # 認証を検証
        try:
            verification = verify_authentication(
                user=user,
                credential_data=data,
                challenge=challenge_obj.challenge,
                stored_credential=stored_credential
            )
        except Exception as e:
            logger.error(f"Verification error: {e}")
            import traceback
            traceback.print_exc()
            return JsonResponse({
                'success': False,
                'error': f'検証エラー: {str(e)}'
            }, status=400)
        
        if verification['verified']:
            # サインカウントを更新
            stored_credential.sign_count = verification['new_sign_count']
            stored_credential.last_used = timezone.now()
            stored_credential.save()
            
            # ログイン
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            # ログイン履歴を記録
            device_info = get_device_info(request)
            location_info = get_location_info(request)
            
            LoginHistory.objects.create(
                user=user,
                ip_address=location_info['ip_address'],
                user_agent=device_info['user_agent'],
                device_type=device_info['device_type'],
                device_name=f"{device_info['device_name']} (パスキー)",
                browser=device_info['browser'],
                os=device_info['os'],
                location_city=location_info['city'],
                location_country=location_info['country'],
                status='success'
            )
            
            # チャレンジを削除
            challenge_obj.delete()
            
            logger.info(f"Passkey authentication successful for user: {user.username}")
            
            return JsonResponse({
                'success': True,
                'message': 'ログインしました',
                'redirect_url': '/'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': '認証に失敗しました'
            }, status=400)
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return JsonResponse({
            'success': False,
            'error': 'リクエストデータが不正です'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in webauthn_login_complete: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


@require_http_methods(["POST"])
def check_passkey(request):
    """ユーザーのパスキーの有無を確認"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        
        if not username:
            return JsonResponse({'has_passkey': False})
        
        try:
            user = CustomUser.objects.get(username=username)
            has_passkey = WebAuthnCredential.objects.filter(user=user).exists()
            
            return JsonResponse({
                'has_passkey': has_passkey,
                'user_exists': True
            })
        except CustomUser.DoesNotExist:
            return JsonResponse({
                'has_passkey': False,
                'user_exists': False
            })
            
    except Exception as e:
        logger.error(f"Error checking passkey: {e}")
        return JsonResponse({'has_passkey': False}, status=400)

@require_http_methods(["GET", "POST"])
def oauth_authorize(request):
    """OAuth2 認可エンドポイント"""
    try:
        client_id = request.GET.get('client_id') or request.POST.get('client_id')
        response_type = request.GET.get('response_type', 'code')
        redirect_uri = request.GET.get('redirect_uri') or request.POST.get('redirect_uri')
        scope = request.GET.get('scope', 'read') or request.POST.get('scope', 'read')
        state = request.GET.get('state') or request.POST.get('state')
        
        if not all([client_id, redirect_uri]):
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'client_idとredirect_uriが必要です'
            }, status=400)
        
        # アプリケーションを確認
        try:
            app = Application.objects.get(client_id=client_id)
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_client',
                'error_description': 'クライアントIDが見つかりません'
            }, status=400)
        
        if not request.user.is_authenticated:
            # ログインが必要な場合は、ログインページにリダイレクト
            from django.http import urlencode
            params = {
                'client_id': client_id,
                'response_type': response_type,
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': state,
            }
            return redirect(f'/accounts/login/?next=/api/oauth/authorize/?{"&".join([f"{k}={v}" for k, v in params.items()])}')
        
        if request.method == 'POST':
            # ユーザーが認可を承認
            # 認可コードを生成
            auth_code = secrets.token_urlsafe(32)
            
            # セッションに保存
            request.session[f'oauth_auth_code_{auth_code}'] = {
                'client_id': client_id,
                'user_id': request.user.id,
                'scope': scope,
                'redirect_uri': redirect_uri,
            }
            request.session.save()
            
            logger.info(f"OAuth authorization granted for user: {request.user.username}, client: {client_id}")
            
            # リダイレクト
            redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"
            return redirect(redirect_url)
        
        # GET リクエスト：認可画面を表示
        context = {
            'client_id': client_id,
            'app_name': app.name,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'cancel_url': redirect_uri + '?error=access_denied&state=' + (state or ''),
        }
        
        return render(request, 'accounts/oauth_authorize.html', context)
        
    except Exception as e:
        logger.error(f"OAuth authorize error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'error': 'server_error',
            'error_description': str(e)
        }, status=500)
    
# OAuth2 トークンエンドポイント
@require_http_methods(["POST"])
@csrf_exempt
def oauth_token(request):
    """OAuth2 トークンエンドポイント"""
    try:
        grant_type = request.POST.get('grant_type')
        
        if grant_type == 'authorization_code':
            # 認可コードを使用してトークンを取得
            code = request.POST.get('code')
            client_id = request.POST.get('client_id')
            client_secret = request.POST.get('client_secret')
            redirect_uri = request.POST.get('redirect_uri')
            
            if not all([code, client_id, client_secret, redirect_uri]):
                return JsonResponse({
                    'error': 'invalid_request',
                    'error_description': '必須パラメータが不足しています'
                }, status=400)
            
            # アプリケーションを確認
            try:
                app = Application.objects.get(
                    client_id=client_id,
                    client_secret=client_secret
                )
            except Application.DoesNotExist:
                return JsonResponse({
                    'error': 'invalid_client',
                    'error_description': 'クライアントの認証に失敗しました'
                }, status=400)
            
            # 認可コードを確認
            auth_data = request.session.get(f'oauth_auth_code_{code}')
            if not auth_data:
                return JsonResponse({
                    'error': 'invalid_grant',
                    'error_description': '認可コードが無効です'
                }, status=400)
            
            # ユーザーを取得
            try:
                user = CustomUser.objects.get(id=auth_data['user_id'])
            except CustomUser.DoesNotExist:
                return JsonResponse({
                    'error': 'server_error',
                    'error_description': 'ユーザーが見つかりません'
                }, status=500)
            
            # アクセストークンを生成
            access_token = secrets.token_urlsafe(64)
            refresh_token = secrets.token_urlsafe(64)
            
            # トークンを保存
            AccessToken.objects.create(
                token=access_token,
                application=app,
                user=user,
                scope=auth_data['scope'],
                expires=timezone.now() + timedelta(hours=10)
            )
            
            RefreshToken.objects.create(
                token=refresh_token,
                application=app,
                user=user,
                access_token=AccessToken.objects.get(token=access_token)
            )
            
            # 認可コードを削除
            del request.session[f'oauth_auth_code_{code}']
            request.session.save()
            
            logger.info(f"OAuth token issued for user: {user.username}")
            
            return JsonResponse({
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': 36000,
                'refresh_token': refresh_token,
                'scope': auth_data['scope'],
            })
            
        elif grant_type == 'refresh_token':
            # リフレッシュトークンを使用してアクセストークンを更新
            refresh_token = request.POST.get('refresh_token')
            client_id = request.POST.get('client_id')
            client_secret = request.POST.get('client_secret')
            
            if not all([refresh_token, client_id, client_secret]):
                return JsonResponse({
                    'error': 'invalid_request',
                    'error_description': '必須パラメータが不足しています'
                }, status=400)
            
            try:
                app = Application.objects.get(
                    client_id=client_id,
                    client_secret=client_secret
                )
                ref_token = RefreshToken.objects.get(
                    token=refresh_token,
                    application=app
                )
            except (Application.DoesNotExist, RefreshToken.DoesNotExist):
                return JsonResponse({
                    'error': 'invalid_grant',
                    'error_description': 'リフレッシュトークンが無効です'
                }, status=400)
            
            # 新しいアクセストークンを生成
            new_access_token = secrets.token_urlsafe(64)
            
            AccessToken.objects.create(
                token=new_access_token,
                application=app,
                user=ref_token.user,
                scope=ref_token.access_token.scope,
                expires=timezone.now() + timedelta(hours=10)
            )
            
            logger.info(f"OAuth token refreshed for user: {ref_token.user.username}")
            
            return JsonResponse({
                'access_token': new_access_token,
                'token_type': 'Bearer',
                'expires_in': 36000,
                'scope': ref_token.access_token.scope,
            })
        
        else:
            return JsonResponse({
                'error': 'unsupported_grant_type',
                'error_description': 'サポートされていないgrant_typeです'
            }, status=400)
            
    except Exception as e:
        logger.error(f"OAuth token error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'error': 'server_error',
            'error_description': str(e)
        }, status=500)


# ユーザー情報エンドポイント
@require_http_methods(["GET"])
def oauth_userinfo(request):
    """OAuth2 ユーザー情報エンドポイント"""
    try:
        # Authorizationヘッダーからトークンを取得
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return JsonResponse({
                'error': 'invalid_token',
                'error_description': 'トークンが指定されていません'
            }, status=401)
        
        token = auth_header[7:]
        
        # トークンを検証
        try:
            access_token = AccessToken.objects.get(token=token)
        except AccessToken.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_token',
                'error_description': 'トークンが無効です'
            }, status=401)
        
        # トークンの有効期限を確認
        if access_token.is_expired():
            return JsonResponse({
                'error': 'invalid_token',
                'error_description': 'トークンが期限切れです'
            }, status=401)
        
        user = access_token.user
        
        # ユーザー情報を返す
        userinfo = {
            'sub': str(user.id),
            'username': user.username,
            'email': user.email,
            'email_verified': True,
            'name': user.get_display_name(),
            'given_name': user.first_name,
            'family_name': user.last_name,
            'picture': None,  # プロフィール画像URL（必要に応じて追加）
            'updated_at': int(user.last_login.timestamp()) if user.last_login else None,
        }
        
        logger.info(f"OAuth userinfo requested for user: {user.username}")
        
        return JsonResponse(userinfo)
        
    except Exception as e:
        logger.error(f"OAuth userinfo error: {e}")
        return JsonResponse({
            'error': 'server_error',
            'error_description': str(e)
        }, status=500)


# トークン取り消しエンドポイント
@require_http_methods(["POST"])
@csrf_exempt
def oauth_revoke(request):
    """OAuth2 トークン取り消しエンドポイント"""
    try:
        token = request.POST.get('token')
        client_id = request.POST.get('client_id')
        client_secret = request.POST.get('client_secret')
        
        if not all([token, client_id, client_secret]):
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': '必須パラメータが不足しています'
            }, status=400)
        
        # アプリケーションを確認
        try:
            app = Application.objects.get(
                client_id=client_id,
                client_secret=client_secret
            )
        except Application.DoesNotExist:
            return JsonResponse({
                'error': 'invalid_client',
                'error_description': 'クライアントの認証に失敗しました'
            }, status=400)
        
        # トークンを削除
        try:
            access_token = AccessToken.objects.get(token=token, application=app)
            access_token.delete()
        except AccessToken.DoesNotExist:
            pass
        
        logger.info(f"OAuth token revoked for client: {client_id}")
        
        return JsonResponse({'status': 'ok'})
        
    except Exception as e:
        logger.error(f"OAuth revoke error: {e}")
        return JsonResponse({
            'error': 'server_error',
            'error_description': str(e)
        }, status=500)
    
@login_required
def setup_totp(request):
    """TOTP設定画面"""
    user = request.user
    totp_device, created = TOTPDevice.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        data = json.loads(request.body)
        token = data.get('token')
        
        if totp_device.verify_token(token):
            totp_device.is_confirmed = True
            totp_device.save()
            
            # バックアップコード生成
            BackupCode.objects.filter(user=user).delete()
            codes = []
            for _ in range(10):
                code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
                BackupCode.objects.create(user=user, code=code)
                codes.append(code)
            
            return JsonResponse({
                'success': True,
                'backup_codes': codes,
            })
        else:
            return JsonResponse({'success': False, 'error': '無効なトークンです'}, status=400)
    
    # 新しいシークレット生成
    if not totp_device.is_confirmed:
        totp_device.secret = pyotp.random_base32()
        totp_device.save()
    
    qr_code = totp_device.generate_qr_code()
    
    context = {
        'qr_code': qr_code,
        'secret': totp_device.secret,
        'is_confirmed': totp_device.is_confirmed,
    }
    
    return render(request, 'accounts/setup_totp.html', context)


@login_required
@require_http_methods(["POST"])
def disable_totp(request):
    """TOTP無効化"""
    user = request.user
    TOTPDevice.objects.filter(user=user).delete()
    BackupCode.objects.filter(user=user).delete()
    return JsonResponse({'success': True})


# ====== WebAuthn デバイス管理 ======

@login_required
def webauthn_devices(request):
    """WebAuthnデバイス一覧"""
    devices = WebAuthnDevice.objects.filter(user=request.user).order_by('-is_primary', '-last_used')
    context = {'devices': devices}
    return render(request, 'accounts/webauthn_devices.html', context)


@login_required
@require_http_methods(["POST"])
def rename_webauthn_device(request, device_id):
    """WebAuthnデバイスを名前変更"""
    device = get_object_or_404(WebAuthnDevice, id=device_id, user=request.user)
    data = json.loads(request.body)
    
    device.device_name = data.get('name', device.device_name)
    device.save()
    
    return JsonResponse({'success': True})


@login_required
@require_http_methods(["POST"])
def set_primary_webauthn_device(request, device_id):
    """WebAuthnデバイスをプライマリに設定"""
    device = get_object_or_404(WebAuthnDevice, id=device_id, user=request.user)
    
    # 他のプライマリを外す
    WebAuthnDevice.objects.filter(user=request.user, is_primary=True).update(is_primary=False)
    
    # このデバイスをプライマリに
    device.is_primary = True
    device.save()
    
    return JsonResponse({'success': True})


@login_required
@require_http_methods(["POST"])
def delete_webauthn_device(request, device_id):
    """WebAuthnデバイスを削除"""
    device = get_object_or_404(WebAuthnDevice, id=device_id, user=request.user)
    device.delete()
    return JsonResponse({'success': True})


# ====== OAuth アプリ権限管理 ======

@login_required
def oauth_applications(request):
    """接続しているOAuthアプリケーション一覧"""
    from oauth2_provider.models import AccessToken
    from django.utils import timezone
    
    user = request.user
    
    # 有効なアクセストークンを取得（expires が未来の日付）
    access_tokens = AccessToken.objects.filter(user=user).exclude(
        expires__lt=timezone.now()
    )
    
    apps = []
    seen_apps = set()
    
    for token in access_tokens:
        app_id = token.application.id
        if app_id not in seen_apps:
            app = {
                'token_id': token.id,
                'application': token.application,
                'scopes': token.scope,
                'granted_at': token.created,
                'expires_at': token.expires,
            }
            apps.append(app)
            seen_apps.add(app_id)
    
    context = {'apps': apps}
    return render(request, 'accounts/oauth_applications.html', context)


@login_required
@require_http_methods(["POST"])
def revoke_oauth_application(request, token_id):
    """OAuthアプリケーションの権限を取り消す"""
    from oauth2_provider.models import AccessToken, RefreshToken
    
    token = get_object_or_404(AccessToken, id=token_id, user=request.user)
    
    # リフレッシュトークンも削除
    RefreshToken.objects.filter(access_token=token).delete()
    
    # アクセストークン削除
    token.delete()
    
    return JsonResponse({'success': True})



# ====== メール確認（任意） ======

@login_required
def verify_email(request):
    """メール確認画面"""
    user = request.user
    
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        
        # トークン生成
        token = EmailVerification.generate_token()
        expires_at = timezone.now() + timedelta(hours=24)
        
        verification = EmailVerification.objects.create(
            user=user,
            email=email,
            token=token,
            expires_at=expires_at,
        )
        
        # メール送信（実装例）
        from django.core.mail import send_mail
        verify_url = f"http://localhost:8000/accounts/verify-email/{token}/"
        
        send_mail(
            'Enova ID - メール確認',
            f'以下のリンクをクリックしてメールを確認してください:\n{verify_url}',
            'noreply@enova-id.com',
            [email],
            fail_silently=False,
        )
        
        return JsonResponse({
            'success': True,
            'message': 'メール送信完了',
        })
    
    context = {}
    return render(request, 'accounts/verify_email.html', context)


def verify_email_token(request, token):
    """メール確認トークン検証"""
    verification = get_object_or_404(EmailVerification, token=token)
    
    if verification.is_verified:
        return redirect('/accounts/settings/?verified=already')
    
    if timezone.now() > verification.expires_at:
        return redirect('/accounts/settings/?verified=expired')
    
    verification.is_verified = True
    verification.verified_at = timezone.now()
    verification.save()
    
    return redirect('/accounts/settings/?verified=success')


@login_required
def backup_codes(request):
    """バックアップコード表示"""
    user = request.user
    codes = BackupCode.objects.filter(user=user, is_used=False)
    
    context = {'codes': codes}
    return render(request, 'accounts/backup_codes.html', context)


@login_required
@require_http_methods(["POST"])
def regenerate_backup_codes(request):
    """バックアップコード再生成"""
    user = request.user
    
    # 古いコードを削除
    BackupCode.objects.filter(user=user).delete()
    
    # 新しいコード生成
    codes = []
    for _ in range(10):
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        BackupCode.objects.create(user=user, code=code)
        codes.append(code)
    
    return JsonResponse({'success': True, 'codes': codes})