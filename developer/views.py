from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q
from django.utils import timezone
import secrets
import json
from datetime import timedelta
from .models import DeveloperApplication, APIKey, APILog

@login_required
def dashboard(request):
    """ダッシュボード"""
    user = request.user
    
    apps_count = DeveloperApplication.objects.filter(developer=user).count()
    api_keys_count = APIKey.objects.filter(developer=user).count()
    api_calls_month = APILog.objects.filter(developer=user).count()
    recent_logs = APILog.objects.filter(developer=user).order_by('-created_at')[:10]
    
    context = {
        'apps_count': apps_count,
        'api_keys_count': api_keys_count,
        'api_calls_month': api_calls_month,
        'recent_logs': recent_logs,
    }
    
    return render(request, 'developer/dashboard.html', context)


@login_required
def applications_list(request):
    """アプリケーション一覧"""
    apps = DeveloperApplication.objects.filter(developer=request.user).order_by('-created_at')
    context = {'applications': apps}
    return render(request, 'developer/applications_list.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def application_create(request):
    """アプリケーション作成"""
    if request.method == 'POST':
        data = json.loads(request.body)
        
        app = DeveloperApplication.objects.create(
            developer=request.user,
            name=data['name'],
            description=data.get('description', ''),
            website=data.get('website', ''),
            redirect_uris=data['redirect_uris'],
            allowed_scopes=data.get('allowed_scopes', 'read profile email'),
            client_id=secrets.token_urlsafe(32),
            client_secret=secrets.token_urlsafe(64),
        )
        
        return JsonResponse({
            'success': True,
            'app_id': app.id,
            'client_id': app.client_id,
            'client_secret': app.client_secret,
        })
    
    return render(request, 'developer/application_create.html')


@login_required
def application_edit(request, app_id):
    """アプリケーション編集"""
    app = get_object_or_404(DeveloperApplication, id=app_id, developer=request.user)
    
    if request.method == 'POST':
        data = json.loads(request.body)
        
        app.name = data.get('name', app.name)
        app.description = data.get('description', app.description)
        app.website = data.get('website', app.website)
        app.redirect_uris = data.get('redirect_uris', app.redirect_uris)
        app.allowed_scopes = data.get('allowed_scopes', app.allowed_scopes)
        app.is_active = data.get('is_active', app.is_active)
        app.save()
        
        return JsonResponse({'success': True})
    
    context = {'app': app}
    return render(request, 'developer/application_edit.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def application_delete(request, app_id):
    """アプリケーション削除"""
    app = get_object_or_404(DeveloperApplication, id=app_id, developer=request.user)
    
    if request.method == 'POST':
        app.delete()
        return JsonResponse({'success': True})
    
    return render(request, 'developer/application_confirm_delete.html', {'app': app})


@login_required
def application_stats(request, app_id):
    """アプリケーション統計"""
    app = get_object_or_404(DeveloperApplication, id=app_id, developer=request.user)
    
    # API呼び出しログを取得（スライスの前に order_by）
    logs = APILog.objects.filter(developer=request.user).order_by('-created_at')[:50]
    
    # 日別統計
    from django.db.models.functions import TruncDate
    daily_stats = APILog.objects.filter(developer=request.user).annotate(
        date=TruncDate('created_at')
    ).values('date').annotate(
        count=Count('id'),
        errors=Count('id', filter=Q(status_code__gte=400))
    ).order_by('date')
    
    context = {
        'app': app,
        'logs': logs,
        'daily_stats': list(daily_stats),
    }
    return render(request, 'developer/application_stats.html', context)


@login_required
def api_keys_list(request):
    """APIキー一覧"""
    api_keys = APIKey.objects.filter(developer=request.user).order_by('-created_at')
    context = {'api_keys': api_keys}
    return render(request, 'developer/api_keys_list.html', context)


@login_required
@require_http_methods(["POST"])
def api_key_create(request):
    """APIキー作成"""
    data = json.loads(request.body)
    
    api_key = APIKey.objects.create(
        developer=request.user,
        name=data['name'],
        key=secrets.token_urlsafe(32),
        secret=secrets.token_urlsafe(64),
    )
    
    return JsonResponse({
        'success': True,
        'key': api_key.key,
        'secret': api_key.secret,
    })


@login_required
@require_http_methods(["POST"])
def api_key_delete(request, key_id):
    """APIキー削除"""
    api_key = get_object_or_404(APIKey, id=key_id, developer=request.user)
    api_key.delete()
    return JsonResponse({'success': True})


@login_required
@require_http_methods(["POST"])
def api_key_regenerate(request, key_id):
    """APIキー再生成"""
    api_key = get_object_or_404(APIKey, id=key_id, developer=request.user)
    
    api_key.secret = secrets.token_urlsafe(64)
    api_key.save()
    
    return JsonResponse({
        'success': True,
        'secret': api_key.secret,
    })


@login_required
def api_logs(request):
    """API呼び出しログ"""
    logs = APILog.objects.filter(developer=request.user).order_by('-created_at')
    
    # フィルタリング
    endpoint = request.GET.get('endpoint')
    method = request.GET.get('method')
    status = request.GET.get('status')
    
    if endpoint:
        logs = logs.filter(endpoint__icontains=endpoint)
    if method:
        logs = logs.filter(method=method)
    if status:
        logs = logs.filter(status_code=int(status))
    
    # ページネーション
    from django.core.paginator import Paginator
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'logs': page_obj.object_list,
        'methods': ['GET', 'POST', 'PUT', 'DELETE'],
    }
    return render(request, 'developer/api_logs.html', context)


@login_required
def documentation(request):
    """ドキュメント一覧"""
    return render(request, 'developer/documentation.html')
