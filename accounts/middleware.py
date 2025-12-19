from django.utils import timezone
from .models import ActiveSession
from .utils import get_device_info, get_location_info
import logging

logger = logging.getLogger(__name__)


class SessionTrackingMiddleware:
    """セッションを追跡するミドルウェア"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        if request.user.is_authenticated and request.session.session_key:
            try:
                device_info = get_device_info(request)
                location_info = get_location_info(request)
                
                logger.info(f"Session tracking for user: {request.user.username}")
                logger.info(f"Session key: {request.session.session_key}")
                
                # 現在のセッションを取得または作成
                session, created = ActiveSession.objects.get_or_create(
                    user=request.user,
                    session_key=request.session.session_key,
                    defaults={
                        'ip_address': location_info['ip_address'],
                        'user_agent': device_info['user_agent'],
                        'device_type': device_info['device_type'],
                        'device_name': device_info['device_name'],
                        'browser': device_info['browser'],
                        'os': device_info['os'],
                        'location_city': location_info['city'],
                        'location_country': location_info['country'],
                        'is_current': True,
                    }
                )
                
                if created:
                    logger.info(f"New session created for {request.user.username}")
                else:
                    # 既存セッションの最終アクティビティを更新
                    session.last_activity = timezone.now()
                    session.is_current = True
                    session.save(update_fields=['last_activity', 'is_current'])
                    logger.info(f"Session updated for {request.user.username}")
                
                # 他のセッションのis_currentをFalseに
                ActiveSession.objects.filter(
                    user=request.user
                ).exclude(
                    session_key=request.session.session_key
                ).update(is_current=False)
                
            except Exception as e:
                logger.error(f"Error in SessionTrackingMiddleware: {e}")
        
        response = self.get_response(request)
        return response
