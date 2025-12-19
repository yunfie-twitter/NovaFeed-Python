from django.db import models
from django.contrib.auth import get_user_model
import secrets
import pyotp

User = get_user_model()

class DeveloperApplication(models.Model):
    """OAuth 2.0 アプリケーション"""
    developer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='developer_apps')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    website = models.URLField(blank=True)
    logo_url = models.URLField(blank=True)
    
    client_id = models.CharField(max_length=255, unique=True)
    client_secret = models.CharField(max_length=255)
    
    redirect_uris = models.TextField()
    allowed_scopes = models.CharField(max_length=255, default='read profile email')
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Developer Application'
        verbose_name_plural = 'Developer Applications'
    
    def __str__(self):
        return f"{self.name}"


class APIKey(models.Model):
    """APIキー"""
    developer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=255, unique=True)
    secret = models.CharField(max_length=255)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'
    
    def __str__(self):
        return f"{self.name}"


class APILog(models.Model):
    """APIログ"""
    developer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_logs')
    api_key = models.ForeignKey(APIKey, on_delete=models.SET_NULL, null=True, blank=True)
    
    endpoint = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    status_code = models.IntegerField()
    response_time_ms = models.IntegerField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=500, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'API Log'
        verbose_name_plural = 'API Logs'

