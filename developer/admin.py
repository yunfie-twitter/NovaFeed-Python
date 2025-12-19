from django.contrib import admin
from .models import DeveloperApplication, APIKey, APILog

@admin.register(DeveloperApplication)
class DeveloperApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'developer', 'client_id', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'client_id')
    readonly_fields = ('client_id', 'client_secret', 'created_at', 'updated_at')


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('name', 'developer', 'key', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'key')
    readonly_fields = ('key', 'secret', 'created_at')


@admin.register(APILog)
class APILogAdmin(admin.ModelAdmin):
    list_display = ('developer', 'method', 'endpoint', 'status_code', 'created_at')
    list_filter = ('method', 'status_code', 'created_at')
    search_fields = ('endpoint', 'developer__username')
    readonly_fields = ('created_at',)
