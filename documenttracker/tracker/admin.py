# tracker/admin.py
from django.contrib import admin
from .models import CustomUser, Document, AuditLog

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'created_at']
    list_filter = ['role', 'created_at']
    search_fields = ['user__username', 'user__email']

@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['title', 'owner', 'document_type', 'due_date', 'created_at']
    list_filter = ['document_type', 'created_at', 'owner']
    search_fields = ['title', 'description', 'owner__username']
    readonly_fields = ['document_id', 'encrypted_id', 'access_key', 'encryption_key', 'created_at', 'updated_at']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'document', 'access_type', 'timestamp', 'success']
    list_filter = ['access_type', 'success', 'timestamp']
    search_fields = ['user__username', 'document__title']
    readonly_fields = ['timestamp']
