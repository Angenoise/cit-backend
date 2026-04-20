# tracker/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'documents', views.DocumentViewSet, basename='document')

urlpatterns = [
    # Router URLs
    path('', include(router.urls)),
    
    # Authentication endpoints
    path('auth/token/', views.CustomAuthToken.as_view(), name='obtain_token'),
    path('auth/register/', views.register_user, name='register'),
    path('auth/logout/', views.logout_user, name='logout'),
    path('auth/me/', views.get_current_user, name='get_current_user'),
    
    # QR and Access Key endpoints
    path('qr/scan/', views.scan_qr_code, name='scan_qr_code'),
    path('access-key/verify/', views.verify_access_key, name='verify_access_key'),
    
    # Audit Log endpoints
    path('audit-logs/', views.get_audit_logs, name='get_audit_logs'),
    path('audit-logs/<int:document_id>/', views.get_document_audit_logs, name='get_document_audit_logs'),
    
    # Admin endpoints
    path('admin/stats/', views.get_admin_stats, name='admin_stats'),
    path('admin/users/', views.get_all_users, name='get_all_users'),
]
