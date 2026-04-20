# tracker/views.py
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.utils import timezone
from django.shortcuts import get_object_or_404

from .models import CustomUser, Document, AuditLog
from .serializers import (
    UserSerializer, UserRegistrationSerializer, DocumentListSerializer,
    DocumentDetailSerializer, DocumentCreateUpdateSerializer,
    AuditLogSerializer, AccessKeyVerificationSerializer, QRScanSerializer,
    CustomUserSerializer
)
from .encryption import decrypt_data


# =====================
# AUTHENTICATION VIEWS
# =====================

class CustomAuthToken(ObtainAuthToken):
    """Custom token authentication view."""
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data,
        })


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_user(request):
    """Register a new user."""
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'message': 'User registered successfully',
            'token': token.key,
            'user': UserSerializer(user).data,
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_current_user(request):
    """Get current authenticated user."""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def logout_user(request):
    """Logout user by deleting token."""
    try:
        request.user.auth_token.delete()
        return Response({'message': 'Logged out successfully'})
    except:
        return Response({'message': 'Already logged out'})


# =====================
# DOCUMENT VIEWS
# =====================

class DocumentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing documents.
    Supports CRUD operations with access control.
    """
    
    serializer_class = DocumentListSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get documents based on user role."""
        user = self.request.user
        
        try:
            if user.profile.is_admin():
                # Admins can see all documents
                return Document.objects.all()
        except:
            pass
        
        # Regular users see only their own documents
        return Document.objects.filter(owner=user)
    
    def get_serializer_class(self):
        """Use different serializers for different actions."""
        if self.action == 'retrieve':
            return DocumentDetailSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return DocumentCreateUpdateSerializer
        return DocumentListSerializer
    
    def get_serializer_context(self):
        """Add request to serializer context."""
        context = super().get_serializer_context()
        context['request'] = self.request
        return context
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve a document with access control."""
        document = self.get_object()
        
        # Check access
        access_key = request.query_params.get('access_key', None)
        if not document.can_access(request.user, access_key):
            return Response(
                {'detail': 'Access denied. You do not have permission to view this document.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Log access
        self._log_access(document, 'direct_access', request)
        
        serializer = self.get_serializer(document)
        return Response(serializer.data)
    
    def destroy(self, request, *args, **kwargs):
        """Delete a document (only owner can delete)."""
        document = self.get_object()
        
        if document.owner != request.user:
            return Response(
                {'detail': 'Only the owner can delete this document.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Delete file if exists
        if document.file:
            default_storage.delete(document.file.name)
        
        document.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_access_key(self, request, pk=None):
        """Get access key for a document (owner only)."""
        document = self.get_object()
        
        if document.owner != request.user:
            return Response(
                {'detail': 'Only the owner can view the access key.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return Response({
            'access_key': document.access_key,
            'document_id': str(document.document_id),
        })
    
    @action(detail=True, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_qr_code(self, request, pk=None):
        """Get QR code for a document."""
        document = self.get_object()
        
        if document.owner != request.user:
            return Response(
                {'detail': 'Only the owner can view the QR code.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            import qrcode
            from io import BytesIO
            import base64
            
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=2,
            )
            qr.add_data(f"doc:{document.encrypted_id}")
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            img_io = BytesIO()
            img.save(img_io, 'PNG')
            img_io.seek(0)
            qr_base64 = base64.b64encode(img_io.getvalue()).decode()
            
            return Response({
                'qr_code': qr_base64,
                'encrypted_id': document.encrypted_id,
            })
        except Exception as e:
            return Response(
                {'detail': f'Error generating QR code: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _log_access(self, document, access_type, request):
        """Log document access."""
        try:
            AuditLog.objects.create(
                user=request.user,
                document=document,
                access_type=access_type,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=True,
            )
        except:
            pass
    
    @staticmethod
    def _get_client_ip(request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# =====================
# QR CODE & ACCESS KEY VIEWS
# =====================

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def scan_qr_code(request):
    """
    Scan and process QR code.
    If user is not logged in, return encrypted_id for login redirect.
    If user is logged in, decrypt and verify access.
    """
    serializer = QRScanSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    encrypted_id = serializer.validated_data['encrypted_id']
    
    try:
        document = Document.objects.get(encrypted_id=encrypted_id)
    except Document.DoesNotExist:
        return Response(
            {'detail': 'Document not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # If user not authenticated, return document info for redirect
    if not request.user.is_authenticated:
        return Response({
            'authenticated': False,
            'message': 'Please login to access this document',
            'encrypted_id': encrypted_id,
        })
    
    # Check access
    if not document.can_access(request.user):
        return Response({
            'authenticated': True,
            'has_access': False,
            'encrypted_id': encrypted_id,
            'message': 'Access denied. You need the access key to view this document.',
        })
    
    # Log successful access
    try:
        AuditLog.objects.create(
            user=request.user,
            document=document,
            access_type='qr_scan',
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True,
        )
    except:
        pass
    
    # Return document access
    serializer = DocumentDetailSerializer(document, context={'request': request})
    return Response({
        'authenticated': True,
        'has_access': True,
        'document': serializer.data,
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def verify_access_key(request):
    """
    Verify access key for a document.
    Used when user has scanned QR code but is not owner.
    """
    serializer = AccessKeyVerificationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        document = Document.objects.get(
            encrypted_id=serializer.validated_data['encrypted_id']
        )
    except Document.DoesNotExist:
        return Response(
            {'detail': 'Document not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Verify access
    if not document.can_access(request.user, serializer.validated_data['access_key']):
        # Log failed access
        try:
            AuditLog.objects.create(
                user=request.user,
                document=document,
                access_type='key_verification',
                ip_address=_get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                details={'reason': 'Invalid access key'},
            )
        except:
            pass
        
        return Response(
            {'detail': 'Invalid access key'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Log successful verification
    try:
        AuditLog.objects.create(
            user=request.user,
            document=document,
            access_type='key_verification',
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True,
        )
    except:
        pass
    
    # Return document
    serializer = DocumentDetailSerializer(document, context={'request': request})
    return Response({
        'message': 'Access verified',
        'document': serializer.data,
    })


# =====================
# AUDIT LOG VIEWS
# =====================

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_audit_logs(request):
    """Get audit logs for authenticated user."""
    try:
        if request.user.profile.is_admin():
            # Admin sees all logs
            logs = AuditLog.objects.all()
        else:
            # Users see only logs for their documents
            logs = AuditLog.objects.filter(document__owner=request.user)
    except:
        # Users see only logs for their documents
        logs = AuditLog.objects.filter(document__owner=request.user)
    
    # Pagination parameters
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 20))
    
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    logs_paginated = logs[start_idx:end_idx]
    
    serializer = AuditLogSerializer(logs_paginated, many=True)
    
    return Response({
        'count': logs.count(),
        'page': page,
        'page_size': page_size,
        'results': serializer.data,
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_document_audit_logs(request, document_id):
    """Get audit logs for a specific document."""
    try:
        document = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response(
            {'detail': 'Document not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if user can view logs
    if document.owner != request.user:
        try:
            if not request.user.profile.is_admin():
                return Response(
                    {'detail': 'Access denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except:
            return Response(
                {'detail': 'Access denied'},
                status=status.HTTP_403_FORBIDDEN
            )
    
    logs = AuditLog.objects.filter(document=document)
    serializer = AuditLogSerializer(logs, many=True)
    
    return Response({
        'document': str(document),
        'logs': serializer.data,
    })


# =====================
# ADMIN VIEWS
# =====================

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_admin_stats(request):
    """Get admin statistics."""
    try:
        if not request.user.profile.is_admin():
            return Response(
                {'detail': 'Access denied. Admin only.'},
                status=status.HTTP_403_FORBIDDEN
            )
    except:
        return Response(
            {'detail': 'Access denied. Admin only.'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    stats = {
        'total_users': User.objects.count(),
        'total_documents': Document.objects.count(),
        'total_audit_logs': AuditLog.objects.count(),
        'documents_by_type': list(
            Document.objects.values('document_type').annotate(count=models.Count('id'))
        ),
    }
    
    return Response(stats)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_all_users(request):
    """Get all users (admin only)."""
    try:
        if not request.user.profile.is_admin():
            return Response(
                {'detail': 'Access denied. Admin only.'},
                status=status.HTTP_403_FORBIDDEN
            )
    except:
        return Response(
            {'detail': 'Access denied. Admin only.'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    
    return Response({
        'count': users.count(),
        'results': serializer.data,
    })


# =====================
# UTILITY FUNCTIONS
# =====================

def _get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# Import models for stats
from django.db import models
