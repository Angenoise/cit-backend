# tracker/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
import string
import random

from .encryption import IDEA, generate_idea_key, encrypt_data, decrypt_data


class CustomUser(models.Model):
    """Extended user model with role-based access."""
    
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Administrator'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'custom_users'
    
    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"
    
    def is_admin(self):
        """Check if user is an admin."""
        return self.role == 'admin'


class Document(models.Model):
    """
    Document model for tracking documents with IDEA encryption.
    Each document has an encrypted ID for QR codes and an access key for sharing.
    """
    
    DOCUMENT_TYPE_CHOICES = [
        ('assignment', 'Assignment'),
        ('project', 'Project'),
        ('exam', 'Exam'),
        ('syllabus', 'Syllabus'),
        ('lecture', 'Lecture Notes'),
        ('other', 'Other'),
    ]
    
    # IDs and keys
    document_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    encrypted_id = models.TextField(editable=False)  # IDEA-encrypted document ID
    access_key = models.CharField(max_length=32, unique=True, editable=False)
    
    # Core fields
    title = models.CharField(max_length=255)
    description = models.TextField()
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPE_CHOICES)
    due_date = models.DateTimeField()
    remarks = models.TextField(blank=True, null=True)
    
    # File upload
    file = models.FileField(upload_to='documents/', null=True, blank=True)
    
    # Metadata
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Encryption key (stored separately for production use)
    encryption_key = models.BinaryField(editable=False)
    
    class Meta:
        db_table = 'documents'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', '-created_at']),
            models.Index(fields=['access_key']),
            models.Index(fields=['document_id']),
        ]
    
    def save(self, *args, **kwargs):
        """Override save to generate encryption key and encrypted ID on creation."""
        if not self.pk:
            # Generate encryption key on first save
            self.encryption_key = generate_idea_key()
            
            # Generate and encrypt document ID
            self.encrypted_id = encrypt_data(str(self.document_id), self.encryption_key)
            
            # Generate unique access key
            self.access_key = self.generate_access_key()
        
        super().save(*args, **kwargs)
    
    @staticmethod
    def generate_access_key():
        """Generate a unique 32-character access key."""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(32))
    
    def decrypt_id(self):
        """Decrypt and return the document ID."""
        try:
            decrypted = decrypt_data(self.encrypted_id, self.encryption_key)
            return decrypted
        except Exception as e:
            raise ValueError(f"Failed to decrypt document ID: {str(e)}")
    
    def get_qr_data(self):
        """Return the data to be encoded in QR code (encrypted document ID)."""
        return self.encrypted_id
    
    def can_access(self, user, access_key=None):
        """
        Check if a user can access this document.
        
        Access is granted if:
        1. User is the owner
        2. User is an admin
        3. User provides the correct access key
        
        Args:
            user: User object
            access_key: Access key to verify
            
        Returns:
            Boolean indicating access permission
        """
        # Owner can always access
        if self.owner == user:
            return True
        
        # Admin can access any document
        try:
            if user.profile.is_admin():
                return True
        except:
            pass
        
        # Check access key
        if access_key and access_key == self.access_key:
            return True
        
        return False
    
    def __str__(self):
        return f"{self.title} (ID: {self.document_id})"


class AuditLog(models.Model):
    """
    Audit log for tracking document access via QR scans and key verification.
    """
    
    ACCESS_TYPE_CHOICES = [
        ('qr_scan', 'QR Code Scan'),
        ('key_verification', 'Access Key Verification'),
        ('direct_access', 'Direct Access'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='audit_logs')
    access_type = models.CharField(max_length=20, choices=ACCESS_TYPE_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=True)
    details = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['document', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user} accessed {self.document.title} via {self.get_access_type_display()}"
