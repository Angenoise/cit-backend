# tracker/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import CustomUser, Document, AuditLog
from .encryption import encrypt_data, decrypt_data


class CustomUserSerializer(serializers.ModelSerializer):
    """Serializer for CustomUser profile."""
    
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'created_at']
        read_only_fields = ['created_at']


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    
    profile = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile']
        read_only_fields = ['id']


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'first_name', 'last_name']
    
    def validate(self, data):
        """Validate that passwords match."""
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already exists.")
        
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("Email already exists.")
        
        return data
    
    def create(self, validated_data):
        """Create user and associated profile."""
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        # Create user profile
        CustomUser.objects.create(user=user, role='user')
        
        return user


class DocumentListSerializer(serializers.ModelSerializer):
    """Serializer for document list view."""
    
    owner_name = serializers.CharField(source='owner.username', read_only=True)
    is_owner = serializers.SerializerMethodField()
    encrypted_id = serializers.CharField(read_only=True)
    
    class Meta:
        model = Document
        fields = [
            'id', 'document_id', 'title', 'description', 'document_type',
            'due_date', 'owner_name', 'is_owner', 'created_at', 'encrypted_id'
        ]
        read_only_fields = ['document_id', 'created_at']
    
    def get_is_owner(self, obj):
        """Check if current user is the owner."""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.owner == request.user
        return False


class DocumentDetailSerializer(serializers.ModelSerializer):
    """Serializer for document detail view."""
    
    owner = UserSerializer(read_only=True)
    is_owner = serializers.SerializerMethodField()
    can_access = serializers.SerializerMethodField()
    encrypted_id = serializers.CharField(read_only=True)
    access_key_display = serializers.SerializerMethodField()
    
    class Meta:
        model = Document
        fields = [
            'id', 'document_id', 'title', 'description', 'document_type',
            'due_date', 'remarks', 'owner', 'is_owner', 'can_access',
            'created_at', 'updated_at', 'file', 'encrypted_id', 'access_key_display'
        ]
        read_only_fields = ['document_id', 'created_at', 'updated_at', 'file']
    
    def get_is_owner(self, obj):
        """Check if current user is the owner."""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.owner == request.user
        return False
    
    def get_can_access(self, obj):
        """Check if current user can access."""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.can_access(request.user)
        return False
    
    def get_access_key_display(self, obj):
        """Return access key only if user is owner."""
        request = self.context.get('request')
        if request and request.user.is_authenticated and obj.owner == request.user:
            return obj.access_key
        return None


class DocumentCreateUpdateSerializer(serializers.ModelSerializer):
    """Serializer for creating and updating documents."""
    
    class Meta:
        model = Document
        fields = [
            'title', 'description', 'document_type', 'due_date', 'remarks', 'file'
        ]
    
    def create(self, validated_data):
        """Create document with current user as owner."""
        validated_data['owner'] = self.context['request'].user
        return Document.objects.create(**validated_data)
    
    def update(self, instance, validated_data):
        """Update document fields."""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for audit logs."""
    
    user_name = serializers.CharField(source='user.username', read_only=True)
    document_title = serializers.CharField(source='document.title', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user_name', 'document_title', 'access_type', 'ip_address',
            'timestamp', 'success', 'details'
        ]
        read_only_fields = ['id', 'timestamp']


class AccessKeyVerificationSerializer(serializers.Serializer):
    """Serializer for verifying access key."""
    
    access_key = serializers.CharField(max_length=32)
    encrypted_id = serializers.CharField()
    
    def validate(self, data):
        """Validate access key and encrypted ID."""
        from .models import Document
        
        try:
            document = Document.objects.get(encrypted_id=data['encrypted_id'])
        except Document.DoesNotExist:
            raise serializers.ValidationError("Document not found.")
        
        if document.access_key != data['access_key']:
            raise serializers.ValidationError("Invalid access key.")
        
        return data


class QRScanSerializer(serializers.Serializer):
    """Serializer for QR scan data."""
    
    encrypted_id = serializers.CharField()
    
    def validate_encrypted_id(self, value):
        """Validate that encrypted ID exists in the system."""
        from .models import Document
        
        if not Document.objects.filter(encrypted_id=value).exists():
            raise serializers.ValidationError("Document not found.")
        
        return value
