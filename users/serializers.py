from rest_framework import serializers
from .models import User, PasswordResetCode
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode,  urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings

class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email =  serializers.EmailField(source='user.email', read_only=True)

    def validate(self, attrs):
        user = attrs.get('user')

        if not user:
            raise serializers.ValidationError('user is required')
        
        return attrs
    
    class Meta:
        model = User
        fields = ['id', 'user', 'username', 'email', 'role', 'date_of_membership', 'active_status']

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': True},
            'email': {'required': True},
        }
    
    def validate_username(self, value):
        #Normalize uername: remeber to trim white spaces anto usisahau anko preserve original case for display onluy
        if not value:
            raise serializers.ValidationError('Username is required')
        value = value.strip()
        if not value:
            raise serializers.ValidationError('Username cannot be emptiii')
        if len(value) < 3:
            raise serializers.ValidationError('Username must be at least 3 characters long')
        if len(value) > 50:
            raise serializers.ValidationError('Username cannot be longer or larger than 50 characters')
        
        return value
    
    def validate_email(self, value):
        #Normalize email: trim and lowercaseeeee
        if not value:
            raise serializers.ValidationError('Email is required')
        return value.strip()
    
    def validate(self, attrs):
        #CHECk for ndumplicate email usernamesss
        username = attrs.get('username')
        email = attrs.get('email', '').strip()

        #Check for existing username (case-insensitive) & emairs
        if User.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError({
                'username': 'A user with this exact username credentials already exists.'
            })
        
        #Check for existing email (case-insensitive)
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError({
                'email': 'A user with this email already exists.'
            })
        
        return attrs

    def create(self, validated_data):
        #Create user with normal email and username should have spaces in between names
        user = User.objects.create_user(
            username=validated_data['username'].strip(),
            email=validated_data['email'].strip(),
            password=validated_data['password']
        )

        return user

class UserLoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(help_text='Username or email address')
    password = serializers.CharField(style={'input_type': 'password'}), trim_whitespace=False

    def validate(self, data):
        username_or_email = data.get('username_or_email', '').strip()
        password = data.get('password')

        if not username_or_email or not password:
            raise serializers.ValidationError({'error': 'Both username/email and password are required'})
        
        user = None

        if '@' in username_or_email:
            try:
                user = User.objects.get(email__iexact=username_or_email)
            except User.DoesNotExist:
                pass
        else:
            try:
                user = User.objects.get(username__iexact=username_or_email)
            except User.DoesNotExist:
                pass
        
        if user:
            user = authenticate(username=user.username, password=password)
        
        if not user:
            raise serializers.ValidationError({'error': 'Invalid username/email or password'})
        
        if not user.is_active:
            raise serializers.ValidationError({'error': 'User account has been disabled contact admin or moderators to get it sported out'})
        
        refresh = RefreshToken.for_user(user)
        return{
            'user': user,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['username'] = user.username
        token['is_admin'] = user.is_admin

        return token
    
class PasswordResetOTPRequestSerializer(serializers.Serializer):
    #REquest OTP code for password reset
    email = serializers.CharField()

    def validate_email(self, value):
        #Basic email valuation
        if not value or not isinstance(value, str):
            raise serializers.ValidationError('Email is required')
        value = value.strip()
        if '@' not in value:
            raise serializers.ValidationError('Please enter a valid email address')
        parts = value.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise serializers.ValidationError('Please enter a valid email address')
        return value
    
    def save(self):
        #Generate and send OTP code
        from django.utils import timezone
        from datetime import timedelta
        import random
        import logging
        from django.core.mail import send_mail
        from django.conf import settings

        logger = logging.getLogger(__name__)
        email = self.validated_data['email']

        #Find user by mail
        try:
            user = User.objects.filter(email__iexact=email).first()
        except Exception as e:
            logger.error(f'Error looking up user: {str(e)}')
            return{'email_exists': False}
        
        if not user or not user.mail:
            logger.info(f'Password reset required for non-existent email: {email}')
            return {'email_exists': False}
        
        #genereate 6 ndigit code
        code = str(random.randint(100000, 999999))

        #set expiration at 15 minutes
        expires_at = timezone.now() + timedelta(minutes=15)

        #Innvalidate any existing codes & raise an exception immediately
        from django.db import OperationError, ProgrammingError

        try:
            PasswordResetCode.objects.filter(user=user, used=False). update(used=True)
        
        except (OperationError, ProgrammingError) as db_error:
            #Database toble doesn't exist or other  database error
            error_msg = str(db_error).lower()
            logger.error(f'Database error invalidating codes: {str(db_error)}')
            if 'does not exist' in error_msg or 'relation' in error_msg or 'no such table' in error_msg:
                raise serializers.Validationerror({
                    'email': ['Database migration required. Please  run migrations on the server.']
                })
            #Raise if it's a different database
            raise
        except Exception as db_error:
            #Catch any other unexpected errors you never know
            error_msg = str(db_error).lower()
            if 'does not exist' in error_msg or 'relation' in error_msg or 'no such table' in error_msg:
                logger.error(f'Database error creating code (unexpected type): {str(db_error)}')
                raise serializers.ValidationError({
                    'email': ['Database migration required.  Please run migrations on the  server.']
                })
            #RE-raise if it's not a databese error
            raise

        #Send email
        subject = 'Password Reset Code - Diary Management System'
        message = f'''Hello {user.username},

You requested a password reset for your account. Your verification code is:

{code}

This code expires in 15 minutes

If you did not request this password reset, please ignore this email.sum

Best Regards,
Diary Management System Team
'''
        #GEt email verification
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@dairy.com')
        email_backend = getattr(settings, 'EMAIL_BACKEND', '')

        #Check email backend config
        if not settings.DEBUG and 'console' in email_backend.lower():
            if reset_code:
                reset_code.delete()
            
            raise serializers.ValidationError({
                'email': ['Email configuration error: Email service not configured properly. Please contact administrator.']
            })
        
        #Send email using DJango's send_mail (will use configured backend)
        try:
            email_timeout = getattr(settings, 'EMAIL_TIMEOUT', 10)
            from django.core.mail import get_connection
            connection = get_connection(fail_silently=False, timeout=email_timeout)

            result = send_mail(
                subject,
                message,
                from_email,
                [email],
                fail_silently=False,
                connection = connection,
            )

            logger.info(f'Password reset OTP sent to {email}')
            return {'email_exists': True, 'code_sent': True}
        
        except Exception as e:
            error_msg = str(e)
            error_type = type(e).__name__
            error_lower = error_msg.lower()

            logger.error(f'Error sending password reset email: {error_type}: {error_msg}')

            #Provide user-friendly and easy to understand error messages
            if 'api' in email_backend.lower() or 'brevo' in email_backend.lower():
                if '401' in error_msg or 'unauthorized' in error_lower:
                    error_message = 'Email service authentication failed. Please check BREVO_API_KEY configuration.'
                elif '400' in error_msg:
                    error_message = 'Email service configuration error. Please check DEFAULT_FROM_EMAIL and sender verification.'
                else:
                    error_message = 'Error sending email. Please try again later or contact administrator.'
            elif 'connection' in error_lower or 'timeout' in error_lower:
                error_message = 'Unable to connect to email service. This may be a temporary issue. Please try again later. Thank you.'
            elif 'authentication' in error_lower or '535' in error_msg:
                error_message = 'Email authentication failed. Please try again later. Sorry for any delays caused. Please contact administrator.'
            else: 
                error_message = 'Error sending email. Please try again later. Thank you and sorry.'
            
            #Delete the code if the email failed
            if reset_code:
                try:
                    reset_code.delete()
                except Exception:
                    pass

            raise serializers.ValidationError({'email': {error_message}})

class PasswordResetOTPVerifySerializer(serializers.Serializer):
    #VErify OTP code and reset password
    email = serializers.CharField()
    code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True, min_length=8)

    def validate_email(self, value):
        #Normalize email
        if not value:
            raise serializers.ValidationError('Email is required.')
        return value.strip() #Not using lower 
    
    def validate_code(self, value):
        #validate code format entered
        if not value or len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError('Code must be a 6 digit number')
        return value
    
    def validate(self, attrs):
        #Validate passwords match
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({'new_password_confirm': 'Passwords do not match'})
        return attrs
    
    def save(self):
        #Verify code and reset password
        from django.utils import timezone
        import logging
        
        logger = logging.getLogger(__name__)
        email = self.validated_data['email']
        code = self.validated_data['code']
        new_password = self.validated_data['new_password']

        #find user
        try:
            user = User.objects.filter(email__iexact=email).first()
        except Exception as e:
            logger.error(f'Error looking up user: {str(e)}')
            raise serializers.ValidationError({'code': ['Invalid code or email']})
        
        if not user:
            raise serializers.ValidationError({'code': ['Invalid code or email']})
        
        #FInd valid code
        try:
            reset_code = PasswordResetCode.objects.filter(
                user=user,
                email__iexact=email,
                code=code,
                used=False
            ).first()
        except Exception as e:
            logger.error(f'Error looking up code: {str(e)}')
            raise serializers.ValidationError({'code': ['Invalid code']})
        
        if not reset_code or not reset_code.is_valid():
            raise serializers.ValidationError({'code': ['Invalid or expired code']})
        
        user.set_password(new_password)
        user.save()
        reset_code.user = True
        reset_code.save()

        logger.info(f'Password reset successful for {email}')
        return {'success': True, 'message': 'Password has been reset successfully'}

#===========================================================================================
#OLd TOKEN-BASED Password Reset (Keep for backward compatibility just incase I need it)
#===========================================================================================
#TO be written kesho manze