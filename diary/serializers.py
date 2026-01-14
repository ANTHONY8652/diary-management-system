from rest_framework import serializers
from .models import Diary
from django.contrib.auth.models import User
from django.conf import settings

class DiarySerializer(serializers.ModelSerializer):
    def validate(self, attrs):
        title = attrs.get('title')
        author = attrs.get('author')
        mood = attrs.get('mood')
        content = attrs.get('content')
        created_at = attrs.get('created_at')

        if not title:
            raise serializers.ValidationError('Title is required')
        if not author:
            raise serializers.ValidationError('Author is required')
        if not mood:
            raise serializers.ValidationError('Mood is required')
        if not content:
            raise serializers.ValidationError('Content is required')
        if not created_at:
            raise serializers.ValidationError('Created at is required')
        
        return attrs
    
    class Meta:
        model = Diary
        fields = ['id', 'title', 'author', 'mood', 'content', 'created_at']
