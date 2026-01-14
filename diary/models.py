from django.db import models

class Diary(models.Model):
    title = models.CharField(max_length=50)
    author = models.CharField(max_length=50)
    mood = models.CharField(max_length=50)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['title', 'author']

# Create your models here.
