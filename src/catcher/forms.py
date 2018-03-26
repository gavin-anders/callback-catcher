from django import forms
from django.core.exceptions import ValidationError
from catcher.models import Port, Handler
from datetime import datetime 

class PortForm(forms.ModelForm):
    number        = forms.IntegerField()
    protocol      = forms.CharField(max_length=3)
    ssl           = forms.IntegerField()
    handler       = forms.ModelChoiceField(queryset=Handler.objects.all())

    class Meta:
        model = Port
        fields = ['number', 'protocol', 'ssl', 'handler']