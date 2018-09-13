from django import forms
from django_filters import rest_framework as filters
from catcher.models import Callback, Fingerprint

import django_filters
import binascii
import logging

logger = logging.getLogger(__name__)

def is_hex(data):
    try:
        int(data, 16)
        return True
    except:
        return False

class CallbackFilter(filters.FilterSet):
    number_choices = [('exact', 'Equals'),('gt', 'Greater than'),('lt', 'Less than'),('regex', 'Regex'),]
    char_choices = [('exact', 'Equals'),('contains', 'Contains'),('regex', 'Regex'),]
    
    ip = django_filters.LookupChoiceFilter(
        field_class=forms.CharField,
        field_name='sourceip', 
        lookup_choices=char_choices
    ) 
    port = django_filters.LookupChoiceFilter(
        field_class=forms.IntegerField,
        field_name='serverport', 
        lookup_choices=number_choices
    )
    timestamp =  django_filters.DateTimeFromToRangeFilter(
        field_name='timestamp',
    )
    fingerprint = django_filters.ModelChoiceFilter(
        queryset=Fingerprint.objects.all()
    )
    data = django_filters.LookupChoiceFilter(
        field_class=forms.CharField,
        field_name='datahex', 
        lookup_choices=char_choices
    )
    
    def __init__(self, *args, **kwargs):
        super(CallbackFilter, self).__init__(*args, **kwargs)
        if self.request.method == 'GET':
            if 'data' in self.request.GET:
                data = self.request.GET.get('data')
                if is_hex(data) is False:
                    hex = binascii.hexlify(data.encode()).decode()
                    logger.info("Converted search '{}' term to '{}'".format(data, hex))
                    self.request.query_params._mutable = True
                    self.request.query_params['data'] = hex
    
    class Meta:
        model = Callback
        fields = (
            'ip',
            'port',
            'protocol',
            'timestamp',
            'fingerprint',
            'data',
            )