import logging
import time

import boto3
from botocore.exceptions import ClientError

from resource_provider import ResourceProvider

logger = logging.getLogger()

lambda_client = boto3.client('lambda')


class CertificateDNSRecordProvider(ResourceProvider):

    def __init__(self):
        super(CertificateDNSRecordProvider, self).__init__()
        self.request_schema = {
            "type": "object",
            "required": ["CertificateArn"],
            "properties": {
                "CertificateArn": {
                    "type": "string",
                    "description": "to get the DNS record for"
                },
                "DomainName": {
                    "type": "string",
                    "description": "to get the DNS validation record for, default Certificate's Domain name"
                }
            }
        }

    @property
    def certificate(self):
        region = self.certificate_arn.split(':')[3]
        acm = boto3.client('acm', region_name=region)
        try:
            response = acm.describe_certificate(CertificateArn=self.certificate_arn)
            result = Certificate(response["Certificate"])
            if result.status not in ['PENDING_VALIDATION', 'ISSUED']:
                raise PreConditionFailed(
                    f'certificate {result} is state {result.status}, expected pending validation or issued')
            return result
        except ClientError as e:
            raise PreConditionFailed(f'{e}')

    @property
    def certificate_arn(self):
        return self.get('CertificateArn')

    @property
    def domain_name(self):
        return self.get('DomainName', None)

    @property
    def domain_validation_option(self):
        result = self.certificate.get_validation_option(self.domain_name)

        if not result:
            raise PreConditionFailed('No validation option found for domain')

        return result

    @property
    def dns_domain_validation_option(self):
        result = self.domain_validation_option
        if result.validation_method != 'DNS':
            raise PreConditionFailed(
                f'domain is using validation method {result.validation_method}, not DNS')
        return result

    def poll_for_resource_record(self):
        try:
            dns_record = None
            while not dns_record:
                dns_record = self.dns_domain_validation_option.resource_record
                if not dns_record:
                    print('waiting for resource record to appear')
                    time.sleep(15)

            self.response['Data'] = dns_record
            self.physical_resource_id = dns_record['Name']
        except PreConditionFailed as error:
            if self.request_type == 'Create':
                self.physical_resource_id = 'could-not-create'
            self.fail(error.message)

    def create(self):
        self.poll_for_resource_record()

    def update(self):
        self.poll_for_resource_record()

    def delete(self):
        pass


class DomainValidationOption(object):
    def __init__(self, option):
        self.domain_name = option['DomainName']
        self.validation_status = option.get('ValidationStatus', None)
        self.resource_record = option.get('ResourceRecord', None)
        self.validation_method = option.get('ValidationMethod', None)


class Certificate(object):
    def __init__(self, certificate):
        self.certificate = certificate.copy()
        self.arn = self.certificate['CertificateArn']
        self.status = self.certificate['Status']
        self.domain_name = self.certificate['DomainName']
        self.options = list(map(lambda o: DomainValidationOption(o), self.certificate['DomainValidationOptions']))

    def __str__(self):
        return f'{self.domain_name} - {self.arn}'

    def get_validation_option(self, domain_name):
        """
        returns the validation option for `domain_name` or the certificate domain_name if not specified
        """
        return next(
            filter(lambda o: o.domain_name == domain_name or (not domain_name and o.domain_name == self.domain_name),
                   self.options), None)


class PreConditionFailed(Exception):
    def __init__(self, message):
        super(PreConditionFailed, self).__init__()
        self.message = message


provider = CertificateDNSRecordProvider()


def handler(request, context):
    return provider.handle(request, context)
