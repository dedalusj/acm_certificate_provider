import json
import time

import boto3

from certificate_dns_record_provider import CertificateDNSRecordProvider, PreConditionFailed


lambda_client = boto3.client('lambda')


class IssuedCertificateProvider(CertificateDNSRecordProvider):

    def __init__(self):
        super(IssuedCertificateProvider, self).__init__()
        self.request_schema = {
            "type": "object",
            "required": ["CertificateArn"],
            "properties": {
                "CertificateArn": {
                    "type": "string",
                    "description": "to get the status of"
                }
            }
        }

    def check(self):
        self.physical_resource_id = self.certificate_arn
        try:
            certificate = self.certificate
            if certificate.status == 'ISSUED':
                print(f'{certificate} is issued')
                self.success()
            elif certificate.status == 'PENDING_VALIDATION':
                print(f'{certificate} is pending validation')
                self.async_reinvoke()
            else:
                print(f'{certificate} is in incorrect state {certificate.status}')
                self.fail(f'incorrect certificated status {certificate.status}, expected ISSUED or PENDING_VALIDATION')
        except PreConditionFailed as error:
            self.fail(error.message)

    def create(self):
        self.check()

    def update(self):
        self.check()

    def delete(self):
        pass

    def invoke_lambda(self, payload):
        lambda_client.invoke(FunctionName=self.get('ServiceToken'), InvocationType='Event', Payload=payload)

    def async_reinvoke(self, interval_in_seconds=15):
        self.asynchronous = True  # do not report result to CFN yet
        time.sleep(interval_in_seconds)
        self.increment_attempt()
        payload = json.dumps(self.request).encode('utf-8')
        self.invoke_lambda(payload)

    @property
    def attempt(self):
        """ returns the number of attempts waiting for completion """
        return int(self.get('Attempt', 1))

    def increment_attempt(self):
        """ returns the number of attempts waiting for completion """
        self.properties['Attempt'] = (self.attempt + 1)


provider = IssuedCertificateProvider()


def handler(request, context):
    return provider.handle(request, context)
