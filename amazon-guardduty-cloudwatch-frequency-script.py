#!/usr/bin/env python

import boto3
import argparse
import re

from botocore.exceptions import ClientError


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: GuardDuty client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='EnableGuardDuty'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for account {}.".format(
        aws_account_number
    ))

    return session


def list_detectors(gd_client, aws_region):
    """
    Lists the detectors in a given Region
    Used to detect if a detector exists already
    :param gd_client: GuardDuty client
    :param aws_region: AWS Region
    :return: Dictionary of AWS_Region: DetectorId
    """

    detector_dict = gd_client.list_detectors()

    if detector_dict['DetectorIds'] == []:
        pass
    else:
        return detector_dict


def change_configuration(gd_client, aws_region, desired_frequency, detector_dict):
    """
    Change the GuardDuty configuration
    as stated in the desired frequency arg
    :param gd_client: GuardDuty client
    :param aws_region: AWS Region
    :param desirec_frequency: arg for configuration setting
    :param detector_dict: GuardDuty Detector Id
    """
    try:
        gd_client.update_detector(
            DetectorId=detector_dict['DetectorIds'][0],
            FindingPublishingFrequency=desired_frequency
        )
        print(f'GuardDuty CloudWatch Event frequency change to {desired_frequency} in {aws_region}')
    except ClientError as err:
        if err.response['RespoonseMetadata']['HTTPStatusCode'] == 500:
            print("Internal server error")


if __name__ == '__main__':

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Change CloudWatch Event frequency for all enabled GuardDuty regions')
    parser.add_argument('--administrator_account', type=str, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume")
    parser.add_argument('--desired_frequency', type=str, help="Frequency to set for CloudWatch Event exporting. Accetaple inputs = FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS. If not specified, 15 minutes will be selected.")
    args = parser.parse_args()

    # Validate administrator accountId
    if not re.match(r'[0-9]{12}', args.administrator_account):
        raise ValueError("Master AccountId is not valid")

    # Getting GuardDuty regions
    session = boto3.session.Session()
    guardduty_regions = []
    guardduty_regions = session.get_available_regions('guardduty')
    print("Changing configuration in all available GuardDuty regions {}".format(guardduty_regions))

    # Processing Administrator account
    desired_frequency = args.desired_frequency
    master_session = assume_role(args.administrator_account, args.assume_role)
    for aws_region in guardduty_regions:
        try:
            gd_client = master_session.client('guardduty', region_name=aws_region)
            detector_dict = list_detectors(gd_client, aws_region)
            if detector_dict != None:
                change_configuration(gd_client, aws_region, desired_frequency, detector_dict)
            else:
                print(f"Failed to list detectors in Administrator account for region: {aws_region}.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the Administrator account.  Skipping {aws_region} and attempting to continue")
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print(f"Failed to list detectors in Administrator account for region: {aws_region}.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the Administrator account.  Skipping {aws_region} and attempting to continue")
