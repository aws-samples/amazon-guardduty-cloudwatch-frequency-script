# amazon-guardduty-cloudwatch-frequency-script

This script automates the process of updating the GuardDuty CloudWatch Event publishing frequency across all GuardDuty capable regions in a GuardDuty administrator account.

## Prerequisites

* This script requires permissions to make changes in the Guardduty administrator account. 

* An environment capable of executing this script is required. That can be an EC2 instance or locally.

### Execute Scripts

```
usage: amazon-guardduty-cloudwatch-frequency-script.py [-h] --administrator_account ADMINISTATOR_ACCOUNT --assume_role ASSUME_ROLE --desired_frequency DESIRED_FREQUENCY

Change the frequency for when GuardDuty delivers to Cloudwatch

arguments:
  -h, --help            show this help message and exit
  --administrator_account ADMINISTRATOR_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role name of role to use
  --desired_frequency DESIRED_FREQUENCY
                        Frequency to set for CloudWatch Event exporting. Accetaple inputs = FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS. If not specified, 15 minutes will be selected
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

