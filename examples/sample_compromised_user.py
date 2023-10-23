"""
Sample script for adding a logs from a simulated compromised user
"""
from datetime import datetime

import sample_helper
from sample_insider_exfil import generate_auth_log
from sample_insider_exfil import generate_download_log
from sample_insider_exfil import generate_view_log
from sample_okta_bruteforce import generate_okta_auth_log

from tomisp import MISPHelper
from tomisp.vendor.aws import from_cloudtrail
from tomisp.vendor.google import from_gsuite_log
from tomisp.vendor.okta import from_okta_log

if __name__ == "__main__":
    user_email = "target.user@company.com"
    user_name = "User, Target"
    user_id_okta = "poiuytrewq"
    user_id_google = "mnbvcxz"

    user_agent1 = sample_helper.generate_random_ua()
    ip_address1 = sample_helper.generate_ip()
    user_agent2 = sample_helper.generate_random_ua()
    ip_address2 = sample_helper.generate_ip()

    okta_data = [
        generate_okta_auth_log(
            user_email, user_name, user_id_okta, user_agent1, ip_address1
        ),
        generate_okta_auth_log(
            user_email, user_name, user_id_okta, user_agent2, ip_address2
        ),
    ]
    gsuite_data = [
        generate_auth_log(user_email, user_id_google, ip_address1),
        generate_view_log(user_email, user_id_google, ip_address1, user_email),
        generate_auth_log(user_email, user_id_google, ip_address2),
    ]

    for x in range(50):
        gsuite_data.append(
            generate_download_log(user_email, user_id_google, ip_address2, user_email)
        )
    cloudtrail_data = [
        {
            "eventVersion": "1.8",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AR423CKCS7LYM423YUHFK:" + user_email,
                "arn": "arn:aws:sts::A00000000004:assumed-role/AWSReservedSSO_AdministratorAccess_f29f65281095808f/user.user@company.com",
                "accountId": "A00000000004",
                "accessKeyId": "ASIA3CKCS7LYCCIR7I3U",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AR423CKCS7LYM423YUHFK",
                        "arn": "arn:aws:iam::A00000000004:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_f29f65281095808f",
                        "accountId": "A00000000004",
                        "userName": "AWSReservedSSO_AdministratorAccess_f29f65281095808f",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate": datetime.utcnow().isoformat() + "Z",
                        "mfaAuthenticated": "false",
                    },
                },
            },
            "eventTime": datetime.utcnow().isoformat() + "Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "StartInstances",
            "eventType": "AwsApiCall",
            "awsRegion": "us-east-2",
            "sourceIPAddress": ip_address2,
            "userAgent": "AWS Internal",
            "requestParameters": {
                "instancesSet": {"items": [{"instanceId": "i-ebeaf9e2"}]}
            },
            "responseElements": {
                "instancesSet": {
                    "items": [
                        {
                            "instanceId": "i-ebeaf9e2",
                            "currentState": {"code": 0, "name": "pending"},
                            "previousState": {"code": 80, "name": "stopped"},
                        }
                    ]
                }
            },
            "recipientAccountId": "A00000000004",
        },
        {
            "eventVersion": "1.8",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AR423CKCS7LYM423YUHFK:" + user_email,
                "arn": "arn:aws:sts::A00000000004:assumed-role/AWSReservedSSO_AdministratorAccess_f29f65281095808f/user.user@company.com",
                "accountId": "A00000000004",
                "accessKeyId": "ASIA3CKCS7LYCCIR7I3U",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AR423CKCS7LYM423YUHFK",
                        "arn": "arn:aws:iam::A00000000004:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_f29f65281095808f",
                        "accountId": "A00000000004",
                        "userName": "AWSReservedSSO_AdministratorAccess_f29f65281095808f",
                    },
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate": datetime.utcnow().isoformat() + "Z",
                        "mfaAuthenticated": "false",
                    },
                },
            },
            "eventTime": datetime.utcnow().isoformat() + "Z",
            "eventSource": "ec2.amazonaws.com",
            "eventType": "AwsApiCall",
            "eventName": "CreateKeyPair",
            "awsRegion": "us-east-2",
            "sourceIPAddress": ip_address2,
            "userAgent": sample_helper.generate_random_ua(),
            "requestParameters": {"keyName": "mykeypair"},
            "responseElements": {
                "keyName": "mykeypair",
                "keyFingerprint": "30:1d:46:d0:5b:ad:7e:1b:b6:70:62:8b:ff:38:b5:e9:ab:5d:b8:21",
                "keyMaterial": "\u003csensitiveDataRemoved\u003e",
            },
            "recipientAccountId": "A00000000004",
        },
    ]

    helper = MISPHelper()

    event = MISPHelper.create_event("Simulated Compromised User")

    for data in gsuite_data:
        from_gsuite_log(data, event)
    for data in okta_data:
        from_okta_log(data, event)
    for data in cloudtrail_data:
        from_cloudtrail(data, event)

    misp_id = helper.save_new_event(
        event, {"GSuite": gsuite_data, "Okta": okta_data, "CloudTrail": cloudtrail_data}
    )
    print(misp_id)
