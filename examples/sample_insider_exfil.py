"""
Sample script for adding a logs from a simulated insider attack
"""

from datetime import datetime
from random import choice
from string import ascii_letters
from string import digits

import sample_helper

from tomisp import MISPHelper
from tomisp.vendor.google import from_gsuite_log


def generate_google_base_log(email: str, id: str, ip_address: str) -> dict:
    """
    generate_google_base_log - generates the base dict for a google log

    Arguments:
        email -- actor email
        id -- actor id
        ip_address -- actor IP Address
    """
    return {
        "kind": "admin#reports#activity",
        "id": {
            "time": datetime.utcnow().isoformat() + "Z",
            "uniqueQualifier": sample_helper.generate_random_str(
                charset=digits, length=18
            ),
            "applicationName": "token",
            "customerId": "_google_customer_id_",
        },
        "etag": '"'
        + sample_helper.generate_random_str(charset=ascii_letters, length=71)
        + '"',
        "actor": {
            "email": email,
            "profileId": id,
        },
        "ipAddress": ip_address,
        "events": [],
    }


def generate_auth_log(email: str, id: str, ip_address: str) -> dict:
    """
    generate_auth_log - generates a google 'auth' log

    Arguments:
        email -- actor email
        id -- actor id
        ip_address -- actor IP Address
    """
    obj = generate_google_base_log(email, id, ip_address)
    app = sample_helper.generate_random_str(charset=digits, length=21)
    obj["events"] = [
        {
            "name": "authorize",
            "parameters": [
                {"name": "client_id", "value": app},
                {"name": "app_name", "value": app},
                {"name": "client_type", "value": "WEB"},
                {
                    "name": "scope_data",
                    "multiMessageValue": [
                        {
                            "parameter": [
                                {
                                    "name": "scope_name",
                                    "value": "https://www.googleapis.com/auth/drive",
                                },
                                {"name": "product_bucket", "multiValue": ["DRIVE"]},
                            ]
                        }
                    ],
                },
                {
                    "name": "scope",
                    "multiValue": ["https://www.googleapis.com/auth/drive"],
                },
            ],
        }
    ]
    return obj


def generate_view_log(
    actor_email: str, id: str, ip_address: str, owner_email: str
) -> dict:
    """
    generate_view_log - generates a google 'view' log

    Arguments:
        actor_email -- actor email
        id -- actor id
        ip_address -- actor IP Address
        owner_email -- email of the document owner
    """
    obj = generate_google_base_log(actor_email, id, ip_address)
    obj["events"] = [
        {
            "type": "access",
            "name": "view",
            "parameters": [
                {"name": "primary_event", "boolValue": True},
                {"name": "billable", "boolValue": True},
                {"name": "owner_is_shared_drive", "boolValue": False},
                {"name": "owner", "value": owner_email},
                {
                    "name": "doc_id",
                    "value": "1Z" + sample_helper.generate_random_str(length=42),
                },
                {
                    "name": "doc_type",
                    "value": choice(
                        ["presentation", "spreadsheet", "document", "folder", "pdf"]
                    ),
                },
                {"name": "is_encrypted", "boolValue": False},
                {
                    "name": "doc_title",
                    "value": sample_helper.generate_random_str(length=42).title(),
                },
                {"name": "visibility", "value": "shared_internally"},
                {"name": "actor_is_collaborator_account", "boolValue": False},
                {"name": "owner_is_team_drive", "boolValue": False},
            ],
        }
    ]
    return obj


def generate_download_log(
    actor_email: str, id: str, ip_address: str, owner_email: str
) -> dict:
    """
    generate_download_log - generates a google 'download' log

    Arguments:
        actor_email -- actor email
        id -- actor id
        ip_address -- actor IP Address
        owner_email -- email of the document owner
    """
    obj = generate_google_base_log(actor_email, id, ip_address)
    obj["events"] = [
        {
            "type": "access",
            "name": "download",
            "parameters": [
                {"name": "primary_event", "boolValue": True},
                {"name": "billable", "boolValue": True},
                {"name": "owner_is_shared_drive", "boolValue": False},
                {"name": "owner", "value": owner_email},
                {
                    "name": "doc_id",
                    "value": "1Z" + "".join([choice(ascii_letters) for x in range(42)]),
                },
                {
                    "name": "doc_type",
                    "value": choice(
                        ["presentation", "spreadsheet", "document", "folder", "pdf"]
                    ),
                },
                {"name": "is_encrypted", "boolValue": False},
                {
                    "name": "doc_title",
                    "value": "".join(
                        [choice(ascii_letters + " " * 10) for x in range(42)]
                    ).title(),
                },
                {"name": "visibility", "value": "shared_internally"},
                {
                    "name": "originating_app_id",
                    "value": "".join([choice(digits) for x in range(11)]),
                },
                {"name": "actor_is_collaborator_account", "boolValue": False},
                {"name": "owner_is_team_drive", "boolValue": False},
            ],
        }
    ]
    return obj


if __name__ == "__main__":
    helper = MISPHelper()

    owners = ["user.ABC@company.com", "admin@company.com", "somebody@company.com"]
    bad_user = "cool.user@company.com"
    bad_user_id = "1234567890"
    ip_address = sample_helper.generate_ip()
    sample_data = [
        generate_auth_log(bad_user, bad_user_id, ip_address),
        generate_view_log(bad_user, bad_user_id, ip_address, bad_user),
    ]
    for x in range(50):
        owner_email = choice([*owners, f"user.{x}@company.com"])
        sample_data.append(
            generate_download_log(bad_user, bad_user_id, ip_address, owner_email)
        )

    event = MISPHelper.create_event("Simulated Insider GSuite Event")

    for sdata in sample_data:
        from_gsuite_log(sdata, event)

    misp_id = helper.save_new_event(event, sample_data)
    print(misp_id)
