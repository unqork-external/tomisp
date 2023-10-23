"""
Sample script for simple use of ToMisp
"""
from tomisp import MISPHelper

if __name__ == "__main__":
    auth_key = "-=INSERT MISP API KEY HERE=-"
    base_url = "https://localhost"

    helper = MISPHelper(misp_url=base_url, misp_api_key=auth_key)

    event = MISPHelper.create_event("Sample Event 001")

    email_obj = MISPHelper.create_email_obj(
        event,
        "This is an email",
        "<12345>",
        "noone@nowhere.com",
        "someone@somewhere.com",
    )

    user_obj = MISPHelper.create_user_obj(event, "me", "ME", "local")

    MISPHelper.create_relationship(user_obj, "sends", email_obj)

    misp_id = helper.save_new_event(event, {"data": "good"})

    print(misp_id)
