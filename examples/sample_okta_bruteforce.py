"""
Sample script for adding a logs from a simulated Okta bruteforce attempt
"""
import uuid
from datetime import datetime
from random import randint
from random import uniform
from string import ascii_letters
from string import digits

import sample_helper

from tomisp import MISPHelper
from tomisp.vendor.okta import from_okta_log


def _generate_fake_geo(ip: str, idx: int) -> dict:
    """
    _generate_fake_geo - generates fake geolocation data
    """
    return {
        "city": sample_helper.generate_random_str(
            charset=ascii_letters + " " * 10, length=randint(3, 15)
        ).title(),
        "state": sample_helper.generate_random_str(length=randint(5, 12)).title(),
        "country": sample_helper.generate_random_str(
            charset=ascii_letters + " " * 10, length=randint(3, 15)
        ).title(),
        "postalCode": sample_helper.generate_random_str(charset=digits, length=5),
        "geolocation": {"lat": uniform(-90.0, 90.0), "lon": uniform(-180.0, 180.0)},
    }


_cached_Geo = sample_helper.CachedGenerator(_generate_fake_geo)


def generate_fake_geo_for_ip(ip_address: str) -> dict:
    """
    generate_fake_geo_for_ip - generates fake geolocation data for a given ip address
    """
    global _cached_Geo
    return _cached_Geo.Generate(ip_address)


def generate_okta_failAuth_log(
    user_email: str, user_name: str, user_id: str, user_agent: str, ip_address: str
) -> dict:
    """
    generate_oka_failAuth_log - generates a okta failed auth log entry

    Arguments:
        user_email -- target user email
        user_name -- target user name (should be Last, First to mimic Okta logs)
        user_id -- target user id
        user_agent -- user agent used by the attacker
        ip_address -- ip address of the attacker
    """
    ua_browser, ua_os = sample_helper.get_parts_from_ua(user_agent)
    geo_context = generate_fake_geo_for_ip(ip_address)
    return {
        "actor": {
            "id": user_id,
            "type": "User",
            "alternateId": user_email,
            "displayName": user_name,
            "detailEntry": None,
        },
        "client": {
            "userAgent": {
                "rawUserAgent": user_agent,
                "os": ua_os,
                "browser": ua_browser,
            },
            "zone": "None",
            "device": "Computer",
            "id": None,
            "ipAddress": ip_address,
            "geographicalContext": geo_context,
        },
        "device": None,
        "authenticationContext": {
            "authenticationProvider": None,
            "credentialProvider": None,
            "credentialType": None,
            "issuer": None,
            "interface": None,
            "authenticationStep": 0,
            "externalSessionId": sample_helper.generate_random_str(length=4)
            + "-"
            + sample_helper.generate_random_str(length=25),
        },
        "displayMessage": "User login to Okta",
        "eventType": "user.session.start",
        "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        "published": datetime.utcnow().isoformat() + "Z",
        "securityContext": {
            "asNumber": 0,
            "asOrg": "",
            "isp": "",
            "domain": "",
            "isProxy": False,
        },
        "severity": "WARN",
        "debugContext": {"debugData": {}},
        "legacyEventType": "core.user_auth.login_failed",
        "transaction": {
            "type": "WEB",
            "id": sample_helper.generate_random_str(length=27),
            "detail": {},
        },
        "uuid": str(uuid.uuid4()),
        "version": "0",
        "request": {
            "ipChain": [
                {
                    "ip": ip_address,
                    "geographicalContext": geo_context,
                    "version": "V4",
                    "source": None,
                }
            ]
        },
        "target": [
            {
                "id": sample_helper.generate_random_str(length=20),
                "type": "AuthenticatorEnrollment",
                "alternateId": "unknown",
                "displayName": "Password",
                "detailEntry": None,
            },
            {
                "id": sample_helper.generate_random_str(length=20),
                "type": "AppInstance",
                "alternateId": "Okta Dashboard",
                "displayName": "Okta Dashboard",
                "detailEntry": None,
            },
        ],
    }


def generate_okta_auth_log(
    user_email: str, user_name: str, user_id: str, user_agent: str, ip_address: str
) -> dict:
    obj = generate_okta_failAuth_log(
        user_email, user_name, user_id, user_agent, ip_address
    )
    obj["outcome"]["result"] = "SUCCESS"
    obj["outcome"]["reason"] = None
    obj["legacyEventType"] = "core.user_auth.login_success"
    return obj


if __name__ == "__main__":
    helper = MISPHelper()

    sample_data = []
    user_email = "sample.user@company.com"
    user_name = "User, Sample"
    user_id = "abcdefghijklmnop"
    for x in range(124):
        user_agent = sample_helper.generate_random_ua()
        ip_address = sample_helper.generate_ip()
        sample_data.append(
            generate_okta_failAuth_log(
                user_email, user_name, user_id, user_agent, ip_address
            )
        )
    sample_data.append(
        generate_okta_auth_log(user_email, user_name, user_id, user_agent, ip_address)
    )

    event = MISPHelper.create_event("Simulated Okta Bruteforce")

    for sdata in sample_data:
        from_okta_log(sdata, event)

    misp_id = helper.save_new_event(event, sample_data)
    print(misp_id)
