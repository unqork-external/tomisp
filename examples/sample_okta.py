"""
Sample script for adding OKTA logs to a MISP instance
"""

from tomisp import MISPHelper
from tomisp.vendor.okta import from_okta_log

if __name__ == "__main__":
    helper = MISPHelper()

    sample_data = [
        {
            "actor": {
                "id": "00ukbc70hkeK5sJFV357",
                "type": "User",
                "alternateId": "user.5fa2e50e44@auQ-1i4.com",
                "displayName": "Admin A1",
                "detailEntry": None,
            },
            "client": {
                "userAgent": None,
                "zone": None,
                "device": None,
                "id": None,
                "ipAddress": None,
                "geographicalContext": None,
            },
            "device": None,
            "authenticationContext": {
                "authenticationProvider": None,
                "credentialProvider": None,
                "credentialType": None,
                "issuer": None,
                "interface": None,
                "authenticationStep": 0,
                "externalSessionId": "trsc3qZ70ORS92xBKy2qJs2jQ",
            },
            "displayMessage": "Add user to application membership",
            "eventType": "application.user_membership.add",
            "outcome": {"result": "SUCCESS", "reason": None},
            "published": "2023-10-15T16:54:14.214Z",
            "securityContext": {
                "asNumber": None,
                "asOrg": None,
                "isp": None,
                "domain": None,
                "isProxy": None,
            },
            "severity": "INFO",
            "debugContext": {"debugData": {"appname": "CompanyApp_001"}},
            "legacyEventType": "app.generic.provision.assign_user_to_app",
            "transaction": {"type": "JOB", "id": "gamwxv0qkzSCuxw6L357", "detail": {}},
            "uuid": "78842718-6b7b-11ee-a315-470b996b30cd",
            "version": "0",
            "request": {"ipChain": []},
            "target": [
                {
                    "id": "0uawxviv3283tH5UI357",
                    "type": "AppUser",
                    "alternateId": "user.9986445d56@APzfMSs.com",
                    "displayName": "User, User",
                    "detailEntry": None,
                },
                {
                    "id": "0oavps13otvxJuqFs357",
                    "type": "AppInstance",
                    "alternateId": "CompanyApp_001",
                    "displayName": "CompanyApp_001",
                    "detailEntry": None,
                },
                {
                    "id": "00ucs3m73cTf2OTld357",
                    "type": "User",
                    "alternateId": "user.9986445d56@APzfMSs.com",
                    "displayName": "User, User",
                    "detailEntry": None,
                },
            ],
            "x_source": "http_log_processor",
            "current_runtime": "2023-10-15T17:04:36",
        },
        {
            "actor": {
                "id": "00ucs3m73cTf2OTld357",
                "type": "User",
                "alternateId": "user.9986445d56@APzfMSs.com",
                "displayName": "User, User",
                "detailEntry": None,
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "B7F62B65BN.com.okta.mobile/8.2.1 OktaDeviceSDK/0.0.1 macOS/14.0.0 Apple/MacBookPro16,1 C29A8729-9E97-4E50-8E71-CA1B43E178A9",
                    "os": "Mac OS X",
                    "browser": "UNKNOWN",
                },
                "zone": "None",
                "device": "Computer",
                "id": None,
                "ipAddress": "203.0.113.0",
                "geographicalContext": {
                    "city": "Rexburg",
                    "state": "Idaho",
                    "country": "United States",
                    "postalCode": "83440",
                    "geolocation": {"lat": 43.8125, "lon": -111.7855},
                },
            },
            "device": None,
            "authenticationContext": {
                "authenticationProvider": "FACTOR_PROVIDER",
                "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
                "credentialType": None,
                "issuer": None,
                "interface": None,
                "authenticationStep": 0,
                "externalSessionId": "idxaPWMZtseTdOgAHzfbBtWQA",
            },
            "displayMessage": "Authentication of user via MFA",
            "eventType": "user.authentication.auth_via_mfa",
            "outcome": {"result": "SUCCESS", "reason": None},
            "published": "2023-10-11T21:56:17.822Z",
            "securityContext": {
                "asNumber": 11492,
                "asOrg": "cable one  inc.",
                "isp": "cable one  inc.",
                "domain": "sparklight.net",
                "isProxy": False,
            },
            "severity": "INFO",
            "debugContext": {
                "debugData": {
                    "authnRequestId": "ZScZ_5a09n-iO7E7PS8mHAAAAFY",
                    "requestId": "ZScaAaFN_ZFIMj9ZJeUbfAAAD2Q",
                    "dtHash": "9b1b107a7358d5e724c22b1b3477465e9c313a221be53a8ca51771f691769a53",
                    "requestUri": "/idp/authenticators/autu612snoYSzoCvu357/transactions/ft7MDlVFT5bR363u2X79R42kCsLHJPn_H-/verify",
                    "factor": "SIGNED_NONCE",
                    "factorIntent": "AUTHENTICATION",
                    "url": "/idp/authenticators/autu612snoYSzoCvu357/transactions/ft7MDlVFT5bR363u2X79R42kCsLHJPn_H-/verify?",
                }
            },
            "legacyEventType": "core.user.factor.attempt_success",
            "transaction": {
                "type": "WEB",
                "id": "ZScaAaFN_ZFIMj9ZJeUbfAAAD2Q",
                "detail": {},
            },
            "uuid": "01604420-6881-11ee-8754-050a89ee763e",
            "version": "0",
            "request": {
                "ipChain": [
                    {
                        "ip": "203.0.113.0",
                        "geographicalContext": {
                            "city": "Rexburg",
                            "state": "Idaho",
                            "country": "United States",
                            "postalCode": "83440",
                            "geolocation": {"lat": 43.8125, "lon": -111.7855},
                        },
                        "version": "V4",
                        "source": None,
                    }
                ]
            },
            "target": [
                {
                    "id": "00ucs3m73cTf2OTld357",
                    "type": "User",
                    "alternateId": "user.9986445d56@APzfMSs.com",
                    "displayName": "User, User",
                    "detailEntry": None,
                },
                {
                    "id": "pfdu7dgy1fUuaFlNA357",
                    "type": "AuthenticatorEnrollment",
                    "alternateId": "unknown",
                    "displayName": "Okta Verify",
                    "detailEntry": {
                        "methodTypeUsed": "Use Okta FastPass",
                        "methodUsedVerifiedProperties": "[DEVICE_BOUND, PHISHING_RESISTANT, HARDWARE_PROTECTED]",
                    },
                },
            ],
            "x_source": "http_log_processor",
            "current_runtime": "2023-10-11T22:04:36",
        },
        {
            "actor": {
                "id": "00ucs3m73cTf2OTld357",
                "type": "User",
                "alternateId": "user.9986445d56@APzfMSs.com",
                "displayName": "User, User",
                "detailEntry": None,
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "OktaVerify/4.4.1.0 WPFDeviceSDK/1.7.4.17 Windows/10.0.19045.3570 Micro-Star_International_Co._L/MS-7B51",
                    "os": "Windows",
                    "browser": "UNKNOWN",
                },
                "zone": "None",
                "device": "Computer",
                "id": None,
                "ipAddress": "203.0.113.0",
                "geographicalContext": {
                    "city": "Rexburg",
                    "state": "Idaho",
                    "country": "United States",
                    "postalCode": "83440",
                    "geolocation": {"lat": 43.8125, "lon": -111.7855},
                },
            },
            "device": None,
            "authenticationContext": {
                "authenticationProvider": "FACTOR_PROVIDER",
                "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
                "credentialType": None,
                "issuer": None,
                "interface": None,
                "authenticationStep": 0,
                "externalSessionId": "idxyzP_uMC7Rea35TYTYjVUuA",
            },
            "displayMessage": "Authentication of user via MFA",
            "eventType": "user.authentication.auth_via_mfa",
            "outcome": {"result": "SUCCESS", "reason": None},
            "published": "2023-10-13T16:02:40.367Z",
            "securityContext": {
                "asNumber": 11492,
                "asOrg": "cable one  inc.",
                "isp": "cable one  inc.",
                "domain": "sparklight.net",
                "isProxy": False,
            },
            "severity": "INFO",
            "debugContext": {
                "debugData": {
                    "authnRequestId": "ZSlqHmRMWpYJheycqygOLAAABQg",
                    "requestId": "ZSlqIL7SQ6msxsF9LVNVvQAACUE",
                    "dtHash": "9685af4de851de065256534d9af4beda4f9e9f51b12218bd03b6b19076cab217",
                    "requestUri": "/idp/authenticators/autu612snoYSzoCvu357/transactions/ftnW821g27k5fjC2s3OlXWCGYQ-73kFXU1/verify",
                    "factor": "SIGNED_NONCE",
                    "factorIntent": "AUTHENTICATION",
                    "url": "/idp/authenticators/autu612snoYSzoCvu357/transactions/ftnW821g27k5fjC2s3OlXWCGYQ-73kFXU1/verify?",
                }
            },
            "legacyEventType": "core.user.factor.attempt_success",
            "transaction": {
                "type": "WEB",
                "id": "ZSlqIL7SQ6msxsF9LVNVvQAACUE",
                "detail": {},
            },
            "uuid": "ef9d0ff8-69e1-11ee-aed0-d39d5439862e",
            "version": "0",
            "request": {
                "ipChain": [
                    {
                        "ip": "203.0.113.0",
                        "geographicalContext": {
                            "city": "Rexburg",
                            "state": "Idaho",
                            "country": "United States",
                            "postalCode": "83440",
                            "geolocation": {"lat": 43.8125, "lon": -111.7855},
                        },
                        "version": "V4",
                        "source": None,
                    }
                ]
            },
            "target": [
                {
                    "id": "00ucs3m73cTf2OTld357",
                    "type": "User",
                    "alternateId": "user.9986445d56@APzfMSs.com",
                    "displayName": "User, User",
                    "detailEntry": None,
                },
                {
                    "id": "pfdu9j5s6uaUh6q2D357",
                    "type": "AuthenticatorEnrollment",
                    "alternateId": "unknown",
                    "displayName": "Okta Verify",
                    "detailEntry": {
                        "methodTypeUsed": "Use Okta FastPass",
                        "methodUsedVerifiedProperties": "[DEVICE_BOUND, PHISHING_RESISTANT]",
                    },
                },
            ],
            "x_source": "http_log_processor",
            "current_runtime": "2023-10-13T16:14:37",
        },
        {
            "actor": {
                "id": "00ucs3m73cTf2OTld357",
                "type": "User",
                "alternateId": "user.9986445d56@APzfMSs.com",
                "displayName": "User, User",
                "detailEntry": None,
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                    "os": "Windows 10",
                    "browser": "CHROME",
                },
                "zone": "None",
                "device": "Computer",
                "id": None,
                "ipAddress": "203.0.113.0",
                "geographicalContext": {
                    "city": "Rexburg",
                    "state": "Idaho",
                    "country": "United States",
                    "postalCode": "83440",
                    "geolocation": {"lat": 43.8125, "lon": -111.7855},
                },
            },
            "device": {
                "id": "guou9j5s6rdbHzPrO357",
                "name": "MS-7B51",
                "os_platform": "WINDOWS",
                "os_version": "10.0.19045.3570",
                "managed": False,
                "registered": True,
                "device_integrator": None,
                "disk_encryption_type": "NONE",
                "screen_lock_type": "NONE",
                "jailbreak": None,
                "secure_hardware_present": False,
            },
            "authenticationContext": {
                "authenticationProvider": None,
                "credentialProvider": None,
                "credentialType": None,
                "issuer": None,
                "interface": None,
                "authenticationStep": 0,
                "externalSessionId": "idxyzP_uMC7Rea35TYTYjVUuA",
            },
            "displayMessage": "User single sign on to app",
            "eventType": "user.authentication.sso",
            "outcome": {"result": "SUCCESS", "reason": None},
            "published": "2023-10-13T16:02:41.258Z",
            "securityContext": {
                "asNumber": 11492,
                "asOrg": "cable one  inc.",
                "isp": "cable one  inc.",
                "domain": "sparklight.net",
                "isProxy": False,
            },
            "severity": "INFO",
            "debugContext": {
                "debugData": {
                    "audience": "https://slack.com",
                    "behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity=NEGATIVE, New City=NEGATIVE}",
                    "subject": "user.9986445d56@APzfMSs.com",
                    "signOnMode": "SAML 2.0",
                    "authenticationClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                    "authTime": "2023-10-13T16:02:40.545Z",
                    "requestUri": "/login/token/redirect",
                    "issuer": "http://www.okta.com/exkej1cbbuV7jdlOm357",
                    "url": "/login/token/redirect?stateToken=02.id.a24XWi4WJQ4CkRHchZD_i94_g2HCTacic43z7NOl",
                    "initiationType": "IDP_INITIATED",
                    "authnRequestId": "ZSlqHmRMWpYJheycqygOLAAABQg",
                    "requestId": "ZSlqIAYbiUCxUTxdvtFl8AAADkA",
                    "dtHash": "42d2eede31e62652bebd7438fcf84b51ac1f019b45e23464f806ee8364ddce10",
                    "expiryTime": "2023-10-13T16:07:41.248Z",
                    "risk": "{level=LOW}",
                    "issuedAt": "2023-10-13T16:02:41.248Z",
                    "threatSuspected": "False",
                    "jti": "id22104068794728091516954837",
                }
            },
            "legacyEventType": "app.auth.sso",
            "transaction": {
                "type": "WEB",
                "id": "ZSlqIAYbiUCxUTxdvtFl8AAADkA",
                "detail": {},
            },
            "uuid": "f025059e-69e1-11ee-8e73-b56d7f19b1e1",
            "version": "0",
            "request": {
                "ipChain": [
                    {
                        "ip": "203.0.113.0",
                        "geographicalContext": {
                            "city": "Rexburg",
                            "state": "Idaho",
                            "country": "United States",
                            "postalCode": "83440",
                            "geolocation": {"lat": 43.8125, "lon": -111.7855},
                        },
                        "version": "V4",
                        "source": None,
                    }
                ]
            },
            "target": [
                {
                    "id": "0oaej1cbbv1cfhjmA357",
                    "type": "AppInstance",
                    "alternateId": "Slack Enterprise",
                    "displayName": "Slack",
                    "detailEntry": {"signOnModeType": "SAML_2_0"},
                },
                {
                    "id": "0uaf63o74upTfDuxN357",
                    "type": "AppUser",
                    "alternateId": "user.9986445d56@APzfMSs.com",
                    "displayName": "User User",
                    "detailEntry": None,
                },
            ],
            "x_source": "http_log_processor",
            "current_runtime": "2023-10-13T16:14:37",
        },
    ]

    event = MISPHelper.create_event("Sample Okta Event")

    for sdata in sample_data:
        from_okta_log(sdata, event)

    misp_id = helper.save_new_event(event, sample_data)
    print(misp_id)
