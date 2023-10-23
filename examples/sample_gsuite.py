"""
Sample script for adding Google GSuite logs to a MISP instance
"""

from tomisp import MISPHelper
from tomisp.vendor.google import from_gsuite_log

if __name__ == "__main__":
    helper = MISPHelper()

    sample_data = [
        {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2023-10-15T14:51:42.545Z",
                "uniqueQualifier": "-8326214377634822704",
                "applicationName": "drive",
                "customerId": "_gid_c16577735b_",
            },
            "etag": '"jc94nIMyBF33504pkAndEQD3hXqUGGH0EHOA9OLU9Ps/EOMmJtludOn1U-mqsw9xpv0l-QQ"',
            "actor": {
                "email": "user.39093549d9@company.com",
                "profileId": "112283590960109431700",
            },
            "ipAddress": "203.0.113.13",
            "events": [
                {
                    "type": "access",
                    "name": "expire_access_request",
                    "parameters": [
                        {"name": "primary_event", "boolValue": True},
                        {"name": "billable", "boolValue": True},
                        {"name": "target_user", "value": "user.254dfe24f0@company.com"},
                        {"name": "owner_is_shared_drive", "boolValue": False},
                        {"name": "owner", "value": "user.d87f02d1b9@company.com"},
                        {
                            "name": "doc_id",
                            "value": "1Qr_5oTIcRTMw1-ZxL8MQXj2xp93AvOwa9I2MZGaQ19I",
                        },
                        {"name": "doc_type", "value": "spreadsheet"},
                        {"name": "is_encrypted", "boolValue": False},
                        {
                            "name": "doc_title",
                            "value": "Super Spreadsheet!",
                        },
                        {"name": "visibility", "value": "shared_internally"},
                        {"name": "originating_app_id", "value": "211604355607"},
                        {"name": "actor_is_collaborator_account", "boolValue": False},
                        {"name": "owner_is_team_drive", "boolValue": False},
                    ],
                }
            ],
        },
        {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2023-10-13T17:36:04.286Z",
                "uniqueQualifier": "-5905157485008212847",
                "applicationName": "mobile",
                "customerId": "_gid_c16577735b_",
            },
            "etag": '"jc94nIMyBF33504pkAndEQD3hXqUGGH0EHOA9OLU9Ps/P0z_UiZ2FhYDBniWs4IwzbgoVBs"',
            "actor": {
                "callerType": "USER",
                "email": "user.254dfe24f0@company.com",
                "profileId": "104545172014506248332",
            },
            "events": [
                {
                    "type": "device_updates",
                    "name": "DEVICE_SYNC_EVENT",
                    "parameters": [
                        {"name": "USER_EMAIL", "value": "user.254dfe24f0@company.com"},
                        {
                            "name": "DEVICE_ID",
                            "value": "fb0cdaf4-8fad-4e0b-bd3b-9a418ca9765d",
                        },
                        {"name": "SERIAL_NUMBER", "value": ""},
                        {"name": "DEVICE_TYPE", "value": "MAC"},
                        {"name": "DEVICE_MODEL", "value": "Mac"},
                        {
                            "name": "RESOURCE_ID",
                            "value": "AFiQxQ92rWRCXM_uhrKRHw4BAw9tPRH9-v3Xq4FL-gPz8hwSRV5jUdB6QtbwOvwT4t4TYEeLZrc60PZc1w1GlfFNtGKzQwltHHhhf64yYCGkKoXwWCjE6c4KTLmvEMaG0f6NHgYoAMWH",
                        },
                        {"name": "IOS_VENDOR_ID", "value": ""},
                        {"name": "LAST_SYNC_AUDIT_DATE", "intValue": "1697218564286"},
                        {"name": "OS_VERSION", "value": "macOS 10.15.7"},
                    ],
                }
            ],
        },
        {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2023-10-11T15:50:49.677Z",
                "uniqueQualifier": "3285384908582641280",
                "applicationName": "token",
                "customerId": "_gid_c16577735b_",
            },
            "etag": '"rQ3qpTrpjMqlOD9Fi6ZCgnpo6zAdUtM4Y4wU0J6c8Yw/-rwS5U9xjqm4AhYQZx_e7-dt9dQ"',
            "actor": {
                "email": "user.254dfe24f0@company.com",
                "profileId": "104545172014506248332",
            },
            "ipAddress": "203.0.113.10",
            "events": [
                {
                    "name": "authorize",
                    "parameters": [
                        {
                            "name": "client_id",
                            "value": "961264221134-foqde0lca4la6b7s9kg4lkkj7prg9qn6.apps.googleusercontent.com",
                        },
                        {"name": "app_name", "value": "Microsoft Teams Meeting"},
                        {"name": "client_type", "value": "WEB"},
                        {
                            "name": "scope_data",
                            "multiMessageValue": [
                                {
                                    "parameter": [
                                        {
                                            "name": "scope_name",
                                            "value": "https://www.googleapis.com/auth/calendar.addons.current.event.read",
                                        },
                                        {
                                            "name": "product_bucket",
                                            "multiValue": ["CALENDAR"],
                                        },
                                    ]
                                },
                                {
                                    "parameter": [
                                        {
                                            "name": "scope_name",
                                            "value": "https://www.googleapis.com/auth/calendar.addons.current.event.write",
                                        },
                                        {
                                            "name": "product_bucket",
                                            "multiValue": ["CALENDAR"],
                                        },
                                    ]
                                },
                                {
                                    "parameter": [
                                        {
                                            "name": "scope_name",
                                            "value": "https://www.googleapis.com/auth/calendar.addons.execute",
                                        },
                                        {
                                            "name": "product_bucket",
                                            "multiValue": ["CALENDAR"],
                                        },
                                    ]
                                },
                                {
                                    "parameter": [
                                        {
                                            "name": "scope_name",
                                            "value": "https://www.googleapis.com/auth/calendar.readonly",
                                        },
                                        {
                                            "name": "product_bucket",
                                            "multiValue": ["CALENDAR"],
                                        },
                                    ]
                                },
                                {
                                    "parameter": [
                                        {
                                            "name": "scope_name",
                                            "value": "https://www.googleapis.com/auth/script.external_request",
                                        },
                                        {
                                            "name": "product_bucket",
                                            "multiValue": ["APPS_SCRIPT_RUNTIME"],
                                        },
                                    ]
                                },
                                {
                                    "parameter": [
                                        {
                                            "name": "scope_name",
                                            "value": "https://www.googleapis.com/auth/script.locale",
                                        },
                                        {
                                            "name": "product_bucket",
                                            "multiValue": ["APPS_SCRIPT_API"],
                                        },
                                    ]
                                },
                            ],
                        },
                        {
                            "name": "scope",
                            "multiValue": [
                                "https://www.googleapis.com/auth/calendar.addons.current.event.read",
                                "https://www.googleapis.com/auth/calendar.addons.current.event.write",
                                "https://www.googleapis.com/auth/calendar.addons.execute",
                                "https://www.googleapis.com/auth/calendar.readonly",
                                "https://www.googleapis.com/auth/script.external_request",
                                "https://www.googleapis.com/auth/script.locale",
                            ],
                        },
                    ],
                }
            ],
        },
        {
            "kind": "admin#reports#activity",
            "id": {
                "time": "2023-10-16T14:59:36.044Z",
                "uniqueQualifier": "8282019642642647526",
                "applicationName": "meet",
                "customerId": "_gid_c16577735b_",
            },
            "etag": '"jc94nIMyBF33504pkAndEQD3hXqUGGH0EHOA9OLU9Ps/VAPZ17rQTCrr36SGwcvuxkEgJiw"',
            "actor": {
                "callerType": "USER",
                "email": "user.254dfe24f0@company.com",
                "profileId": "104545172424206248332",
            },
            "events": [
                {
                    "type": "call",
                    "name": "call_ended",
                    "parameters": [
                        {"name": "video_send_seconds", "intValue": "1018"},
                        {"name": "location_country", "value": "US"},
                        {"name": "identifier_type", "value": "email_address"},
                        {"name": "audio_send_bitrate_kbps_mean", "intValue": "23"},
                        {"name": "video_send_packet_loss_max", "intValue": "0"},
                        {"name": "endpoint_id", "value": "boq_hlane_AghezdMixcQ"},
                        {"name": "device_type", "value": "web"},
                        {"name": "video_send_packet_loss_mean", "intValue": "0"},
                        {
                            "name": "video_recv_long_side_median_pixels",
                            "intValue": "640",
                        },
                        {"name": "screencast_send_seconds", "intValue": "0"},
                        {"name": "video_send_fps_mean", "intValue": "27"},
                        {"name": "audio_send_packet_loss_max", "intValue": "0"},
                        {
                            "name": "video_recv_short_side_median_pixels",
                            "intValue": "360",
                        },
                        {"name": "video_recv_packet_loss_mean", "intValue": "0"},
                        {"name": "network_send_jitter_msec_mean", "intValue": "7"},
                        {"name": "audio_recv_seconds", "intValue": "1021"},
                        {"name": "network_congestion", "intValue": "0"},
                        {
                            "name": "network_estimated_download_kbps_mean",
                            "intValue": "274",
                        },
                        {"name": "audio_send_packet_loss_mean", "intValue": "0"},
                        {"name": "network_transport_protocol", "value": "udp"},
                        {"name": "duration_seconds", "intValue": "1020"},
                        {"name": "video_send_bitrate_kbps_mean", "intValue": "1048"},
                        {"name": "identifier", "value": "user.254dfe24f0@company.com"},
                        {"name": "location_region", "value": "Idaho Falls"},
                        {"name": "audio_recv_packet_loss_max", "intValue": "1"},
                        {"name": "video_recv_fps_mean", "intValue": "24"},
                        {"name": "audio_recv_packet_loss_mean", "intValue": "0"},
                        {"name": "network_recv_jitter_msec_max", "intValue": "44"},
                        {
                            "name": "organizer_email",
                            "value": "user.d87f02d1b9@company.com",
                        },
                        {"name": "network_recv_jitter_msec_mean", "intValue": "2"},
                        {"name": "ip_address", "value": "208.0.113.42"},
                        {"name": "audio_send_seconds", "intValue": "1021"},
                        {"name": "display_name", "value": "User A"},
                        {"name": "video_recv_seconds", "intValue": "525"},
                        {"name": "network_rtt_msec_mean", "intValue": "44"},
                        {
                            "name": "video_send_long_side_median_pixels",
                            "intValue": "640",
                        },
                        {
                            "name": "conference_id",
                            "value": "6zJrTxw02R_dpNGH_AncDxIWOAkBMgAYBwiKAiABCA",
                        },
                        {"name": "screencast_recv_seconds", "intValue": "0"},
                        {"name": "product_type", "value": "meet"},
                        {
                            "name": "network_estimated_upload_kbps_mean",
                            "intValue": "1089",
                        },
                        {
                            "name": "video_send_short_side_median_pixels",
                            "intValue": "360",
                        },
                        {"name": "video_recv_packet_loss_max", "intValue": "0"},
                        {"name": "meeting_code", "value": "TRVQAAIKCC"},
                        {"name": "is_external", "boolValue": False},
                    ],
                }
            ],
        },
    ]
    event = MISPHelper.create_event("Sample GSuite Event")

    for sdata in sample_data:
        from_gsuite_log(sdata, event)

    misp_id = helper.save_new_event(event, sample_data)
    print(misp_id)
