"""
MISP Helper - Vendor - Okta Helper Functions
"""

from pymisp import MISPEvent

from ..misphelper import MISPHelper


def _create_okta_base(log: dict, event: MISPEvent):
    """
    _create_okta_base - generates base objects for any given Okta log item

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    src_ip = None
    last_ip = None
    username = None
    device = None
    software = None
    useragent = None
    httprequest = None

    ip_chain = log.get("request", {}).get("ipChain", [])
    for i in range(len(ip_chain) - 1, -1, -1):
        src = ip_chain[i].get("ip")
        if src:
            src_ip = MISPHelper.create_ip_obj(event, src, False, False, False)
        last_ip = src_ip

    user_name = log.get("actor", {}).get("alternateId")
    user_display_name = log.get("actor", {}).get("displayName")
    username = MISPHelper.create_user_obj(event, user_name, user_display_name, "okta")
    if last_ip:
        MISPHelper.create_relationship(username, "connected-from", last_ip)

    outcome_str = log.get("outcome", {}).get("result")
    outcome = MISPHelper.create_outcome_obj(event, log.get("eventType"), outcome_str)
    MISPHelper.create_relationship(username, "indicates", outcome)

    ua = log.get("client", {}).get("userAgent", {})
    os_str = ua.get("os") if ua else None
    if os_str:
        device = MISPHelper.create_device_obj(event, os_str)
    if outcome and device:
        MISPHelper.create_relationship(outcome, "authored-by", device)

    browser = ua.get("browser") if ua else None
    if browser:
        software = MISPHelper.create_software_obj(event, browser)
    if device and software:
        MISPHelper.create_relationship(device, "executes", software)

    raw_useragent_str = ua.get("rawUserAgent") if ua else None
    if raw_useragent_str:
        useragent = MISPHelper.create_useragent_obj(event, raw_useragent_str)
    if useragent and software:
        MISPHelper.create_relationship(software, "produced", useragent)

    url = log.get("debugContext", {}).get("debugData", {}).get("url")
    if url:
        httprequest = MISPHelper.create_http_obj(event, url)
    if httprequest and useragent:
        MISPHelper.create_relationship(useragent, "triggers", httprequest)
        return httprequest, url
    else:
        return outcome, outcome_str


def from_okta_log(log: dict, event: MISPEvent):
    """
    from_okta_log - takes an Okta log and generates objects in the MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("Okta")
    event_type = log.get("eventType")
    http_request_obj, http_url = _create_okta_base(log, event)

    event_obj = MISPHelper.create_annotation_obj(event, "OKTA Event", event_type)
    MISPHelper.create_relationship(http_request_obj, "triggers", event_obj)

    last_obj = event_obj
    relationship = "affects"
    if "target" in log and log.get("target"):
        for target in log.get("target", []):
            target_type = target.get("type")
            target_alt_id = target.get("alternateId")
            target_display_name = target.get("displayName")
            if target_type == "AppInstance":
                next_obj = MISPHelper.create_software_obj(
                    event, target_alt_id if target_alt_id else target_display_name
                )
                relationship = "targets"
            elif target_type == "AppUser":
                next_obj = MISPHelper.create_user_obj(
                    event, target_alt_id, target_display_name, "OKTA-APP"
                )
                relationship = "used-by"
            elif target_type in ["AppGroup", "UserGroup", "GroupPushMapping"]:
                next_obj = MISPHelper.create_group_obj(
                    event, target_display_name, "OKTA-" + target_type
                )
            elif target_type == "User":
                if "alternateId" in target:
                    id = target.get("alternateId")
                    name = target.get("displayName")
                    next_obj = MISPHelper.create_user_obj(event, id, name, "OKTA")
                else:
                    id = target.get("id")
                    next_obj = MISPHelper.create_user_obj(event, id)
                relationship = "used-by"
            elif target_type in ["access_token", "id_token"]:
                token_hash = target.get("detailEntry", {}).get("hash")
                next_obj = MISPHelper.create_annotation_obj(
                    event, target_type, token_hash
                )
                relationship = "delivers"
            elif target_type in ["code", "DeprovisionTask", "Org", "Custom Domain"]:
                id = target.get("id")
                next_obj = MISPHelper.create_annotation_obj(event, target_type, id)
            elif target_type in [
                "PolicyEntity",
                "PolicyRule",
                "ProfileMapping",
                "Schema",
            ]:
                next_obj = MISPHelper.create_annotation_obj(
                    event, target_type, target_display_name
                )
            else:
                next_obj = None

            if last_obj and next_obj:
                MISPHelper.create_relationship(last_obj, relationship, next_obj)
            if next_obj:
                last_obj = next_obj

    if "actor" in log and log.get("actor"):
        relationship = "affected-by"
        last_obj = event_obj
        actor = log.get("actor")
        actor_type = actor["type"]
        actor_alt_id = actor["alternateId"]
        actor_display_name = actor["displayName"]

        if actor_type in ["User"]:
            next_obj = MISPHelper.create_user_obj(
                event, actor_alt_id, actor_display_name, "OKTA-APP"
            )
            relationship = "used-by"
        else:
            next_obj = None

        if last_obj and next_obj:
            MISPHelper.create_relationship(last_obj, relationship, next_obj)
        if next_obj:
            last_obj = next_obj
