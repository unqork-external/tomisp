"""
MISP Helper - Vendor - AWS Helper Functions
"""

import os.path
import urllib.parse

from pymisp import MISPEvent

from ..common import array_to_dict
from ..common import parse_ip_and_port
from ..misphelper import MISPHelper


def from_load_balancer(log: dict, event: MISPEvent):
    """
    from_load_balancer - takes parsed AWS load balancer logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("AWS")
    event.add_tag("LoadBalancer")
    src_ip_obj = None
    action_obj = None
    useragent_obj = None
    http_method_obj = None
    src_ip_obj = None
    http_method_obj = None
    device = None
    aws_obj = None
    uri_obj = None
    lb_ip_obj = None
    dst_ip_obj = None
    qs_obj = None

    end_action = log.get("actions_executed")
    action_obj = MISPHelper.create_annotation_obj(event, "AWS LB Action", end_action)

    src_ip_and_port = log.get("client")
    if src_ip_and_port:
        src_ip, src_port = parse_ip_and_port(src_ip_and_port)
        src_ip_obj = MISPHelper.create_ip_obj(event, src_ip) if src_ip else None
    else:
        src_ip_obj = None

    dst_ip_and_port = log.get("target")
    if dst_ip_and_port and dst_ip_and_port != "-":
        dst_ip, dst_port = parse_ip_and_port(dst_ip_and_port)
        dst_ip_obj = MISPHelper.create_ip_obj(event, dst_ip, True, dst_port, True)
    else:
        dst_ip_obj = None

    lb_ip = log.get("IPAddress")
    if lb_ip:
        lb_ip_obj = MISPHelper.create_ip_obj(event, lb_ip, True)

    user_agent = log.get("user_agent")
    if user_agent:
        useragent_obj = MISPHelper.create_useragent_obj(event, user_agent)

    request = log.get("request")
    if request:
        parts = request.split(" ")
        http_method = parts[0]
        http_uri = parts[1] if len(parts) > 0 else None
        # http_version = parts[2]
        if http_method:
            http_method_obj = MISPHelper.create_annotation_obj(
                event, "http_method", http_method
            )
        if http_uri:
            uri_obj = MISPHelper.create_url_obj(event, http_uri)

        parsed_url = urllib.parse.urlparse(http_uri)
        query_string = parsed_url.query
        if query_string and query_string != "":
            qs_obj = MISPHelper.create_querystring_obj(event, query_string)
    else:
        http_method_obj = None
        uri_obj = None
        qs_obj = None

    dst_host = log.get("domain_name")
    if dst_host:
        device = MISPHelper.create_device_obj(event, dst_host)

    aws_account_id = log.get("Account")
    if aws_account_id:
        aws_obj = MISPHelper.create_user_obj(event, aws_account_id, None, "AWS")

    # Relationships
    if src_ip_obj and action_obj:
        MISPHelper.create_relationship(action_obj, "authored-by", src_ip_obj)
    if src_ip_obj and useragent_obj:
        MISPHelper.create_relationship(src_ip_obj, "executes", useragent_obj)
    if useragent_obj and http_method_obj:
        MISPHelper.create_relationship(useragent_obj, "uses", http_method_obj)
    if src_ip_obj and http_method_obj and not useragent_obj:
        MISPHelper.create_relationship(src_ip_obj, "uses", http_method_obj)
    if http_method_obj and device:
        MISPHelper.create_relationship(http_method_obj, "connects-to", device)
    if device and aws_obj:
        MISPHelper.create_relationship(device, "belongs-to", aws_obj)
    if device and uri_obj:
        MISPHelper.create_relationship(device, "queried-for", uri_obj)
    if qs_obj and uri_obj:
        MISPHelper.create_relationship(uri_obj, "contains", qs_obj)
    if src_ip_obj and lb_ip_obj:
        MISPHelper.create_relationship(src_ip_obj, "connects-to", lb_ip_obj)
    if lb_ip_obj and dst_ip_obj:
        MISPHelper.create_relationship(lb_ip_obj, "connects-to", dst_ip_obj)


def from_vpc(log: dict, event: MISPEvent):
    """
    from_vpc - takes AWS VPC logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("AWS")
    event.add_tag("VPC")

    src_ip = log.get("srcaddr")
    src_port = log.get("srcport")
    src_ip_obj = MISPHelper.create_ip_obj(event, src_ip, False, src_port, False)

    dst_ip = log.get("dstaddr")
    dst_port = log.get("dstport")
    dst_ip_obj = MISPHelper.create_ip_obj(event, dst_ip, True, dst_port, True)

    end_action = log.get("action")
    action_obj = (
        MISPHelper.create_annotation_obj(event, "LB Action", end_action)
        if end_action
        else None
    )

    aws_account_id = log.get("account-id")
    aws_obj = (
        MISPHelper.create_user_obj(event, aws_account_id, None, "AWS")
        if aws_account_id
        else None
    )

    # TODO: create more objects
    # aws_region = log.get("region"]
    # aws_vpc_id = log.get("vpc-id"]
    # aws_subnet_id = log.get("subnet-id"]
    # aws_interface_id = log.get("interface-id"]
    # aws_instance_id = log.get("instance-id"]

    MISPHelper.create_relationship(src_ip_obj, "targets", dst_ip_obj)
    MISPHelper.create_relationship(action_obj, "authored-by", src_ip_obj)
    MISPHelper.create_relationship(dst_ip_obj, "belongs-to", aws_obj)


def from_waf(log: dict, event: MISPEvent):
    """
    from_waf - takes AWS WAFv2 logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("AWS")
    event.add_tag("WAF")

    action_obj = None
    src_ip_obj = None
    useragent_obj = None
    http_method_obj = None
    device = None
    aws_obj = None
    uri_obj = None
    qs_obj = None

    block_rules = []
    count_rules = []

    for rule_group in log.get("ruleGroupList"):
        terminating_rule = rule_group["terminatingRule"]
        if terminating_rule:
            block_rules.append(terminating_rule["ruleId"])
        for count_rule in rule_group["nonTerminatingMatchingRules"]:
            if count_rule:
                count_rules.append(count_rule["ruleId"])

    http_request = log.get("httpRequest")
    headerdict = array_to_dict(http_request["headers"], "name", "value", True)

    end_action = log.get("action")
    if end_action:
        action_obj = MISPHelper.create_annotation_obj(event, "WAF Action", end_action)

    src_ip = http_request.get("clientIp")
    if src_ip:
        src_ip_obj = MISPHelper.create_ip_obj(event, src_ip, False, None, None)

    user_agent = headerdict.get("user-agent")
    if user_agent:
        useragent_obj = MISPHelper.create_useragent_obj(event, user_agent)

    http_method = http_request.get("httpMethod")
    if http_method:
        http_method_obj = MISPHelper.create_annotation_obj(
            event, "http_method", http_method
        )

    dst_host = headerdict.get("host")
    if dst_host:
        device = MISPHelper.create_device_obj(event, dst_host)

    aws_account_id = log.get("httpSourceId", "").split("-")[0]
    if aws_account_id and aws_account_id != "":
        aws_obj = MISPHelper.create_user_obj(event, aws_account_id, None, "AWS")

    uri = http_request.get("uri")
    if uri:
        uri_obj = MISPHelper.create_url_obj(event, uri)

    query_string = http_request.get("args")
    if query_string and query_string != "":
        qs_obj = MISPHelper.create_querystring_obj(event, query_string)

    # Relationships
    if src_ip_obj and action_obj:
        MISPHelper.create_relationship(action_obj, "authored-by", src_ip_obj)
    if src_ip_obj and useragent_obj:
        MISPHelper.create_relationship(src_ip_obj, "executes", useragent_obj)
    if useragent_obj and http_method_obj:
        MISPHelper.create_relationship(useragent_obj, "uses", http_method_obj)
    if src_ip_obj and http_method_obj and not useragent_obj:
        MISPHelper.create_relationship(src_ip_obj, "uses", http_method_obj)
    if http_method_obj and device:
        MISPHelper.create_relationship(http_method_obj, "connects-to", device)
    if device and aws_obj:
        MISPHelper.create_relationship(device, "belongs-to", aws_obj)
    if device and uri_obj:
        MISPHelper.create_relationship(device, "queried-for", uri_obj)
    if qs_obj and uri_obj:
        MISPHelper.create_relationship(uri_obj, "contains", qs_obj)

    # Rule Hits
    for block_rule in block_rules:
        br_obj = MISPHelper.create_outcome_obj(event, block_rule, "BLOCK")
        if br_obj and uri_obj:
            MISPHelper.create_relationship(uri_obj, "triggers", br_obj)
    for count_rule in count_rules:
        c_obj = MISPHelper.create_outcome_obj(event, count_rule, "COUNT")
        if c_obj and uri_obj:
            MISPHelper.create_relationship(uri_obj, "triggers", c_obj)


def from_cloudtrail(log: dict, event: MISPEvent):
    """
    from_cloudtrail - takes AWS CloudTrail logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("AWS")
    event.add_tag("CloudTrail")

    event_type = log.get("eventType")
    # event_time = log.get("eventTime")
    # event_source = log.get("eventSource")
    event_name = log.get("eventName")
    # event_cat = log.get("eventCategory")

    event_obj = MISPHelper.create_annotation_obj(event, event_type, event_name)

    aws_account_id = log.get("recipientAccountId")
    if aws_account_id:
        aws_obj = MISPHelper.create_user_obj(event, aws_account_id, None, "AWS")
    else:
        aws_obj = None

    if event_obj and aws_obj:
        MISPHelper.create_relationship(event_obj, "linked-to", aws_obj)

    src_ip = log.get("sourceIPAddress")
    src_ip_obj = MISPHelper.create_ip_obj(event, src_ip)

    user_agent = log.get("userAgent")
    user_agent_obj = MISPHelper.create_useragent_obj(event, user_agent)

    user_identity = log.get("userIdentity")
    if user_identity:
        principle_id = user_identity.get("principalId")
        user_name = user_identity.get("userName")
        if principle_id or user_name:
            user_obj = MISPHelper.create_user_obj(
                event, principle_id, user_name, account_type="AWS"
            )
        else:
            user_obj = None
    else:
        user_obj = None

    if user_obj and src_ip_obj:
        MISPHelper.create_relationship(user_obj, "conncted-from", src_ip_obj)
    if user_obj and user_agent_obj:
        MISPHelper.create_relationship(user_obj, "uses", user_agent_obj)
    if event_obj and user_agent_obj:
        MISPHelper.create_relationship(user_agent_obj, "executes", event_obj)

    if "resources" in log:
        for resource in log.get("resources", []):
            resource_arn = resource["ARN"]
            # resource_account_id = resource["accountId"]
            resource_type = resource["type"]
            infra_obj = MISPHelper.create_infrastructure_obj(
                event, resource_arn, resource_type
            )
            MISPHelper.create_relationship(event_obj, "affects", infra_obj)
    if "serviceEventDetails" in log:
        service_details = log.get("serviceEventDetails")
        if "id" in service_details:
            service_id = service_details["id"]
            infra_obj = MISPHelper.create_infrastructure_obj(event, service_id, "AWS")
            MISPHelper.create_relationship(event_obj, "affects", infra_obj)
        elif "account_id" in service_details:
            account_id = service_details["account_id"]
            account_obj = MISPHelper.create_user_obj(event, account_id, None, "AWS")
            role_name = service_details["role_name"]
            role_obj = MISPHelper.create_group_obj(event, role_name, "AWS")
            MISPHelper.create_relationship(event_obj, "uses", role_obj)
            MISPHelper.create_relationship(role_obj, "contained-by", account_obj)


def translation_relationship(aws_relationship: str) -> str:
    """
    translation_relationship - translates an AWS relationship to a MISP relationship

    Arguments:
        aws_relationship -- the aws relationship (from OrgConfig logs)

    Returns:
        a misp relationship
    """
    if aws_relationship.startswith("Is attached to"):
        return "connected-to"
    elif aws_relationship.startswith("Is associated with"):
        return "associated-with"
    elif aws_relationship.startswith("Is contained in"):
        return "contain-by"
    else:
        return "references"


def from_orgconfig(log: dict, event: MISPEvent):
    """
    from_orgconfig - takes AWS OrgConfig logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("AWS")
    event.add_tag("OrgConfig")

    if "resourceType" in log:
        resource_type = log.get("resourceType")
        resource_id = log.get("resourceId")
        infra_obj = MISPHelper.create_infrastructure_obj(
            event, resource_id, resource_type
        )

        aws_account = log.get("awsAccountId")
        aws_obj = MISPHelper.create_user_obj(event, aws_account, None, "AWS")
        MISPHelper.create_relationship(infra_obj, "belongs-to", aws_obj)

        # snapshot_timestamp = log.get("configurationItemCaptureTime"]

        for relationship in log.get("relationships"):
            relation_target = relationship["resourceId"]
            relation_target_type = relationship["resourceType"]
            infra2_obj = MISPHelper.create_infrastructure_obj(
                event, relation_target, relation_target_type
            )

            relation_type = relationship["name"]
            MISPHelper.create_relationship(
                infra_obj, translation_relationship(relation_type), infra2_obj
            )

        if "configuration" in log:
            config = log.get("configuration")
            actor = config.get("requesterId")
            actor_email = actor.split(":")[1] if actor else None

            if actor_email:
                user_obj = MISPHelper.create_user_obj(event, actor_email, None, "AWS")
            if user_obj and infra_obj:
                MISPHelper.create_relationship(user_obj, "affects", infra_obj)

            # if "attachment" in config:
            #    timestamp = config["attachment"]["attachTime"]
            #    src_id = config["attachment"]["attachmentId"]
            #    dst_id = config["attachment"]["instanceId"]

            if "certificateArn" in config:
                serial = config["serial"]
                issuer = config["issuer"]
                subject = config["subject"]
                san = config["subjectAlternativeNames"]
                not_after = config["notAfter"]
                not_before = config["notBefore"]
                sig_algo = config["signatureAlgorithm"]
                key_algo = config["keyAlgorithm"]

                cert_obj = MISPHelper.create_certificate_obj(
                    event,
                    serial,
                    issuer,
                    subject,
                    san,
                    not_after,
                    not_before,
                    sig_algo,
                    key_algo,
                )
                MISPHelper.create_relationship(cert_obj, "used-by", infra_obj)


def from_ssm(log: dict, event: MISPEvent, local_log_file: str = None):
    """
    from_ssm - takes AWS SSM logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
        local_log_file - the log file downloaded from S3 for this SSM session (optional)
    """
    event.add_tag("AWS")
    event.add_tag("SSM")

    aws_account_id = log.get("Account")
    if aws_account_id:
        aws_obj = MISPHelper.create_user_obj(event, aws_account_id, None, "AWS")

    user = log.get("User")
    if user:
        user_obj = MISPHelper.create_user_obj(event, user)

    if aws_obj and user_obj:
        MISPHelper.create_relationship(user_obj, "connects-to", aws_obj)

    if local_log_file:
        filename = os.path.basename(local_log_file)
        file_obj = MISPHelper.create_file_obj(
            event, local_log_file, filename, False, "Harmless", "text/plain"
        )

    if file_obj and user_obj:
        MISPHelper.create_relationship(user_obj, "triggers", file_obj)
