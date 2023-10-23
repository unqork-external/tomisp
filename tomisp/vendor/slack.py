"""
MISP Helper - Vendor - Slack Helper Functions
"""

from pymisp import MISPEvent

from ..misphelper import MISPHelper


def from_slack_log(log: dict, event: MISPEvent):
    """
    from_slack_log - takes an slack audit log and generates objects in the MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("Slack")
    action = log.get("action")
    action_obj = MISPHelper.create_annotation_obj(event, "Action", action)

    actor = log.get("actor")
    if actor:
        user = actor.get("user")
        if user:
            actor_name = user.get("name")
            actor_email = user.get("email")
            if actor_name and actor_email:
                user_obj = MISPHelper.create_user_obj(
                    event, actor_email, actor_name, "Slack"
                )

    context = log.get("context")
    if context:
        src_ip = context.get("ip_address")
        if src_ip:
            src_ip_obj = MISPHelper.create_ip_obj(event, src_ip)

        user_agent = context.get("ua")
        if user_agent:
            useragent_obj = MISPHelper.create_useragent_obj(event, user_agent)

    entity = log.get("entity")
    if entity:
        entity_name = entity.get("name")
        if entity_name:
            entity_obj = MISPHelper.create_infrastructure_obj(event, entity_name)

    if user_obj and src_ip_obj:
        MISPHelper.create_relationship(user_obj, "connected-from", src_ip_obj)
    if user_obj and useragent_obj:
        MISPHelper.create_relationship(user_obj, "uses", useragent_obj)
    if useragent_obj and action_obj:
        MISPHelper.create_relationship(useragent_obj, "triggers", action_obj)
    if action_obj and entity_obj:
        MISPHelper.create_relationship(action_obj, "affects", entity_obj)

    details = log.get("details")
    if details:
        if action == "anomaly":
            reasons = details["reason"]
            for reason in reasons:
                reason_obj = MISPHelper.create_annotation_obj(event, action, reason)
                if action_obj and reason_obj:
                    MISPHelper.create_relationship(
                        action_obj, "characterized-by", reason_obj
                    )
                if reason == "ip_address":
                    previous = details["previous_ip_address"]
                    previous_obj = MISPHelper.create_ip_obj(event, previous)
                elif reason == "ua":
                    previous = details["previous_ip_ua"]
                    previous_obj = MISPHelper.create_useragent_obj(event, previous)
                else:
                    previous = None
                    previous_obj = None
                if reason_obj and previous_obj:
                    MISPHelper.create_relationship(
                        reason_obj, "derived-from", previous_obj
                    )
        elif action == "connect_dm_invite_accepted":
            external_user = details.get("external_user_email")
            if external_user:
                external_user_obj = MISPHelper.create_user_obj(event, external_user)
            if action_obj and external_user_obj:
                MISPHelper.create_relationship(
                    action_obj, "includes", external_user_obj
                )

            external_org_name = details.get("external_organization_name")
            if external_org_name:
                external_org_obj = MISPHelper.create_group_obj(
                    event, external_org_name, "SLACK-EXTERNAL"
                )
            if external_user_obj and external_org_obj:
                MISPHelper.create_relationship(
                    external_user_obj, "belongs-to", external_org_obj
                )

        elif "type" in details:
            outcome = details["type"]
            outcome_obj = MISPHelper.create_outcome_obj(event, "Outcome", outcome)
            if outcome_obj and action_obj:
                MISPHelper.create_relationship(action_obj, "produces", outcome_obj)
