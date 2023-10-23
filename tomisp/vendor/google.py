"""
MISP Helper - Vendor - Google Helper Functions
"""

from pymisp import MISPEvent

from ..common import array_to_dict
from ..misphelper import MISPHelper


def from_gsuite_log(log: dict, event: MISPEvent):
    """
    from_gsuite_log - takes GSuite logs and adds them to a MISP event

    Arguments:
        log -- dict object representing the log
        event -- pymisp MISPEvent object
    """
    event.add_tag("Google")
    event.add_tag("GSuite")

    src_ip_obj = None
    actor_obj = None
    event_obj = None
    file_obj = None
    owner = None
    etype = None
    rgroup = None

    src_ip = log.get("ipAddress")
    if src_ip:
        src_ip_obj = MISPHelper.create_ip_obj(event, src_ip)

    actor_email = log.get("actor", {}).get("email")
    if actor_email:
        actor_obj = MISPHelper.create_user_obj(event, actor_email, None, "GSuite")

    if src_ip_obj and actor_obj:
        MISPHelper.create_relationship(actor_obj, "connected-from", src_ip_obj)

    for ev in log.get("events", []):
        etype = ev.get("type")
        ename = ev.get("name")
        eparams = ev.get("parameters")

        if etype:
            event_obj = MISPHelper.create_capalert_obj(event, etype, None, ename)

        if ename == "download":
            edict = array_to_dict(eparams, "name", "value")
            file_type = edict.get("doc_type")
            file_name = edict.get("doc_title")
            if file_name and file_type:
                file_obj = MISPHelper.create_file_obj(
                    event, None, file_name, mime_type=file_type
                )
            if actor_obj and file_obj:
                MISPHelper.create_relationship(actor_obj, "downloads", file_obj)

            owner = edict.get("owner")
            if owner:
                ouser = MISPHelper.create_user_obj(event, owner, "", "gsuite")
            if file_obj and ouser:
                MISPHelper.create_relationship(ouser, "owner-of", file_obj)

        if eparams:
            fixed_params = array_to_dict(eparams, "name", "value", True)
            for pk, pv in fixed_params.items():
                if pk == "user_email":
                    ruser = MISPHelper.create_user_obj(event, pv, "", "gsuite")
                    if ruser and etype:
                        MISPHelper.create_relationship(ruser, "related-to", event_obj)
                elif pk == "group_email":
                    rgroup = MISPHelper.create_group_obj(event, pv)
                    if etype and rgroup:
                        MISPHelper.create_relationship(rgroup, "related-to", event_obj)

        if event_obj and actor_obj:
            MISPHelper.create_relationship(actor_obj, "generates", event_obj)
