from typing import Dict
from xml.etree import ElementTree

from .base import AdapterError


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_windows_event(xml: str) -> Dict[str, object]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise AdapterError("invalid Windows Event XML: %s" % exc) from exc
    system = root.find("e:System", NS)
    if system is None:
        raise AdapterError("Windows Event XML has no System element")
    data = {}
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for item in event_data.findall("e:Data", NS):
            data[item.attrib.get("Name", "unnamed")] = item.text or ""
    event_id = system.findtext("e:EventID", default="", namespaces=NS)
    computer = system.findtext("e:Computer", default="", namespaces=NS)
    time_node = system.find("e:TimeCreated", NS)
    record_id = system.findtext("e:EventRecordID", default="", namespaces=NS)
    return {"event_id": int(event_id), "computer": computer, "time_created": time_node.attrib.get("SystemTime") if time_node is not None else None, "record_id": record_id, "data": data}

