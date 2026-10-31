"""
core/parsers/nmap.py

Parses nmap's `-oX -` XML output into the shared hosts/services shape:
{"hosts": [{"ip": str, "hostname": str|None,
             "services": [{"port": int, "protocol": str,
                           "service": str, "version": str|None}]}]}

This is the same parsing logic that used to live inside ScopedExecutor —
moved here so new tools (naabu, masscan, ...) can each get their own small
parser file without ScopedExecutor or ToolEngine needing to change.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET


def parse(xml_text: str) -> dict:
    if not xml_text.strip():
        return {"hosts": []}

    root = ET.fromstring(xml_text)
    hosts: list[dict] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue  # skip hosts nmap reports as down/filtered

        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        services: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue  # only report open ports as findings

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product") if service_el is not None else None
                version_num = service_el.get("version") if service_el is not None else None
                version = " ".join(p for p in [product, version_num] if p) or None

                services.append(
                    {
                        "port": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol", "tcp"),
                        "service": service_name,
                        "version": version,
                    }
                )

        hosts.append({"ip": ip, "hostname": hostname, "services": services})

    return {"hosts": hosts}