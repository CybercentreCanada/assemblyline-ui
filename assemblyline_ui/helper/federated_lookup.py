"""Interface for federated lookup plugins/extensions and common implementations.

Defines the class structure and methods required to be implemented in order for
federated lookups to be performed against external systems.

Also defines common concrete implementations usable for all installs of Assemblyline.
"""
import requests
from base64 import b64encode
from hashlib import sha256
from typing import Optional

from assemblyline.datasource.common import hash_type
from assemblyline_ui.config import CLASSIFICATION as Classification


class FederatedLookupBase():
    """Base class that defines the interface."""

    def __init__(self, verify: bool = False, max_timeout: float = 5.0, limit: int = 5) -> None:
        """Initialise config.

        Variables:
        verify      => Enable HTTPS verify
        max_timeout => Maximum timeout of query
        limit       => limit the amount of returned results
        """
        self.verify = verify
        self.timeout = max_timeout
        self.limit = limit

    # I don't like ioc as a name, perhaps tags is more approporiate?
    # but there may not be a 1:1 mapping of AL tag name to external system "tag"
    # name, which might be confusing
    def lookup_ioc(self, indicator: str, indicator_type: Optional[str] = None) -> dict[str, dict[str, str]]:
        """Define how to lookup an indicator in the external system.

        This method should return a dictionary containing:

            {
                <identifer/name of object found>:  {
                    "link": <url to object>,
                    "classification": <access control of the document linked to>,
                },
                ...,
            }

            If no data is found, or invalid data is input, `None` should be
            returned to allow up
        """
        raise NotImplementedError("Not Implemented.")


class VTLookup(FederatedLookupBase):
    """Search VT."""

    def __init__(self, verify: bool = False, max_timeout: float = 5.0, limit: int = 5) -> None:
        super().__init__(verify=verify, max_timeout=max_timeout)
        self.valid_ioc_types = ["domain", "hash", "ip-address", "url"]

    def lookup_ioc(self, indicator: str, indicator_type: str) -> dict[str, dict[str, str]]:

        if indicator_type not in self.valid_ioc_types:
            return None

        session = requests.Session()
        headers = {
            "accept": "application/json",
            "x-apikey": "API KEY",  # TODO: how to pass in key??
        }

        check_url = {
            "ip-address": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "url": f"https://www.virustotal.com/api/v3/urls/{b64encode(indicator)}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
        }.get(indicator_type, None)

        if not check_url:
            return None

        if indicator_type == "hash" and hash_type(indicator) == "invalid":
            return None

        rsp = session.get(check_url, headers=headers, verify=self.verify)
        if rsp.status_code != 200:
            return None

        # return view links to the gui once we know it's found
        # might be nicer in the future to parse collection results and display them instead?
        view_url = {
            "ip-address": f"https://www.virustotal.com/gui/ip-address/{indicator}/summary",
            "url": f"https://www.virustotal.com/gui/url/{sha256(indicator.encode('utf-8')).hexdigest()}/summary",
            "domain": f"https://www.virustotal.com/gui/domain/{indicator}/summary",
            "hash": f"https://www.virustotal.com/gui/search/{indicator}",
        }.get(indicator_type, "")

        return {
            f"vt-{indicator_type}": {"link": view_url, "classification": Classification.UNRESTRICTED}
        }


class MBLookup(FederatedLookupBase):
    """Search Malware Bazaar."""

    def __init__(self, verify: bool = False, max_timeout: float = 5.0, limit: int = 5) -> None:
        super().__init__(verify=verify, max_timeout=max_timeout)
        self.valid_ioc_types = ["hash", "imphash"]

    def lookup_ioc(self, indicator: str, indicator_type: str) -> dict[str, dict[str, str]]:
        """Lookup IOCs from Malware Bazaar.

        MB only has limited support of lookups based on IOCs.
        """
        if indicator_type not in self.valid_ioc_types:
            return None
        if indicator_type == "hash" and hash_type(indicator) == "invalid":
            return None

        session = requests.Session()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        url = "https://mb-api.abuse.ch/api/v1/"
        query = {
            "hash": "get_info",
            "imphash": "get_imphash",
            "limit": self.limit,
        }[indicator_type]

        data = {
            "query": query,
            indicator_type: indicator,
        }

        rsp = session.post(url, data, headers=headers)
        if rsp.status_code != 200:
            return None

        rsp_json = rsp.json()
        if rsp_json.get("query_status") != "ok":
            # not found, or invalid data provided
            return None

        # return view links to the gui once we know it's found
        # might be nicer in the future to parse collection results and display them instead?
        data = rsp_json.get("data", [])

        links = {}
        for entity in data:
            digest = entity.get("sha256_hash")
            if digest:
                links[digest] = {
                    "link": f"https://bazaar.abuse.ch/sample/{digest}/",
                    "classification": Classification.UNRESTRICTED
                }
        return links
