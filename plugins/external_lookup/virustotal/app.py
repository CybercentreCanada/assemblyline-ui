"""Lookup through VirusTotal.

Uses the VirusTotal v3 API.
A valid API key is required.
"""
import base64
import datetime
import json
import os

from typing import Union
from urllib import parse as ul

import requests

from flask import Flask, Response, jsonify, make_response, request


app = Flask(__name__)


API_KEY = os.environ.get("VT_API_KEY", "")
VERIFY = os.environ.get("VT_VERIFY", False)
MAX_TIMEOUT = float(os.environ.get("MAX_TIMEOUT", 3))
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")  # Classification of this service
API_URL = os.environ.get("API_URL", "https://www.virustotal.com/api/v3")  # override in case of mirror
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://www.virustotal.com/gui/search")  # override in case of mirror

# Mapping of AL tag names to external systems "tag" names
TAG_MAPPING = os.environ.get(
    "TAG_MAPPING",
    {
        "md5": "files",
        "sha1": "files",
        "sha256": "files",
        "network.dynamic.domain": "domains",
        "network.static.domain": "domains",
        "network.dynamic.ip": "ip_addresses",
        "network.static.ip": "ip_addresses",
        "network.dynamic.uri": "urls",
        "network.static.uri": "urls",
    },
)
if not isinstance(TAG_MAPPING, dict):
    TAG_MAPPING = json.loads(TAG_MAPPING)


def make_api_response(data, err: str = "", status_code: int = 200) -> Response:
    """Create a standard response for this API."""
    return make_response(
        jsonify(
            {
                "api_response": data,
                "api_error_message": err,
                "api_status_code": status_code,
            }
        ),
        status_code,
    )


@app.route("/tags/", methods=["GET"])
def get_tag_names() -> Response:
    """Return supported tag names."""
    return make_api_response({tname: CLASSIFICATION for tname in sorted(TAG_MAPPING)})


def lookup_tag(tag_name: str, tag: str, timeout: float):
    """Lookup the tag in VirusTotal.

    Tag values submitted must be URL encoded.

    Complete data from the lookup is returned unmodified.
    """
    if tag_name == "files" and len(tag) not in (32, 40, 64):
        return make_api_response(None, "Invalid hash provided. Require md5, sha1 or sha256", 422)
    if not API_KEY:
        return make_api_response(None, "No API Key is provided. An API Key is required.", 422)

    session = requests.Session()
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }
    # URLs must be converted into VT "URL identifiers"
    encoded_tag = tag
    if tag_name == "urls":
        encoded_tag = base64.urlsafe_b64encode(tag.encode()).decode().strip("=")
    url = f"{API_URL}/{tag_name}/{encoded_tag}"

    rsp = session.get(url, headers=headers, verify=VERIFY, timeout=timeout)
    if rsp.status_code == 404:
        return make_api_response(None, "No results.", rsp.status_code)
    elif rsp.status_code != 200:
        return make_api_response(rsp.text, "Error submitting data to upstream.", rsp.status_code)

    return rsp.json().get("data", {})


@app.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
def search_tag(tag_name: str, tag: str) -> Response:
    """Search for tags on VirusTotal.

    Tags submitted must be URL encoded (not url_plus quoted).

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 100]


    This method should return an api_response containing:

        {
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "classification": $CLASSIFICATION",
        }
    """
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT, type=float)

    data = lookup_tag(tag_name=tn, tag=tag, timeout=max_timeout)
    if isinstance(data, Response):
        return data

    # ensure there is a result before returning the link, as if you submit a url search
    # to vt that it hasn't seen before, it will start a new scan of that url
    # note: tag must be double url encoded, and include encoding of `/` for URLs to search correctly.
    search_encoded_tag = ul.quote(ul.quote(tag, safe=""), safe="")
    return make_api_response(
        {
            "link": f"{FRONTEND_URL}/{search_encoded_tag}",
            "count": 1,  # url/domain/file/ip searches only return a single result/report
            "classification": CLASSIFICATION,
        }
    )


@app.route("/details/<tag_name>/<path:tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Get detailed lookup results from VirusTotal

    Query Params:
    max_timeout => Maximum execution time for the call in seconds
    limit       => Maximum number of items to return
    enrich      => If specified, return semi structured Key:Value pairs of additional metadata under "enrichment"
    noraw       => If specified, do not return the raw data under the `data` key

    Returns:
    # List of:
    [
        {
            "description": "",                     # Description of the findings
            "malicious": <bool>,                   # Is the file found malicious or not
            "confirmed": <bool>,                   # Is the maliciousness attribution confirmed or not
            "data": {...},                         # Additional Raw data
            "classification": <access control>,    # [Optional] Classification of the returned data
            "enrichment": {
                <group>: {<name>: <value>},
                ...
            }   # [Optional] groupings of additional metadata
        },
        ...,
    ]
    """
    # Invalid tags must either be ignored, or return a 422
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT, type=float)
    enrich = request.args.get("enrich", "false").lower() in ("true", "1")
    noraw = request.args.get("noraw", "false").lower() in ("true", "1")

    data = lookup_tag(tag_name=tn, tag=tag, timeout=max_timeout)
    if isinstance(data, Response):
        return data
    attrs = data.get("attributes", {})

    # only available for hash lookups
    sandboxes = None
    threat = None
    if tn == "files":
        sandboxes = 0
        for results in attrs.get("sandbox_verdicts", {}).values():
            cat = results.get("category", "")
            if cat == "malicious":
                sandboxes += 1
        threats = attrs.get("popular_threat_classification")
        threat_info = []
        if threats:
            label = threats.get("suggested_threat_label")
            if label:
                threat_info.append(f"Threat label: {label}")
            categories = threats.get("popular_threat_category", [])
            if categories:
                cats = ", ".join(cat["value"] for cat in categories)
                threat_info.append(f"Threat categories: {cats}")
            names = threats.get("popular_threat_name", [])
            if names:
                families = ", ".join(name["value"] for name in names)
                threat_info.append(f"Family labels: {families}")
        threat = ". ".join(threat_info)

    # construct a useful description based on available summary info
    vendors = attrs.get("last_analysis_stats", {}).get("malicious", 0)
    description = f"{vendors} security vendors"
    if sandboxes is not None:
        description += f" and {sandboxes} sandboxes"
    description += " flagged this as malicious."
    if threat:
        description += f" {threat}."

    r = {
        "classification": CLASSIFICATION,
        "confirmed": False,  # virustotal does not offer a confirmed property
        "data": data,
        "description": description,
        "malicious": True if vendors > 0 else False,
    }

    if enrich:
        enricher = Enricher(data=attrs)
        r["enrichment"] = enricher.enrichment

    if noraw:
        del r["data"]

    return make_api_response([r])


class Enricher():
    """Object to parse and hold enrichment info."""

    def __init__(self, data: dict) -> None:
        self.enrichment = []
        self.data = data
        self._enrich()
        self.enrichment.sort(key=lambda x: x["name"])

    def _add(
        self,
        group: str,
        name: str,
        key: str = None,
        default=None,
        *,
        label: str = "",
        label_key: str = None,
        value: str = None,
        value_key: Union[str, list] = None,
        is_timestamp: bool = False,
        data: dict = None
    ):
        """
        group: enrichment group
        name: enrichment name
        key: key in data to lookup
        default: default value if key doesn't exist (None to ignore)
        label: label to add to the value
        data: data dict to parse instead of top level
        """
        # allow a passed in dict to be parsed instead
        data = data or self.data

        # when value is directly given, we don't need to get the value out of a dict
        if value is not None:
            item = value
        else:
            # key defaults to name if not specified.
            if key is None:
                key = name
            item = data.get(key, default)
            if item is None:
                return

        items = item
        if not isinstance(item, list):
            items = [item]

        for item in items:
            _label = label
            if label_key is not None:
                _label = item.get(label_key, None)

            # allow multiple value_keys to be given
            values = [item]
            if value_key:
                if not isinstance(value_key, list):
                    value_key = [value_key]
                values = [item[k] for k in value_key if k in item]

            for value in values:
                # if timestamp is specified, all values must be timestamps
                if is_timestamp:
                    value = datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()

                if _label:
                    value = f"{_label}::{value}"

                self.enrichment.append({"name": name, "value": value})

    def _enrich(self):
        # all
        self._add("reputation", default=0)
        self._add("tag", key="tags")
        for vendor, results in self.data.get("last_analysis_results", {}).items():
            self._add("av_results", key="category", label=vendor, data=results)
            self._add("av_last_updated", key="engine_update", label=vendor, data=results)
            self._add("av_name", key="result", label=vendor, data=results)

        # files specific
        self._add("name", key="names")
        self._add("network_infrastructure")
        self._add("capability", key="capabilities_tags")
        self._add("yara_result", key="crowdsourced_yara_results", label_key="author", value_key="rule_name")
        for results in self.data.get("crowdsourced_ai_results", []):
            source = results.get("source")
            self._add("ai_result_category", key="category", label=source, data=results)
            self._add("ai_result_verdict", key="verdict", label=source, data=results)
            self._add("ai_result_analysis", key="analysis", label=source, data=results)
        for results in self.data.get("sigma_analysis_results", []):
            rule_id = results.get("rule_id")
            self._add("sigma_result_severity", key="rule_level", label=rule_id, data=results)
            self._add("sigma_result_name", key="rule_title", label=rule_id, data=results)
            self._add("sigma_result_description", key="rule_description", label=rule_id, data=results)
            self._add("sigma_result_author", key="rule_author", label=rule_id, data=results)
        for results in self.data.get("crowdsourced_ids_results", []):
            rule_id = results.get("rule_id")
            self._add("ids_result_severity", key="alert_severity", label=rule_id, data=results)
            self._add("ids_result_category", key="alert_category", label=rule_id, data=results)
            self._add("ids_result_rule_message", key="rule_msg", label=rule_id, data=results)
            for context in results.get("alert_context", []):
                for k, v in context.items():
                    label = f"{rule_id}::{k}"
                    self._add("ids_result_context", value=v, label=label)
        for vendor, results in self.data.get("sandbox_verdicts", {}).items():
            self._add("sandbox_verdict", key="category", label=vendor, data=results)
        threat_classifications = self.data.get("popular_threat_classification", {})
        if threat_classifications:
            self._add("threat", key="suggested_threat_label", data=threat_classifications)
            self._add("threat_category", key="popular_threat_category", value_key="value", data=threat_classifications)
            self._add("threat_family", key="popular_threat_name", value_key="value", data=threat_classifications)
        # for k, v in self.data.get("signature_info", {}).items():
        #     self._add("signature_info", label=k, value=v)
        for k, v in self.data.get("malware_config", {}).items():
            self._add("malware_config", label=k, value=v)
        self._add(
            "http_request", key="http", label_key="method", value_key=["url", "remote_host"],
            data=self.data.get("traffic_inspection", {})
        )

        # domain specific
        self._add("registrar")
        self._add("last_dns_record_date", is_timestamp=True)
        for dns_record in self.data.get("last_dns_records", []):
            dns_type = dns_record["type"]
            self._add("last_dns_record", key="value", label=dns_type, data=dns_record)
            if dns_type == "SOA":
                self._add("last_dns_record", key="rname", label="SOA_RNAME", data=dns_record)
        for vendor, rank_info in self.data.get("popularity_ranks", {}).items():
            self._add("popularity_rank", key="rank", label=vendor, data=rank_info)
        for vendor, category in self.data.get("categories", {}).items():
            self._add("category", label=vendor, value=category)

        # ip and domain
        self._add("whois")
        self._add("whois_date", is_timestamp=True)
        cert = self.data.get("last_https_certificate", {})
        if cert:
            # enforce correct DN order as per RFC 5280 and RFC 2253.
            # VT returns the cert as a dict, so I have no idea how it's supposed
            # to handle certs with multiple values for the same key...
            subject = ",".join([
                f"{k}={cert['subject'][k]}" for k in ("CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID")
                if cert["subject"].get(k, None)
            ])
            self._add("last_https_certificate_subject", value=subject)
            issuer = ",".join([
                f"{k}={cert['issuer'][k]}" for k in ("CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID")
                if cert["issuer"].get(k, None)
            ])
            self._add("last_https_certificate_issuer", value=issuer)
            self._add("last_https_certificate_validity_not_after", value=cert["validity"]["not_after"])
            self._add("last_https_certificate_validity_not_before", value=cert["validity"]["not_before"])
            self._add("last_https_certificate_date", is_timestamp=True)

        # ip specific
        self._add("country")
        self._add("continent")
        self._add("network")
        self._add("regional_internet_registry")
        self._add("autonomous_system_owner", key="as_owner")
        self._add("autonomous_system_number", key="asn")
        self._add("jarm_hash", key="jarm")
        for context in self.data.get("crowdsourced_context", []):
            value = context.get("details", None) or context.get("title")
            if value:
                self._add("crowdsource_context", label=context["source"], value=value)

        # urls specific
        self._add("redirection_chain")
        self._add("has_content")
        self._add("last_final_url")
        self._add("outgoing_link", key="outgoing_links")
        self._add("url")
        self._add("title")
        self._add("tld")
        self._add("last_http_response_content_length")
        self._add("last_http_response_content_sha256")
        self._add("last_http_response_code")
        for header, value in self.data.get("last_http_response_headers", {}).items():
            self._add("last_http_response_header", label=header, value=value)
        for cookie, value in self.data.get("last_http_response_cookies", {}).items():
            self._add("last_http_response_cookie", label=cookie, value=value)
        for vendor, value in self.data.get("targeted_brand", {}).items():
            self._add("targeted_brand", label=vendor, value=value)
        for tracker in self.data.get("trackers", {}):
            self._add("tracker", key=tracker, label=tracker, value_key="url", data=self.data.get("trackers", {}))


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
