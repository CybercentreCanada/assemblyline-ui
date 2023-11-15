"""Lookup through VirusTotal.

Uses the VirusTotal v3 API.
A valid API key is required.
"""
import base64
import datetime
import json
import os

from urllib import parse as ul

import requests

from flask import Flask, Response, jsonify, make_response, request


app = Flask(__name__)


API_KEY = os.environ.get("VT_API_KEY", "")
MAX_TIMEOUT = float(os.environ.get("MAX_TIMEOUT", 3))
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")  # Classification of this service
API_URL = os.environ.get("API_URL", "https://www.virustotal.com/api/v3")  # override in case of mirror
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://www.virustotal.com/gui/search")  # override in case of mirror

# verify can be boolean or path to CA file
verify = str(os.environ.get("VT_VERIFY", "true")).lower()
if verify in ("true", "1"):
    verify = True
elif verify in ("false", "0"):
    verify = False
VERIFY = verify

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
        return make_api_response(None, "No results.", 200)
    elif rsp.status_code != 200:
        return make_api_response(rsp.text, "Error submitting data to upstream.", rsp.status_code)

    return rsp.json().get("data", {})


@app.route("/details/<tag_name>/<tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Get detailed lookup results from VirusTotal

    Variables:
    tag_name => Tag to look up in the external system.
    tag => Tag value to lookup. *Must be double URL encoded.*

    Query Params:
    max_timeout => Maximum execution time for the call in seconds
    limit       => Maximum number of items to return
    nodata      => If specified, do not return the enrichment data

    Returns:
    # List of:
    [
        {
            "description": "",                     # Description of the findings
            "malicious": <bool>,                   # Is the file found malicious or not
            "confirmed": <bool>,                   # Is the maliciousness attribution confirmed or not
            "classification": <access control>,    # [Optional] Classification of the returned data
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "enrichment": [
                {"group": <group>,
                 "name": <name>, "name_description": <description>,
                 "value": <value>, "value_description": <description>,
                },
                ...,
            ]   # [Optional] ordered groupings of additional metadata
        },
        ...,
    ]
    """
    tag = ul.unquote(ul.unquote(tag))
    # Invalid tags must either be ignored, or return a 422
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            f"Tag name `{tag_name}` is invalid. Valid tags are: {', '.join(TAG_MAPPING.keys())}",
            f"Invalid tag name: {tag_name}",
            422,
        )
    nodata = request.args.get("nodata", "false").lower() in ("true", "1")
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT)
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = MAX_TIMEOUT

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
                threat_info.append(f"It was identified as {label}")
            categories = threats.get("popular_threat_category", [])
            if categories:
                cats = ", ".join(cat["value"] for cat in categories)
                threat_info.append(f"It was categorised with the labels {cats}")
            names = threats.get("popular_threat_name", [])
            if names:
                families = ", ".join(name["value"] for name in names)
                threat_info.append(f"It was given the names {families}")
        threat = ". ".join(threat_info)

    # construct a useful description based on available summary info
    vendors = attrs.get("last_analysis_stats", {}).get("malicious", 0)
    description = f"{vendors} security vendors"
    if sandboxes is not None:
        description += f" and {sandboxes} sandboxes"
    description += " flagged this as malicious."
    if threat:
        description += f" {threat}."

    search_encoded_tag = ul.quote(ul.quote(tag, safe=""), safe="")
    r = {
        "classification": CLASSIFICATION,
        "link": f"{FRONTEND_URL}/{search_encoded_tag}",
        "count": 1,  # url/domain/file/ip searches only return a single result/report
        "confirmed": False,  # virustotal does not offer a confirmed property
        "description": description,
        "malicious": True if vendors > 0 else False,
    }

    if not nodata:
        enricher = Enricher(data=attrs)
        r["enrichment"] = enricher.enrichment

    return make_api_response([r])


class Enricher():
    """Object to parse and hold enrichment info."""

    def __init__(self, data: dict) -> None:
        # self._enrichment = {}
        self.enrichment = []
        self.data = data
        self._enrich()

        # Convert dict to ordered list as JSON objects are unordered.
        # (note: As of py3.7 item order for dicts is part of the official language spec so we can rely on insert order)
        #
        # convert {<group>: {<name>: [<vals>]}} ->
        #   {"group": <group>, "values": [{"name": <name>, "values": [<value>]}]}
        # for group, kvals in self._enrichment.items():
        #     values = [{"name": name, "values": vals} for name, vals in kvals.items()]
        #     self.enrichment.append({"group": group, "values": values})

    def _add(
        self,
        group: str,
        name: str = None,
        key: str = None,
        default=None,
        *,
        name_key: str = None,
        name_description: str = "",
        name_description_key: str = None,
        value: str = None,
        value_key: str = None,
        value_description: str = "",
        value_description_key: str = None,
        is_timestamp: bool = False,
        ignore_falsy: bool = False,
        data: dict = None
    ):
        # allow a passed in dict to be parsed instead
        data = data or self.data

        # when value is directly given, we don't need to get the value out of a dict
        items = value
        if items is None:
            # key defaults to name if not specified.
            if key is None:
                key = name
            items = data.get(key, default)
            if items is None:
                return

        if not isinstance(items, list):
            items = [items]

        for item in items:
            # values should be either a str or list of str
            values = item
            if value_key:
                values = item.get(value_key, [])
            if not isinstance(values, list):
                values = [values]

            if isinstance(item, dict):
                name_description = item.get(name_description_key, "")
            for value in values:
                if ignore_falsy and not value:
                    continue

                name_ = name
                if name is None:
                    name_ = item.get(name_key)

                if isinstance(item, dict):
                    value_description = item.get(value_description_key, "")

                # when is_timestamp is specified, all values must be timestamps
                if is_timestamp:
                    value = datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()

                # sets cannot be json serialised by default
                # x = self._enrichment.setdefault(group, {}).setdefault(name_, [])
                # if value not in x:
                #     x.append(value)

                self.enrichment.append({
                    "group": group,
                    "name": name_,
                    "name_description": name_description,
                    "value": value,
                    "value_description": value_description,
                })

    def _enrich(self):
        """Parse the data and build an ordered result dict."""
        # Summary Info
        self._add("summary", "av_malicious", key="last_analysis_stats", value_key="malicious")
        self._add("summary", "av_suspicious", key="last_analysis_stats", value_key="suspicious", ignore_falsy=True)
        verdicts = [r.get("category", "") for r in self.data.get("sandbox_verdicts", {}).values()]
        self._add("summary", "sandbox_malicious", value=verdicts.count("malicious"))
        self._add("summary", "sandbox_suspicious", value=verdicts.count("suspicious"), ignore_falsy=True)
        verdicts = [r.get("verdict", "") for r in self.data.get("crowdsourced_ai_results", [])]
        self._add("summary", "ai_malicious", value=verdicts.count("malicious"), ignore_falsy=True)
        self._add("summary", "ai_suspicious", value=verdicts.count("suspicious"), ignore_falsy=True)
        threats = self.data.get("popular_threat_classification", {})
        if threats:
            self._add("summary", "threat", key="suggested_threat_label", data=threats)
            self._add("summary", "threat_family", key="popular_threat_name", value_key="value", data=threats)
            self._add("summary", "threat_category", key="popular_threat_category", value_key="value", data=threats)
        self._add("summary", "threat_family", key="threat_names")
        self._add("summary", "reputation", default=0)
        self._add("summary", "sigma_alerts_critical", key="sigma_analysis_stats", value_key="critical", ignore_falsy=True)
        self._add("summary", "sigma_alerts_high", key="sigma_analysis_stats", value_key="high", ignore_falsy=True)
        self._add("summary", "sigma_alerts_medium", key="sigma_analysis_stats", value_key="medium", ignore_falsy=True)
        self._add("summary", "sigma_alerts_low", key="sigma_analysis_stats", value_key="low", ignore_falsy=True)
        self._add("summary", "ids_alerts_high", key="crowdsourced_ids_stats", value_key="high", ignore_falsy=True)
        self._add("summary", "ids_alerts_medium", key="crowdsourced_ids_stats", value_key="medium", ignore_falsy=True)
        self._add("summary", "ids_alerts_low", key="crowdsourced_ids_stats", value_key="low", ignore_falsy=True)
        self._add("summary", "ids_alerts_info", key="crowdsourced_ids_stats", value_key="info", ignore_falsy=True)
        self._add("summary", "capabilities", key="capabilities_tags")
        if self.data.get("popularity_ranks", {}):
            self._add("summary", "labels", value="popular domain")
        for category in self.data.get("categories", {}).values():
            self._add("summary", "labels", value=category)
        for value in self.data.get("targeted_brand", {}).values():
            self._add("summary", "targeted_brand", value=value)

        # Crowdsourced context
        for context in self.data.get("crowdsourced_context", []):
            name = f"{context['title']} ({context['source']})"
            self._add("crowdsourced_context", name, value=context['details'])

        # Config extraction
        # The VT API docs are out of date and don't reflect what actually comes back.
        # We can only parse cases that we have seen examples of.
        for k, v in self.data.get("malware_config", {}).items():
            # families = list of dicts
            if k == "families":
                for fdetails in v:
                    if fname := fdetails.get("family"):
                        self._add("configuration_extraction", name="family", value=fname)
                    for conf in fdetails.get("configs", []):
                        for txt_conf in conf.get("txt_configs", []):
                            for key, value in json.loads(txt_conf).items():
                                self._add("configuration_extraction", name=key, value=value)
            else:
                # rely on out dated API docs... this will probably results in a dict being returned...
                self._add("configuration_extraction", k, value=v)

        # Networking
        self._add("networking", "infrastructure", key="network_infrastructure")
        for r in self.data.get("traffic_inspection", {}).get("http", []):
            url = r["url"]
            if url:
                self._add("networking", "http_request", value=f"{r['method']} {url}")
            url = r["remote_host"]
            if url:
                self._add("networking", "http_request", value=f"{r['method']} {url}")
            user_agent = r["user-agent"]
            if user_agent:
                self._add("networking", "user-agent", value=user_agent)

        # Yara rule hits
        # show source: rule_name, or rule_name: description?
        self._add(
            "yara_hits", key="crowdsourced_yara_results", name_key="source", value_key="rule_name",
            value_description_key="description")

        # Popularity
        for vendor, r in self.data.get("popularity_ranks", {}).items():
            last_updated = datetime.datetime.fromtimestamp(r["timestamp"], datetime.timezone.utc).isoformat()
            value = f"{r['rank']} ({last_updated})"
            self._add("popularity_ranks", vendor, value=value)

        # Sigma results
        for r in self.data.get("sigma_analysis_results", []):
            self._add(
                "sigma_alerts", r["rule_level"], value=f"{r['rule_title']} [{r['rule_author']}]",
                value_description_key="rule_description")

        # IDS details
        for results in self.data.get("crowdsourced_ids_results", []):
            for context in results.get("alert_context", []):
                for k, v in context.items():
                    self._add(
                        f"ids_alerts_{results['alert_severity']}",
                        name=results["rule_msg"],
                        name_description=results["rule_category"],
                        value=f"{k}: {v}")

        # AI results
        for r in self.data.get("crowdsourced_ai_results", []):
            grp = "ai_analysis"
            if r["category"]:
                grp = f"_{r['category']}"
            self._add(grp, key="crowdsourced_ai_results", name=r['source'], value_key="analysis")

        # DNS details
        self._add("dns_records", "last_updated", key="last_dns_record_date", is_timestamp=True)
        for dns_record in sorted(self.data.get("last_dns_records", []), key=lambda x: x["type"]):
            dns_type = dns_record["type"]
            self._add("dns_records", dns_type, value=dns_record["value"])
            if dns_type == "SOA":
                self._add("dns_records", "SOA_RNAME", value=dns_record["rname"])

        # Related URLs
        self._add("linked_urls", "final_url", key="last_final_url")
        self._add("linked_urls", "redirection_chain")
        self._add("linked_urls", "outgoing_links")

        # Last reponse
        self._add("last_response", "has_content")
        self._add("last_response", "content_sha256", key="last_http_response_content_sha256")
        self._add("last_response", "response_code", key="last_http_response_code")
        self._add("last_response", "content_length", key="last_http_response_content_length")
        for header, value in self.data.get("last_http_response_headers", {}).items():
            self._add("last_response_headers", header, value=value)
        for cookie, value in self.data.get("last_http_response_cookies", {}).items():
            self._add("last_response_cookies", cookie, value=value)

        # Trackers
        for tracker in self.data.get("trackers", {}):
            self._add("trackers", tracker, value_key="url", data=self.data.get("trackers", {}))

        # General for info only
        self._add("info", "names")
        self._add("info", "autonomous_system_owner", key="as_owner")
        self._add("info", "autonomous_system_number", key="asn")
        self._add("info", "labels", key="tags")
        self._add("info", "jarm_hash", key="jarm")
        self._add("info", "url")
        self._add("info", "title")
        self._add("info", "tld")
        self._add("info", "regional_internet_registry")
        self._add("info", "registrar")
        self._add("info", "country")
        self._add("info", "continent")
        self._add("info", "network")
        self._add("info", "whois_date", is_timestamp=True)
        self._add("info", "whois")

        # Certificate info
        cert = self.data.get("last_https_certificate", {})
        if cert:
            self._add("certificate_info", "last_updated", key="last_https_certificate_date", is_timestamp=True)
            # enforce correct DN order as per RFC 5280 and RFC 2253.
            # VT returns the cert as a dict, so I have no idea how it's supposed
            # to handle certs with multiple values for the same key...
            subject = ",".join([
                f"{k}={cert['subject'][k]}" for k in ("CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID")
                if cert["subject"].get(k, None)
            ])
            self._add("certificate_info", "subject", value=subject)
            issuer = ",".join([
                f"{k}={cert['issuer'][k]}" for k in ("CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID")
                if cert["issuer"].get(k, None)
            ])
            self._add("certificate_info", "issuer", value=issuer)
            self._add("certificate_info", "validity_not_after", value=cert["validity"]["not_after"])
            self._add("certificate_info", "validity_not_before", value=cert["validity"]["not_before"])

        # Sandbox results
        # ordered to show malicious before suspicious
        malicious = []
        sus = []
        for r in self.data.get("sandbox_verdicts", {}).values():
            if r["category"] == "malicious":
                malicious.append(r)
            if r["category"] == "suspicious":
                sus.append(r)
        for r in malicious:
            # sometimes malware_names are not set...
            value = ", ".join(r.get("malware_names", [])) or "malicious"
            confidence = f" (Confidence: {r.get('confidence')})" if r.get("confidence") else ""
            self._add("sandboxes", r["sandbox_name"], value=f"{value}{confidence}")
        for r in sus:
            self._add("sandboxes", r["sandbox_name"], value="suspicious")

        # AV results
        # ordered to show malicious before suspicious
        malicious = []
        sus = []
        for r in self.data.get("last_analysis_results", {}).values():
            if r["category"] == "malicious":
                malicious.append(r)
            if r["category"] == "suspicious":
                sus.append(r)
        for r in malicious:
            updated = f" ({r.get('engine_update')})" if r.get("engine_update") else ""
            self._add("security_vendors", r["engine_name"], value=f"{r['result']}{updated}")
        for r in sus:
            updated = f" ({r.get('engine_update')})" if r.get("engine_update") else ""
            self._add("security_vendors", r["engine_name"], value=f"suspicious{updated}")


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
