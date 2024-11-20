"""Hatching Results Generation module."""

import datetime
import json
from copy import deepcopy
from logging import getLogger
from re import IGNORECASE
from re import match as re_match
from typing import Any, Dict, List, Optional, Set, Tuple, cast
from urllib.parse import urlparse

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.attack_map import attack_map
from assemblyline.common.isotime import LOCAL_FMT_WITH_MS, format_time
from assemblyline.common.net import (
    is_valid_domain,
    is_valid_email,
    is_valid_ip,
    is_valid_port,
)
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Sandbox as SandboxModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    OntologyResults,
    Process,
    Sandbox,
    Signature,
)
from assemblyline_service_utilities.common.safelist_helper import is_tag_safelisted
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Result,
    ResultKeyValueSection,
    ResultProcessTreeSection,
    ResultSection,
    ResultTableSection,
    TableRow,
)

RE_HTTP_HOST_HEADER = r"host: "
RE_HTTP_USER_AGENT_HEADER = r"user-agent: "
RE_HATCHING_SVC_PRIVATE_IP = r"^(?:100\.6[4-9]\.|100\.[7-9]\d\.|100\.1[0-1]\d\.|100\.12[0-7]\.)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

REPORT_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

al_log.init_logging("service.hatching.hatching_result")
log = getLogger("assemblyline.service.hatching.hatching_result")

HATCHING_TO_AL_SCORE_MAP = {
    0: 0,
    1: 0,
    2: 0,
    3: 0,
    4: 0,
    5: 0,
    6: 600,
    7: 600,
    8: 800,
    9: 800,
    10: 1000,
}
Classification = forge.get_classification()


class HatchingResult:
    """Class to create service results from Hatching API output."""

    def __init__(
        self,
        hatching_results: Dict[str, Dict],
        ontres: OntologyResults,
        web_url: str,
        sample_id: str,
        safelist: Optional[Dict[str, Dict[str, List[str]]]] = None,
    ):
        """Initialize.

        Args:
            hatching_results (Dict[str, Dict]): Aggregated hatching results dict
                {
                    "overview": overview-api results dict,
                    "static_report": static report api results dict,
                    "triage_reports": [triage report api results dict per VM analysis],
                }
            ontres (OntologyResults): OntologyResults instance
            web_url (str): Hatching API endpoint URL
            sample_id (str): Hatching Result Sample ID for a given submission
            safelist (Dict[str, Dict[str, List[str]]]): Expects the AL4 System safelist.
        """
        self.hatching_results = hatching_results
        self.ontres = ontres
        self.web_url = web_url
        self.sample_id = sample_id
        if not safelist:
            self.safelist = {}
        else:
            self.safelist = safelist

    def generate_result(self) -> Result:
        """Generate the overall result and all result sections.

        Returns:
            Result: AL4 Result
        """
        result = Result()

        if self.hatching_results:
            overview_section = self._build_overview_section(
                self.hatching_results.get("overview", {})
            )
            if overview_section:
                result.add_section(overview_section)

            link_section = self._build_link_section()
            if link_section:
                result.add_section(link_section)

            # generate static analysis reports section
            static_analysis_section = self._build_static_analysis_section(
                self.hatching_results.get("static_report", {})
            )
            if static_analysis_section:
                result.add_section(static_analysis_section)

            # Generate sections for dynamic analysis triage results
            for triage_rpt in self.hatching_results.get("triage_reports", []):
                dyn_section = self._build_dynamic_results_sections(triage_rpt)
                if dyn_section:
                    result.add_section(dyn_section)

        return result

    def _build_dynamic_results_sections(
        self, triage_rpt: Dict[str, Any]
    ) -> Optional[ResultSection]:
        """Build a dynamic result section.

        Args:
            triage_rpt (Dict[str, Any]): hatching api output for a single dynamic analysis report

        Returns:
            Optional[ResultSection]: ResultSection or None
        """
        if triage_rpt:
            dyn_res_parent = ResultSection(
                f"Dynamic Analysis Platform: {triage_rpt.get('analysis', {}).get('platform')}"
            )

            info_sub_section = self._build_dynamic_result_info_section(triage_rpt)
            if info_sub_section:
                dyn_res_parent.add_subsection(info_sub_section)

            if triage_rpt.get("signatures"):
                sig_sub_section = self._build_sig_section(
                    triage_rpt.get("signatures", [])
                )
                if sig_sub_section:
                    dyn_res_parent.add_subsection(sig_sub_section)

            if triage_rpt.get("extracted"):
                mal_cfg_sub_section = self._build_malware_extract_section(
                    triage_rpt.get("extracted", []), is_static_analysis=False
                )
                if mal_cfg_sub_section:
                    dyn_res_parent.add_subsection(mal_cfg_sub_section)

            if triage_rpt.get("network"):
                net_sub_section = self._build_network_section(
                    triage_rpt.get("network", {})
                )
                if net_sub_section:
                    dyn_res_parent.add_subsection(net_sub_section)

            if triage_rpt.get("processes"):
                proc_sub_section = self._build_processes_section(
                    triage_rpt.get("processes", {})
                )
                if proc_sub_section:
                    dyn_res_parent.add_subsection(proc_sub_section)

            if dyn_res_parent.subsections:
                return dyn_res_parent

        return None

    def _build_dynamic_result_info_section(
        self, triage_rpt: Dict[str, Any]
    ) -> Optional[ResultKeyValueSection]:
        """Build the info section for the dynamic results parent section.

        Args:
            triage_rpt (Dict[str, Any]): Hatching API results for a given triage report

        Returns:
            Optional[ResultKeyValueSection]: Dyanmic Results Info Section or None
        """
        if triage_rpt:
            start_time = triage_rpt.get("analysis", {}).get("submitted")
            end_time = triage_rpt.get("analysis", {}).get("reported")
            execution_duration = determine_execution_duration(start_time, end_time)
            platform = triage_rpt.get("analysis", {}).get("platform")
            task_name = triage_rpt.get("task_name")
            score = triage_rpt.get("analysis", {}).get("score")

            body = {
                "Score": f"{score} of 10",
                "Task Name": task_name,
                "Platform": platform,
                "Duration": f"{execution_duration} seconds",
            }
            res = ResultKeyValueSection("Analysis Information")
            res.update_items(body)

            self._update_ontres_for_dynamic_result_info_section(
                task_name=task_name,
                start_time=start_time,
                end_time=end_time,
                platform=platform,
                version=triage_rpt.get("version"),
            )

            return res

        return None

    def _build_link_section(self) -> Optional[ResultSection]:
        """Build a section to display a link back to the submission on Hatching's platform.

        Returns:
            Optional[ResultSection]: Link Section or None
        """
        if self.web_url and self.sample_id:
            link = f"{self.web_url}/{self.sample_id}"
            section = ResultSection(
                "Link to Hatching Triage Analysis",
                body_format=BODY_FORMAT.URL,
                body=json.dumps({"name": link, "url": link}),
            )
            return section

        return None

    def _build_malware_extract_section(
        self,
        extracted_items: List[Dict[str, Any]],
        is_static_analysis: bool = True,
    ) -> Optional[ResultSection]:
        """Build the section that shows various items extracted from the malware.

        This handles both static and dynamic analysis scenarios.

        This contains a sub-section per extracted type. Configs, RansomNote, Dropper, Credentials.

        Args:
            extracted_items (List[Dict[str, Any]]): The extracted items from a triage or static
                analysis report
            static_analysis (bool): Whether this is a static analysis or not

        Returns:
            Optional[ResultSection]: A ResultSection or None if no configs found
        """
        if not extracted_items:
            return None

        res = ResultSection("Extracted Items")

        for extracted_item in extracted_items:
            # Build sub-section for any Config extracted
            if extracted_item.get("config"):
                sub_res = self._build_malware_extract_config_sub_section(
                    extracted_item.get("config", {}),
                    is_static_analysis=is_static_analysis,
                )
                if sub_res:
                    res.add_subsection(sub_res)

            # Build sub-section for any Credentials extracted
            if extracted_item.get("credentials"):
                sub_res = self._build_malware_extract_credentials_sub_section(
                    extracted_item.get("credentials", {}),
                    is_static_analysis=is_static_analysis,
                )
                if sub_res:
                    res.add_subsection(sub_res)

            # Build sub-section for any Dropper extracted
            if extracted_item.get("dropper"):
                sub_res = self._build_malware_extract_dropper_sub_section(
                    extracted_item.get("dropper", {}),
                    is_static_analysis=is_static_analysis,
                )
                if sub_res:
                    res.add_subsection(sub_res)

            # Build sub-section for any RansomNote extracted
            if extracted_item.get("ransom_note"):
                sub_res = self._build_malware_extract_ransomnote_sub_section(
                    extracted_item.get("ransom_note", {}),
                    is_static_analysis=is_static_analysis,
                )
                if sub_res:
                    res.add_subsection(sub_res)

        if res.subsections:
            return res

        return None

    def _build_malware_extract_config_sub_section(
        self, malware_config: Dict[str, Any], is_static_analysis: bool = True
    ) -> Optional[ResultKeyValueSection]:
        """Build a KeyValue section based on the RansomNote extracted from the reports.

        This handles both static and dynamic anlaysis scenarios.

        Ref on structure: https://tria.ge/docs/cloud-api/dynamic-report/
        See the Config struct referenced by Extract

        Args:
            malware_config (Dict[str, Any]): The config key from the report.extracted[] dicts
            is_static_analysis (bool, optional): Whether this is a static analysis report or not.

        Returns:
            Optional[ResultKeyValueSection]:
        """
        if not malware_config:
            return None

        res = ResultKeyValueSection("Extracted Malware Config")

        # dump the whole thing into a KeyValue table
        malware_config_disp = sanitize_dict(flatten_dict(malware_config))
        body = malware_config_disp
        res.update_items(body)

        # Create tags from various values in the Config struct
        for val in malware_config.get("c2", []):
            ip, port = get_ip_port(val)

            if ip:
                tag_name = get_network_tag_name(
                    val=ip, is_static_analysis=is_static_analysis
                )
                if tag_name:
                    add_tag(
                        result_section=res,
                        tag=tag_name,
                        value=ip,
                        safelist=self.safelist,
                    )
            if port:
                tag_name = "network.port"
                add_tag(
                    result_section=res, tag=tag_name, value=port, safelist=self.safelist
                )

        for val in malware_config.get("dns", []):
            tag_name = get_network_tag_name(
                val=val, is_static_analysis=is_static_analysis
            )
            if tag_name:
                add_tag(
                    result_section=res, tag=tag_name, value=val, safelist=self.safelist
                )

        for val in malware_config.get("command_lines", []):
            tag_name = "dynamic.process.command_line"
            if tag_name:
                add_tag(
                    result_section=res, tag=tag_name, value=val, safelist=self.safelist
                )

        if malware_config.get("listen_addr"):
            val = malware_config.get("listen_addr")
            tag_name = get_network_tag_name(
                val=val, is_static_analysis=is_static_analysis
            )
            if tag_name:
                add_tag(
                    result_section=res, tag=tag_name, value=val, safelist=self.safelist
                )

        if malware_config.get("listen_port"):
            val = malware_config.get("listen_port")
            tag_name = "network.port"
            add_tag(result_section=res, tag=tag_name, value=val, safelist=self.safelist)

        res.set_heuristic(100)

        if res.body:
            return res

        return None

    def _build_malware_extract_credentials_sub_section(
        self, credentials: Dict[str, Any], is_static_analysis: bool = True
    ) -> Optional[ResultKeyValueSection]:
        """Build a KeyValue section based on the Credentials info extracted from the reports.

        This handles both static and dynamic anlaysis scenarios.

        Ref on structure: https://tria.ge/docs/cloud-api/dynamic-report/
        See the Credentials struct referenced by Extract

        Args:
            credentials (Dict[str, Any]): The credentials key from the report.extracted[] dicts
            is_static_analysis (bool, optional): Whether this is a static analysis report or not.

        Returns:
            Optional[ResultKeyValueSection]:
        """
        if not credentials:
            return None

        res = ResultKeyValueSection("Extracted Credentials")

        # dump the whole thing into a KeyValue table
        creds_disp = sanitize_dict(flatten_dict(credentials))
        body = creds_disp
        res.update_items(body)

        # Create tags from various values in the Credentials struct
        if credentials.get("password"):
            passwd = credentials.get("password")
            tag_passwd = "info.password"
            add_tag(
                result_section=res, tag=tag_passwd, value=passwd, safelist=self.safelist
            )

        if credentials.get("host"):
            host = credentials.get("host")
            tag_network: Optional[str] = get_network_tag_name(
                val=host, is_static_analysis=is_static_analysis
            )
            if tag_network:
                add_tag(
                    result_section=res,
                    tag=tag_network,
                    value=host,
                    safelist=self.safelist,
                )

        if credentials.get("port"):
            port = credentials.get("port")
            tag_port = "network.port"
            add_tag(
                result_section=res, tag=tag_port, value=port, safelist=self.safelist
            )

        if credentials.get("protocol"):
            protocol = credentials.get("protocol")
            tag_proto = "network.protocol"
            add_tag(
                result_section=res,
                tag=tag_proto,
                value=protocol,
                safelist=self.safelist,
            )

        res.set_heuristic(103)

        if res.body:
            return res

        return None

    def _build_malware_extract_dropper_sub_section(
        self, dropper: Dict[str, Any], is_static_analysis: bool = True
    ) -> Optional[ResultKeyValueSection]:
        """Build a KeyValue section based on the Dropper info extracted from the reports.

        This handles both static and dynamic anlaysis scenarios.

        Ref on structure: https://tria.ge/docs/cloud-api/dynamic-report/
        See the Dropper struct referenced by Extract

        Args:
            dropper (Dict[str, Any]): The dropper key from the report.extracted[] dicts
            is_static_analysis (bool, optional): Whether this is a static analysis report or not.

        Returns:
            Optional[ResultKeyValueSection]:
        """
        if not dropper:
            return None

        res = ResultKeyValueSection("Extracted Dropper")

        # dump the whole thing into a KeyValue table
        dropper_disp = sanitize_dict(flatten_dict(dropper))
        body = dropper_disp
        res.update_items(body)

        network_tag_type = "static"
        if not is_static_analysis:
            network_tag_type = "dynamic"

        # Create tags from various values in the Dropper struct
        for dropper_url in dropper.get("urls", []):
            tag_name = f"network.{network_tag_type}.uri"

            url = dropper_url.get("url")
            add_tag(
                result_section=res,
                tag=tag_name,
                value=url,
                safelist=self.safelist,
            )

        res.set_heuristic(102)

        if res.body:
            return res

        return None

    def _build_malware_extract_ransomnote_sub_section(
        self, ransom_note: Dict[str, Any], is_static_analysis: bool = True
    ) -> Optional[ResultKeyValueSection]:
        """Build a KeyValue section based on the Configs extracted from the reports.

        This handles both static and dynamic anlaysis scenarios.

        Ref on structure: https://tria.ge/docs/cloud-api/dynamic-report/
        See the RansomNote struct referenced by Extract

        Args:
            ransom_note (Dict[str, Any]): The ransom_note key from the report.extracted[] dicts
            is_static_analysis (bool, optional): Whether this is a static analysis report or not.

        Returns:
            Optional[ResultKeyValueSection]:
        """
        if not ransom_note:
            return None

        res = ResultKeyValueSection("Extracted Ransom Note")

        # dump the whole thing into a KeyValue table
        ransom_note_disp = sanitize_dict(flatten_dict(ransom_note))
        body = ransom_note_disp
        res.update_items(body)

        network_tag_type = "static"
        if not is_static_analysis:
            network_tag_type = "dynamic"

        # Create tags from various values in the RansomNote struct
        for eml in ransom_note.get("emails", []):
            if is_valid_email(eml):
                tag_name = "network.email.address"
                add_tag(
                    result_section=res,
                    tag=tag_name,
                    value=eml,
                    safelist=self.safelist,
                )

        for url in ransom_note.get("urls", []):
            tag_name = f"network.{network_tag_type}.uri"
            add_tag(
                result_section=res,
                tag=tag_name,
                value=url,
                safelist=self.safelist,
            )

        res.set_heuristic(101)

        if res.body:
            return res

        return None

    def _build_network_section(
        self, hatching_network: Dict[str, Any]
    ) -> Optional[ResultSection]:
        """Build the Network Section.

        Args:
            hatching_network (Dict[str, Any]): The network section of a given dynamic triage
                report's api results

        Returns:
            Optional[ResultSection]: A ResultSection or None if no network sub-sections are created.
        """
        if not hatching_network:
            return None

        res = ResultSection("Network")

        # As iocs are evaluated when processing the dns and http-traffic, if they are considered
        # safelisted, then the associated network flow id is added to this list. It's used as input
        # when processing the network flows themselves.
        filtered_flow_ids: Set[int] = set()

        # process dns traffic
        dns_map, filtered_dns_flow_ids = self._process_dns(hatching_network)
        filtered_flow_ids = filtered_flow_ids.union(set(filtered_dns_flow_ids))
        if dns_map.get("observed_ips") or dns_map.get("observed_domains"):
            dns_sub_section = self._build_network_dns_sub_section(dns_map)
            if dns_sub_section:
                res.add_subsection(dns_sub_section)

        # process http traffic
        http_traffic, filtered_network_flow_ids = self._process_http_traffic(
            hatching_network
        )
        filtered_flow_ids = filtered_flow_ids.union(set(filtered_network_flow_ids))
        if http_traffic:
            http_sub_section = self._build_network_http_sub_section(
                http_traffic, filtered_flow_ids
            )
            if http_sub_section:
                res.add_subsection(http_sub_section)

        network_flows_traffic = self._process_network_flow_traffic(
            hatching_network, list(filtered_flow_ids)
        )
        if network_flows_traffic:
            net_flows_sub_section = self._build_network_flows_sub_section(
                network_flows_traffic
            )
            if net_flows_sub_section:
                res.add_subsection(net_flows_sub_section)

        if res.subsections:
            return res

        return None

    def _build_network_dns_sub_section(
        self, dns_map: Dict[str, Any]
    ) -> Optional[ResultTableSection]:
        """Build the Network DNS sub-section.

        This creates a table view of the domain and associated IP resolutions and creates tags for:
            - network.dynamic.domain, network.dynamic.ip

        This does not create any heuristics.

        Args:
            dns_map (Dict[str, Any]): The processed dns results
                {
                    "domain_map": {},
                    "observed_ips": [],
                    "observed_domains": []
                }

        Returns:
            Optional[ResultTableSection]: A ResultTableSection or None
        """
        if not dns_map:
            return None

        res = ResultTableSection("DNS Resolutions")

        # Create tags for all found domains and ips
        #  Add tag will take care of de-duping
        # Note: There is no scoring associated with the tag for these.

        for dom in dns_map.get("observed_domains", []):
            _ = add_tag(
                res, tag="network.dynamic.domain", value=dom, safelist=self.safelist
            )

        for ip in dns_map.get("observed_ips", []):
            _ = add_tag(res, tag="network.dynamic.ip", value=ip, safelist=self.safelist)

        for dom, resolved_ips in dns_map.get("domain_map", {}).items():
            # add domain
            _ = add_tag(
                res, tag="network.dynamic.domain", value=dom, safelist=self.safelist
            )

            annotated_resolved_ips = []

            for ip in resolved_ips or []:
                _ = add_tag(
                    res, tag="network.dynamic.ip", value=ip, safelist=self.safelist
                )

                # Annotate the resolved IP if it is in the 100.64.0.0/10 IP space
                # Hatching uses this network when the simulate network response option is used.
                # See RFC 6598
                if re_match(RE_HATCHING_SVC_PRIVATE_IP, ip):
                    annotated_resolved_ips.append(f"{ip} (Hatching Simulated Network)")
                else:
                    annotated_resolved_ips.append(ip)

            res.add_row(TableRow(domain=dom, ips=", ".join(annotated_resolved_ips)))

        if res.tags:
            return res

        return None

    def _build_network_flows_sub_section(
        self, network_flows: List[Dict[str, Any]]
    ) -> Optional[ResultTableSection]:
        """Build the Network flows sub-section.

        This creates a table of domain-ja3-ja3s entries.

        It also creates tags for observed traffic for:
            - network.protocol, network.port, network.tls.sni, network.tls.ja3_hash

        Args:
            network_flows (List[Dict[str, Any]]): The network flows from a triage report

        Returns:
            Optional[ResultTableSection]: A ResultTableSection or None
        """
        if not network_flows:
            return None

        res = ResultTableSection("Network Flows")

        protocols: List[str] = []
        ports: List[str] = []
        snis: List[str] = []

        ja3_dicts = []

        for flow in network_flows or []:
            for proto in flow.get("protocols", []):
                if proto not in protocols:
                    protocols.append(proto)

            dst = flow.get("dst")
            if dst:
                dst_split = dst.split(":")
                if len(dst_split) > 1:
                    port = dst_split[-1]
                    if port not in ports:
                        ports.append(port)

            if flow.get("tls_ja3"):
                ja3d = {
                    "domain": flow.get("domain"),
                    "ja3": flow.get("tls_ja3"),
                    "ja3s": flow.get("tls_ja3s"),
                }
                if ja3d not in ja3_dicts:
                    ja3_dicts.append(ja3d)

            sni = flow.get("tls_sni")
            if sni:
                if sni not in snis:
                    snis.append(sni)

        # Add tags
        # network.protocol
        # network.port
        # network.tls.sni

        for proto in protocols:
            _ = add_tag(
                res, tag="network.protocol", value=proto, safelist=self.safelist
            )

        for port in ports:
            _ = add_tag(res, tag="network.port", value=port, safelist=self.safelist)

        for sni in snis:
            _ = add_tag(res, tag="network.tls.sni", value=sni, safelist=self.safelist)

        # Add tags and table-rows for the ja3
        # network.tls.ja3_hash

        for ja3_dict in ja3_dicts:
            res.add_row(
                TableRow(
                    domain=ja3_dict.get("domain"),
                    ja3=ja3_dict.get("ja3"),
                    ja3s=ja3_dict.get("ja3s"),
                )
            )

            _ = add_tag(
                res,
                tag="network.tls.ja3_hash",
                value=ja3_dict.get("ja3"),
                safelist=self.safelist,
            )

            # Future: Need AL4 to add a tag for JA3S

        if res.body or res.tags:
            return res

        return None

    def _build_network_http_sub_section(
        self, http_traffic: Dict[str, Dict[str, Any]], filtered_flow_ids: set
    ) -> Optional[ResultSection]:
        """Build the Network HTTP Traffic sub-section.

        This will create multiple sub-sections based on the input for extracted URIs, extracted
        User Agents, and possible domain-fronting activity.

        The following tags are created: network.dynamic.uri, network.user_agent and possibly others.

        There is one heuristic created if domain-fronting is observed.

        The http_response.response field from the Hatching API does not have the full http response.
        Example response. "response": "HTTP/2.0 302"

        Args:
            http_traffic (Dict[str, Dict[str, Any]]): The processed http network traffic.
            filtered_flow_ids (set): Set of filtered network flow ids.

        Returns:
            Optional[ResultSection]: A ResultSection or None
        """
        if not http_traffic:
            return None

        res = ResultSection("HTTP Traffic")

        # Add tags fo observed URIs
        res_uri = ResultTableSection("Extracted URIs")

        for flow_id, v in http_traffic.items():
            if flow_id in filtered_flow_ids:
                continue

            uri = v.get("http_request", {}).get("url")

            if uri:
                res_uri.add_row(TableRow(uri=uri))

                _ = add_tag(
                    res_uri,
                    tag="network.dynamic.uri",
                    value=uri,
                    safelist=self.safelist,
                )

        if res_uri.section_body.body:
            res.add_subsection(res_uri)

        # Add tags fo observed http user-agent headers
        res_ua = ResultTableSection("Extracted User Agents from Headers")
        for flow_id, v in http_traffic.items():
            if flow_id in filtered_flow_ids:
                continue

            ua = v.get("http_request", {}).get("headers", {}).get("user-agent")

            if ua:
                res_ua.add_row(TableRow(user_agent=ua))

                _ = add_tag(
                    res_ua, tag="network.user_agent", value=ua, safelist=self.safelist
                )
        if res_ua.section_body.body:
            res.add_subsection(res_ua)

        # Detect domain fronting
        dom_front_set = detect_domain_fronting(http_traffic)
        if dom_front_set:
            domain_front_sec = ResultTableSection("Domain Fronting")

            for dom_front in dom_front_set:
                # uri domain
                uri_dom = dom_front.get("uri_domain")
                tag_net_uri = get_network_tag_name(
                    val=uri_dom, is_static_analysis=False
                )
                if tag_net_uri:
                    add_tag(
                        result_section=domain_front_sec,
                        tag=tag_net_uri,
                        value=uri_dom,
                        safelist=self.safelist,
                    )

                # host header domain
                host_header_dom = dom_front.get("host")
                tag_net_dom = get_network_tag_name(
                    val=host_header_dom, is_static_analysis=False
                )
                if tag_net_dom:
                    add_tag(
                        result_section=domain_front_sec,
                        tag=tag_net_dom,
                        value=host_header_dom,
                        safelist=self.safelist,
                    )

                domain_front_sec.add_row(
                    TableRow(
                        uri_domain=uri_dom,
                        host_header_domain=host_header_dom,
                    )
                )

            domain_front_sec.set_heuristic(200)
            res.add_subsection(domain_front_sec)

        if res.subsections:
            return res

        return None

    def _build_overview_section(
        self, overview: Dict[str, Any]
    ) -> Optional[ResultKeyValueSection]:
        """Build the Overview section.

        This section will set a heuristic based on the Hatching overall score.

        Args:
            overview (Dict[str, Any]): The hatching overview api results.

        Returns:
            Optional[ResultKeyValueSection]:
        """
        if overview:
            start_time = overview.get("sample", {}).get("created")
            end_time = overview.get("sample", {}).get("completed")

            execution_duration = determine_execution_duration(start_time, end_time)
            vm_profiles: List[str] = determine_vm_profiles(overview)
            score = overview.get("sample", {}).get("score")

            body = {
                "Overall Score": f"{score} of 10",
                "Sample ID": self.sample_id,
                "Duration": f"{execution_duration} seconds",
                "VM Profile(s)": ", ".join(vm_profiles),
            }
            res = ResultKeyValueSection("Results Overview")
            res.update_items(body)

            # Set the scoring classification heuristic
            score_heur_id = determine_classification_heuristic(
                overview.get("analysis", {}).get("score")
            )
            if score_heur_id:
                res.set_heuristic(score_heur_id)

            return res

        return None

    def _build_processes_section(
        self, hatching_procs: List[Dict[str, Any]]
    ) -> Optional[ResultProcessTreeSection]:
        """Build the Processes Section.

        Args:
            hatching_procs (List[Dict[str, Any]]): The processes section of a given dynamic triage
                report's api results

        Returns:
            Optional[ResultProcessTreeSection]: A ResultProcessTreeSection or None
        """
        if not hatching_procs:
            return None

        # convert the processes from hatching into the ontres
        self._process_processes(hatching_procs)

        if not self.ontres.get_processes():
            return None

        proc_section = self.ontres.get_process_tree_result_section()

        if proc_section:
            return proc_section

        return None

    def _build_sig_section(
        self, signatures: List[Dict[str, Any]]
    ) -> Optional[ResultSection]:
        """Build the Hatching generated signatures section.

        This handles both static and dynamic analysis scenarios and contains a sub-section per
        observed signature.

        Args:
            signatures (List[Dict[str, Any]]): Hatching results signatures

        Returns:
            Optional[ResultSection]: ResultSection or None
        """
        if not signatures:
            return None

        res = ResultSection("Signatures")

        sig_dicts: List[Dict[str, Dict[str, Any]]] = self._process_sigs(signatures)

        for sigd in sig_dicts:
            ontres_sig: Signature = cast(Signature, sigd.get("ontres_sig"))
            if ontres_sig:
                sig_res = self._build_sig_sub_section(
                    ontres_sig=ontres_sig,
                    hatching_sig=sigd.get("hatching_sig", {}),
                )

                if sig_res:
                    self.ontres.add_signature(ontres_sig)
                    res.add_subsection(sig_res)

        if res.subsections:
            return res

        return None

    def _build_sig_sub_section(
        self, ontres_sig: Signature, hatching_sig: Dict[str, Any]
    ) -> Optional[ResultKeyValueSection]:
        """Create the signature sub-section for the given hatching signature.

        It associates a generic heuristic indicating a Hatching Signature was observed.
        Hatching is closed source and there is no known list of hatching signatures to map to.

        Args:
            ontres_sig (Signature): OntologyResult Signature
            hatching_sig (Dict[str, Any]): The associated hatching api results signature

        Returns:
            Optional[ResultMultiSection]: ResultMultiSection
        """
        # Other attributes available in the hatching-sig to consider
        #  - tags, indicators, YaraRule, URL..
        #  ref: https://tria.ge/docs/cloud-api/dynamic-report/

        if not ontres_sig or not hatching_sig:
            return None

        res = ResultKeyValueSection(f"Signature: {ontres_sig.name}")  # type: ignore

        score = hatching_sig.get("score")
        if score:
            score_txt = f"{score} of 10"
        else:
            score_txt = "No Score"

        body = {
            "Description": hatching_sig.get("desc", "No description for signature."),
            "Score": score_txt,
        }
        res.update_items(body)

        # Set the Heuristic
        # Signature approach Chosen: Use a generic heuristic Id and map it to a
        #  Signature/Score/Attack IDs
        res.set_heuristic(300)
        # adding sig and score
        res.heuristic.add_signature_id(
            ontres_sig.name,  # type: ignore
            HATCHING_TO_AL_SCORE_MAP[hatching_sig.get("score", 0)],
        )

        # attack ids / ttps
        if ontres_sig.attacks and len(ontres_sig.attacks) > 0:
            for attack in ontres_sig.attacks:
                res.heuristic.add_attack_id(attack.get("attack_id"))

        # malware families
        if ontres_sig.malware_families and len(ontres_sig.malware_families) > 0:
            _ = add_tag(
                res,
                tag="dynamic.signature.family",
                value=ontres_sig.malware_families,
                safelist=self.safelist,
            )

        return res

    def _build_static_analysis_section(
        self, static_report: Dict[str, Any]
    ) -> Optional[ResultSection]:
        """Build the static analysis report section.

        Args:
            static_report (Dict[str, Any]): hatching api output for static analysis reports

        Returns:
            Optional[ResultSection]: ResultSection or None if nothing to report
        """
        if static_report:
            res = ResultSection("Static Analysis")

            sig_sub_section = self._build_sig_section(
                static_report.get("signatures", [])
            )
            if sig_sub_section:
                res.add_subsection(sig_sub_section)

            if static_report.get("extracted"):
                mal_cfg_sub_section = self._build_malware_extract_section(
                    static_report.get("extracted", []),
                    is_static_analysis=True,
                )
                if mal_cfg_sub_section:
                    res.add_subsection(mal_cfg_sub_section)

            if res.subsections:
                return res

        return None

    def _is_dns_req_safelisted(self, host: str) -> bool:
        """Determine if the host in an observed DNS request is in the safelist.

        Args:
            host (str): hostname

        Returns:
            bool:
        """
        return is_tag_safelisted(
            host, ["network.dynamic.ip", "network.dynamic.domain"], self.safelist
        )

    def _is_http_req_safelisted(self, host: str, uri: str) -> bool:
        """Determine if the domain or uri in observed http-request traffic is in the safelist.

        Args:
            host (str): hostname
            uri (str):

        Returns:
            bool: True if either host or uri is in the safelist.
        """
        if uri is None:
            uri = ""

        return is_tag_safelisted(
            host, ["network.dynamic.ip", "network.dynamic.domain"], self.safelist
        ) or is_tag_safelisted(uri, ["network.dynamic.uri"], self.safelist)

    def _process_dns(
        self, hatching_network: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[int]]:
        """Process Hatching network DNS results from a given dynamic analysis triage report.

        If the domain or ip is in the safelist, it will not be in the response and will be added to
        the filtered flows returned. in-addr-.arpa lookups for private IPs are also filtered as this
        is just noise.

        Args:
            hatching_network (Dict[str, Any]): DNS results from a Hatching dynamic analysis triage
                report

        Returns:
            Dict[str, Any]:
                {
                    "domain_map": {
                        {
                            "<domain>": set(<resolved-ip>),
                        }
                    },
                    # There may be IPs in this list that are not in domain_map
                    "observed_ips": List,
                    # There may be domains requested that have no response therefore won't be in the
                    #  domain_map
                    "observed_domains": List
                },
            List[int]: List of flow ids observed to have safelisted domains, ips, or is filtered out
        """
        dns_map: Dict[str, Any] = {
            "domain_map": {},
            "observed_ips": [],
            "observed_domains": [],
        }

        # Any time a domain is identified as being in the safelist or is filtered, add it to list
        filtered_flow_ids: List[int] = []

        # Start by capturing all of the domains requested.
        #  Doing this in case there is no corresponding network.requests[].dns_response
        for req in hatching_network.get("requests", []):
            dns_req = req.get("dns_request")
            flow_id = req.get("flow")

            if dns_req:
                for dom in dns_req.get("domains"):
                    # ignore private hatching ip in-addr.arpa records as it's noise
                    if not is_domain_a_private_rev_dns_lookup(dom):
                        if self._is_dns_req_safelisted(dom):
                            if flow_id not in filtered_flow_ids:
                                filtered_flow_ids.append(flow_id)
                        else:
                            if dom not in dns_map["observed_domains"]:
                                dns_map["observed_domains"].append(dom)
                    else:
                        if flow_id not in filtered_flow_ids:
                            filtered_flow_ids.append(flow_id)

        # process the responses
        for req in hatching_network.get("requests", []):
            dns_resp = req.get("dns_response")
            flow_id = req.get("flow")

            if dns_resp and flow_id not in filtered_flow_ids:
                in_addr_found = False

                # Associate each domain to each ip
                for dom in dns_resp.get("domains", []):
                    # ignore private hatching ip in-addr.arpa records as it's noise
                    if not is_domain_a_private_rev_dns_lookup(dom):
                        if self._is_dns_req_safelisted(dom):
                            if flow_id not in filtered_flow_ids:
                                filtered_flow_ids.append(flow_id)
                        else:
                            dns_entry = dns_map["domain_map"].get(dom)
                            if not dns_entry:
                                dns_map["domain_map"][dom] = []

                            for ip in dns_resp.get("ip", []):
                                # purposefully not adding the flow to the safelist as there could be
                                # other IPs returned in this list that are not safelisted.
                                if ip not in dns_map["domain_map"][dom]:
                                    dns_map["domain_map"][dom].append(ip)

                    else:
                        in_addr_found = True
                        if flow_id not in filtered_flow_ids:
                            filtered_flow_ids.append(flow_id)

                # associate all observed IPs unless it is related to an in-addr.arpa record
                if not in_addr_found:
                    for ip in dns_resp.get("ip", []):
                        if ip not in dns_map["observed_ips"]:
                            dns_map["observed_ips"].append(ip)

                    # associate all observed domains
                    for dom in dns_resp.get("domains", []):
                        if dom not in dns_map["observed_domains"]:
                            dns_map["observed_domains"].append(dom)

        return dns_map, filtered_flow_ids

    def _process_http_traffic(
        self, hatching_network: Dict[str, Any]
    ) -> Tuple[Dict[str, Dict[str, Any]], List[int]]:
        """Process the Hatching network http-traffic from a given dynamic analysis triage report.

        Observed uris in the safelist will be filtered from the response.

        Args:
            hatching_network (Dict[str, Any]): Network traffic from a Hatching dynamic analysis
                triage report

        Returns:
            Dict[str, Dict[str, Any]]]: Normalized http traffic structure
                http_traffic = {
                    "<flow_num>": {
                        "http_request": {
                            # hatching api results: network.requests[].http_request
                            "method": str,
                            "url": str,
                            "request": str,
                            # headers is changed to only
                            "headers": {
                                "header-name": "header-value"
                            }
                        }
                        "http_response": {
                            # hatching api results: network.requests[].http_response
                            "status": str,
                            "response": str,
                            "headers": [str],
                        }
                    },
                },
            List[int]: List of flow ids observed to have safelisted uris or that have been filtered
        """
        # Aggregated view of all observed http traffic
        http_traffic: Dict[str, Dict[str, Any]] = {}

        # Any time a host or URI is identified as being in the safelist, add it to this list
        filtered_flow_ids: List[int] = []

        # normalize the data into the above structure and filter out safelisted flows
        for req in hatching_network.get("requests", []):
            flow_id = req.get("flow")
            http_req = req.get("http_request")
            http_resp = req.get("http_response")

            if http_req:
                # grab the URI
                uri = http_req.get("url")
                if not uri:
                    continue

                # init the flow_id key
                if not http_traffic.get(flow_id):
                    http_traffic[flow_id] = {}

                # only proceed if the uri or hostname is not safelisted
                uri_components = urlparse(uri)

                if self._is_http_req_safelisted(uri_components.hostname, uri):
                    if flow_id not in filtered_flow_ids:
                        filtered_flow_ids.append(flow_id)
                else:
                    http_traffic[flow_id]["http_request"] = http_req

                    new_headers = {}

                    # parse the headers
                    for header in http_req.get("headers", []):
                        # extract host
                        host_match = re_match(RE_HTTP_HOST_HEADER, header, IGNORECASE)
                        if host_match:
                            hdr_host = header[host_match.end() :]

                            if hdr_host and not self._is_http_req_safelisted(
                                hdr_host, uri
                            ):
                                new_headers["host"] = hdr_host.strip()

                        # extract user-agent
                        ua_match = re_match(
                            RE_HTTP_USER_AGENT_HEADER, header, IGNORECASE
                        )
                        if ua_match:
                            hdr_ua = header[ua_match.end() :]

                            if hdr_ua:
                                new_headers["user-agent"] = hdr_ua.strip()

                    # Setting the headers to the new/filtered structure
                    http_traffic[flow_id]["http_request"]["headers"] = new_headers

            # do not process flows that have been safelisted after going through the http requests
            elif http_resp and flow_id not in filtered_flow_ids:
                # init the flow_id key
                if not http_traffic.get(flow_id):
                    http_traffic[flow_id] = {}

                http_traffic[flow_id]["http_response"] = http_resp

        # remove any safelisted flow ids from the final dict
        #  could have made it in if things out of order
        for safe_flow_id in filtered_flow_ids:
            _ = http_traffic.pop(safe_flow_id, None)  # type: ignore

        return (http_traffic, filtered_flow_ids)

    def _process_network_flow_traffic(
        self, hatching_network: Dict[str, Any], filtered_flow_ids: List[int]
    ) -> List[Dict[str, Any]]:
        """Process Hatching network flow results from a given dynamic analysis triage report.

        Flows found in the filtered_flow_ids input are filtered from the results.

        Args:
            hatching_network (Dict[str, Any]): Hatching Network results
            filtered_flow_ids List[int]: set of filtered network-flow ids

        Returns:
            List[Dict[str, Any]]: List of network.flows in original api results format.
                [
                    {
                        "id": 5,
                        "src": "10.127.0.83:58589",
                        "dst": "8.8.8.8:53",
                        "proto": "udp",
                        "pid": 1988,
                        "procid": 71,
                        "first_seen": 7269,
                        "last_seen": 7286,
                        "rx_bytes": 158,
                        "rx_packets": 1,
                        "tx_bytes": 56,
                        "tx_packets": 1,
                        "protocols": [
                            "dns"
                        ],
                        "domain": "g.bing.com"
                    },
                ]
        """
        network_flows = []

        if hatching_network:
            if not filtered_flow_ids:
                filtered_flow_ids = []

            for flow in hatching_network.get("flows", []):
                if flow.get("id") in filtered_flow_ids:
                    continue

                # consider further filtering. e.g. dst RFC1918
                network_flows.append(flow)

        return network_flows

    def _process_processes(
        self,
        hatching_procs: List[Dict[str, Any]],
    ) -> None:
        """Process Hatching processes results from a given dynamic analysis triage report.

        The procs will be updated on the ontres.

        Args:
            param hatching_procs (List[Dict[str, Any]]): The processes section of a given dynamic
             triage report's api results

        Returns:
            None
        """
        proc_start_time = datetime.datetime.utcnow()

        session = self.ontres.sandboxes[-1].objectid.session  # type: ignore
        for proc in hatching_procs:
            # Hatching process def
            # Process struct {
            #     ProcID       int32       `json:"procid,omitempty"`
            #     ParentProcID int32       `json:"procid_parent,omitempty"`
            #     PID          uint64      `json:"pid"`
            #     PPID         uint64      `json:"ppid"`
            #     Cmd          interface{} `json:"cmd"`
            #     Image        string      `json:"image,omitempty"`
            #     Orig         bool        `json:"orig"` - This indicates whether the file was already present on the VM
            #     System       bool        `json:"-"`
            #     Started      uint32      `json:"started"`
            #     Terminated   uint32      `json:"terminated,omitempty"`
            # }

            image = proc.get("image", "")
            command_line = proc.get("cmd", "")
            # cmd may come back as a str or a list
            if isinstance(command_line, list) and len(command_line) > 0:
                command_line = command_line[0]

            if (
                not image
                or not command_line
                or is_tag_safelisted(
                    image, ["dynamic.process.file_name"], self.safelist
                )
                or is_tag_safelisted(
                    command_line, ["dynamic.process.command_line"], self.safelist
                )
            ):
                continue

            # started and terminated are just uints. Assuming this is MS difference.
            start_time = format_time(
                timeobj=proc_start_time
                + datetime.timedelta(milliseconds=proc.get("started", 0)),
                date_format=LOCAL_FMT_WITH_MS,
            )
            end_time = None
            if proc.get("terminated"):
                end_time = format_time(
                    timeobj=proc_start_time
                    + datetime.timedelta(milliseconds=proc.get("terminated", 0)),
                    date_format=LOCAL_FMT_WITH_MS,
                )

            pid: int = int(proc.get("pid", 0))
            ppid: int = int(proc.get("ppid", 0))

            p_oid = ProcessModel.get_oid(
                {
                    "pid": pid,
                    "ppid": ppid,
                    "image": image,
                    "command_line": command_line,
                }
            )
            self.ontres.update_process(
                objectid=self.ontres.create_objectid(
                    tag=Process.create_objectid_tag(image),
                    ontology_id=p_oid,
                    guid=self.ontres.get_guid_by_pid_and_time(pid, start_time),
                    session=session,
                    time_observed=start_time,
                ),
                pid=pid,
                ppid=ppid,
                image=image,
                command_line=command_line,
                start_time=start_time,
                end_time=end_time,
                pguid=self.ontres.get_guid_by_pid_and_time(ppid, start_time),
            )

    def _process_sigs(
        self, hatching_sigs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process Hatching signatures observed from either static or dynamic analysis reports.

        Args:
            hatching_sigs (List[dict]): list of hatching signatures

        Returns:
            List[Dict[str, Any]]: List of dicts containing the original hatching sig and an
                OntologyResult signature
                [
                    {
                        "hatching_sig": dict,
                        "ontres_sig": assemblyline.odm.models.ontology.results.Signature
                    }
                ]
        """
        if not hatching_sigs:
            return []

        sig_dicts = []

        for hsig in hatching_sigs:
            sig_name = hsig.get("name")
            al4_score = 0
            try:
                al4_score = HATCHING_TO_AL_SCORE_MAP[hsig.get("score", 0)]
            except KeyError:
                log.error(
                    "Invalid Hatching to AL4 score translation. Defaulting to 0. hatching score=%s",
                    hsig.get("score"),
                )

            data = {
                "name": sig_name,
                "type": "CUCKOO",  # This type seems to represent Dynamic.
                # There is no other dynamic type available in the
                #  dynamic_service_helper.py:Signature class. It validates against those types..
            }

            s_tag = SignatureModel.get_tag(data)
            s_oid = SignatureModel.get_oid(data)

            # Get the malware families
            mal_families = extract_malware_families_from_hatching_sig(hsig)

            # Get the ATTACK mappings
            attacks: List[Dict[str, Any]] = []
            for attack_id in hsig.get("ttp", []):
                attack = attack_map.get(attack_id)
                if attack:
                    attacks.append(
                        {
                            "attack_id": attack_id,
                            "pattern": attack.get("name"),
                            "categories": attack.get("categories"),
                        }
                    )
                else:
                    # If this happens, the attack_map may need to be updated.
                    log.warning(
                        "attack_id not found in the attack_map. attack_id: %s",
                        attack_id,
                    )

            ontres_sig: Signature = self.ontres.create_signature(
                objectid=self.ontres.create_objectid(
                    tag=s_tag,
                    ontology_id=s_oid,
                ),
                name=sig_name,
                type="CUCKOO",
                score=al4_score,
                malware_families=mal_families,
                attacks=attacks,
                classification=Classification.UNRESTRICTED,
            )

            sig_dicts.append({"hatching_sig": hsig, "ontres_sig": ontres_sig})

        return sig_dicts

    def _update_ontres_for_dynamic_result_info_section(self, **kwargs) -> None:
        """Update OntologyResults instance based on information section for the dynamic results."""
        if (
            kwargs.get("version") is None
            or kwargs.get("start_time") is None
            or kwargs.get("end_time") is None
            or kwargs.get("platform") is None
        ):
            log.error(
                "Unable to update the OntologyResult. "
                "Missing submission metadata for Hatching sample id: %s",
                self.sample_id,
            )
            return

        # AL Ontology
        ontology_id = SandboxModel.get_oid(
            {
                "sandbox_name": self.ontres.service_name,
                "sandbox_version": kwargs.get("version"),
                "analysis_metadata": {
                    "sample_id": self.sample_id,
                    "start_time": kwargs.get("start_time"),
                    "end_time": kwargs.get("end_time"),
                    "platform": kwargs.get("platform"),
                },
            }
        )

        sandbox = self.ontres.create_sandbox(
            objectid=self.ontres.create_objectid(
                ontology_id=ontology_id,
                tag=self.ontres.service_name,
                session=OntologyResults.create_session(),
            ),
            analysis_metadata=Sandbox.AnalysisMetadata(
                start_time=kwargs.get("start_time"),
                # task_id requires type int.
                #  Would require change in AL4 type since this task id is alpha-num
                # task_id=kwargs.get("task_name"),
                task_id=None,
                end_time=kwargs.get("end_time"),
                routing=None,
                # To be updated later
                machine_metadata=None,
            ),
            sandbox_name=self.ontres.service_name,
            sandbox_version=kwargs.get("version"),
        )

        self.ontres.add_sandbox(sandbox)


def detect_domain_fronting(
    http_traffic: Dict[str, Dict[str, Any]],
) -> Optional[List[Dict[str, str]]]:
    """Determine whether domain-fronting is observed from the http traffic.

    Args:
        http_traffic (Dict[str, Dict[str, Any]]): Processed http traffic of a dynamic triage report.

    Returns:
        Optional[List[Dict[str, str]]]: set or None
            e.g. List[
                {"host": "host-header-domain-val", "uri_domain": "domain-in-uri"},
            ]

    """
    dom_fronting_findings = []
    if http_traffic:
        for v in http_traffic.values():
            uri = v.get("http_request", {}).get("url")
            host_header_dom = v.get("http_request", {}).get("headers", {}).get("host")

            if uri and host_header_dom:
                uri_components = urlparse(uri)
                uri_dom = uri_components.netloc

                if uri_dom != host_header_dom:
                    dom_front = {"host": host_header_dom, "uri_domain": uri_dom}
                    if dom_front not in dom_fronting_findings:
                        dom_fronting_findings.append(dom_front)

    if len(dom_fronting_findings) > 0:
        return dom_fronting_findings

    return None


def determine_classification_heuristic(hatching_score: int) -> Optional[int]:
    """Determine the classification heuristic based on the overall Hatching report's score.

    For reference:

    RF Scoring matrix: https://tria.ge/docs/scoring/

    Default AL4 Scoring
        -1000: safe
        0 - 299: informative
        300 - 699: suspicious
        700 - 999: highly suspicious
        >= 1000: malicious

    Args:
        hatching_score (int): Hatching's score

    Returns:
        Optional[int]: heuristic id or None
    """
    heuristic = None

    if hatching_score == 10:
        heuristic = 2
    elif hatching_score in (8, 9):
        heuristic = 3
    elif hatching_score in (6, 7):
        heuristic = 4
    elif hatching_score in (2, 3, 4, 5):
        heuristic = 5
    elif hatching_score == 1:
        heuristic = 6
    else:
        log.error("Hatching score out of range. Unable to to determine the heuristic.")

    return heuristic


def determine_execution_duration(created_ts: str, completed_ts: str) -> int:
    """Determine the execution duration in seconds.

    Args:
        created_ts (str): date-time str in expected format: %Y-%m-%dT%H:%M:%SZ
        completed_ts (str): date-time str in expected format: %Y-%m-%dT%H:%M:%SZ

    Returns:
        int: total number of seconds or 0 if it fails to parse
    """
    duration = 0
    try:
        created = datetime.datetime.strptime(created_ts, REPORT_TS_FMT)
        completed = datetime.datetime.strptime(completed_ts, REPORT_TS_FMT)

        diff = completed - created
        duration = round(diff.total_seconds())
    except (ValueError, TypeError):
        log.exception("Incorrect date formats passed to determine_execution_duration")

    return duration


def determine_vm_profiles(overview: Dict[str, Any]) -> List[str]:
    """Determine the vm profiles that ran with this submission.

    If invalid input is found, this will simply log an error.

    Args:
        overview (Dict[str, Any]): Hatching API Overview results

    Returns:
        List[str]: vm profile names or empty list
    """
    task_profiles = []
    if overview:
        for task in overview.get("tasks", []):
            if task.get("kind") == "behavioral":
                task_name = task.get("task_name")
                if task_name:
                    task_profiles.append(task_name)

    if len(task_profiles) == 0:
        log.error("Unable to determine the VM profile while processing results.")

    return task_profiles


def extract_malware_families_from_hatching_sig(
    hatching_sig: Dict[str, Any],
) -> List[str]:
    """Get a list of all observed malware families from a hatching sig.

    Args:
        hatching_sig (Dict[str, Any]): Hatching signature

    Returns:
        List[str]: malware families
    """
    families = []
    if hatching_sig:
        for tag in hatching_sig.get("tags", []):
            if tag.startswith("family:"):
                families.append(tag.split(":")[1])

    return families


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten a dictionary consolidating all nested dicts.

    This will also handle dict values that are lists.

    Note: This is just meant to cover the possible results coming back from the Hatching API.

    Args:
        d (Dict[str, Any]):
        parent_key (str, optional): used for nesting prefix Defaults to "".
        sep (str, optional): separator val. Defaults to ".".

    Returns:
        Dict[str, Any]: Flattened dict
    """
    items: List[Any] = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            idx = 1
            newlist = []
            for item in v:
                if isinstance(item, dict):
                    items.extend(flatten_dict(item, new_key, sep=f".{idx}.").items())
                    idx = idx + 1
                else:
                    newlist.append(item)
            if newlist:
                items.append((k, newlist))
        else:
            items.append((new_key, v))
    return dict(items)


def get_ip_port(val: str) -> Tuple[Optional[str], Optional[str]]:
    """Get an IP and Port from the input if they are considered valid.

    Args:
        val (str): expectes IPv4 or IPv4:Port

    Returns:
        Tuple[Optional[str], Optional[str]]: Valid IP (or None), Valid Port (or None)
    """
    ip = None
    port = None

    if val:
        split = val.split(":")

        if is_valid_ip(split[0]):
            ip = split[0].strip()

        if len(split) > 1:
            if is_valid_port(split[1]):
                port = split[1].strip()

    return (ip, port)


def get_network_tag_name(val: Optional[str], is_static_analysis=False) -> Optional[str]:
    """Get the network tag type based on the value. Meant for possible domains or ips.

    Args:
        val (Optional[str]): domain or ip
        is_static_analysis (bool, optional): Whether for static analysis or dynamic analysis.

    Returns:
        Optional[str]: "network.[static|dynamic].[ip|domain]" OR None if invalid input
    """
    network_tag_type = "static"
    if not is_static_analysis:
        network_tag_type = "dynamic"

    tag_name = None

    if val:
        if is_valid_ip(val):
            tag_name = f"network.{network_tag_type}.ip"
        elif is_valid_domain(val):
            tag_name = f"network.{network_tag_type}.domain"

    return tag_name


def is_domain_a_private_rev_dns_lookup(domain: str) -> bool:
    """Determine if the domain specified is a reverse lookup for the private IP space hatching uses.

    Args:
        domain (str): domain

    Returns:
        bool:
    """
    if domain:
        if domain.endswith(".in-addr.arpa"):
            rev_ip_split = domain.split(".")
            if len(rev_ip_split) >= 4:
                rev_ip = f"{rev_ip_split[3]}.{rev_ip_split[2]}.{rev_ip_split[1]}.{rev_ip_split[0]}"

                if re_match(RE_HATCHING_SVC_PRIVATE_IP, rev_ip):
                    return True

    return False


def sanitize_dict(
    val: Dict[str, Any], deep_copy: bool = True
) -> Optional[Dict[str, Any]]:
    """Sanitize the values in a dict recursively.

    This is useful for displaying API results to the user in various ResultSections

    Args:
        val (Dict[str, Any]):
        deep_copy (bool, optional): Whether to deep_copy the dict. Defaults to True.

    Returns:
        Dict[str, Any]: sanitized values for the given dict
    """
    out = None
    if val:
        if deep_copy:
            out = deepcopy(val)
        else:
            out = val

        # now santize the values
        for k, v in out.items():
            if isinstance(v, dict):
                out[k] = sanitize_dict(v, deep_copy=False)
            else:
                out[k] = safe_str(v)

    return out
