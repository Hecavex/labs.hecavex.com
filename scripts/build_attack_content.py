#!/usr/bin/env python3
"""Build the maintained ATT&CK operational and detection publication layers."""

from copy import deepcopy
from datetime import date
import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CATALOGUE_PATH = ROOT / "data" / "attack" / "catalogue" / "enterprise.json"
OFFICIAL_PROCEDURES_PATH = ROOT / "data" / "attack" / "intelligence" / "official-actor-procedures.json"
OPERATIONS_PATH = ROOT / "data" / "attack" / "operations" / "guides.json"
DETECTIONS_PATH = ROOT / "data" / "attack" / "detections" / "packages.json"
EVIDENCE_PATH = ROOT / "data" / "attack" / "intelligence" / "reviewed-evidence.json"
GOVERNANCE_PATH = ROOT / "data" / "attack" / "governance" / "governance.json"


ADDITIONAL_GUIDES = [
    {
        "technique_id": "T1204.001",
        "triggers": ["malicious link", "user clicked", "browser opened", "email URL", "SMS URL", "chat link"],
        "analyst_summary": "Use when a person follows an adversary-controlled link. Message delivery and URL presence are not user execution; preserve click, browser and downstream outcome as separate claims.",
        "minimum_evidence": ["Original message or defensible delivery record", "Normalised URL and redirect chain", "Click or browser-navigation evidence tied to an identity", "Downstream authentication, download or execution outcome"],
        "telemetry": ["Mail, SMS or collaboration platform delivery and click records", "Secure web gateway, DNS and browser navigation history", "Identity, endpoint and proxy events after the navigation"],
        "benign_overlap": ["Legitimate marketing and tracking redirects", "Security-awareness simulations", "Normal external links shared through collaboration tools"],
        "pivots": ["Expand redirects and preserve every hostname", "Scope recipients and clickers separately", "Correlate browser activity with downloads, sign-ins and token events", "Search page templates, certificates and infrastructure reuse"],
        "response": ["Preserve the message and complete redirect chain", "Revoke affected sessions when credential capture is supported", "Block confirmed infrastructure with an expiry and review owner"]
    },
    {
        "technique_id": "T1204.002",
        "triggers": ["malicious file", "user opened", "document execution", "archive opened", "payload launched"],
        "analyst_summary": "Use when a person opens or executes a delivered file. File presence is not execution; require process, document-reader or operating-system evidence of the user-triggered action.",
        "minimum_evidence": ["Original file, hash and collection context", "User and host associated with the file", "Open or execution timestamp", "Process lineage or application evidence showing the action"],
        "telemetry": ["Endpoint file creation and process telemetry", "Document-reader, archive utility and script-interpreter events", "Mail, browser or collaboration delivery metadata"],
        "benign_overlap": ["Expected business documents and installers", "Approved software deployment", "Sandbox or security-team detonation"],
        "pivots": ["Scope the hash, filename and signer across hosts", "Trace the parent process and delivery application", "Inspect child processes, network activity and persistence", "Compare execution with recipients who only received the file"],
        "response": ["Preserve the original file before quarantine", "Contain systems where harmful execution is supported", "Scope all recipients and execution outcomes"]
    },
    {
        "technique_id": "T1059.003",
        "triggers": ["cmd.exe", "command shell", "batch file", "cmd /c", "shell execution"],
        "analyst_summary": "Use when the Windows command shell executes adversary-relevant commands. cmd.exe is common infrastructure; parentage, command content, identity and consequences determine significance.",
        "minimum_evidence": ["Complete command line", "Parent and child process identifiers", "User, host and logon context", "Correlated file, service, registry or network consequences"],
        "telemetry": ["EDR, Sysmon or Security process creation with command lines", "Script, file, registry and service modification events", "DNS, proxy and endpoint network connections"],
        "benign_overlap": ["Logon scripts and software installers", "IT administration and troubleshooting", "Build agents and scheduled maintenance"],
        "pivots": ["Decode quoting, environment variables and chained commands", "Trace the complete ancestry and child tree", "Scope rare commands and parent combinations", "Correlate the same user and logon session across hosts"],
        "response": ["Preserve complete process lineage", "Contain when command intent and consequences support malicious execution", "Turn validated benign chains into narrow regression cases"]
    },
    {
        "technique_id": "T1027",
        "triggers": ["obfuscated", "packed", "encoded", "compressed", "encrypted payload", "high entropy"],
        "analyst_summary": "Use when content is intentionally transformed to hinder inspection or detection. Encoding or compression alone is common; document the transformation, execution context and adversary-relevant purpose.",
        "minimum_evidence": ["Original bytes or content and cryptographic hash", "Observed encoding, packing or transformation", "Process or script responsible for handling the content", "Recovered or partially recovered content where safe"],
        "telemetry": ["Static file and script analysis metadata", "Endpoint process, module and memory telemetry", "Mail, proxy or sandbox content inspection"],
        "benign_overlap": ["Signed software packing and installers", "Minified web content", "Normal archive, encryption and data-protection workflows"],
        "pivots": ["Cluster on packer, decoder and stable code features", "Compare entropy and section metadata with benign software", "Search decoded configuration and infrastructure", "Track the process that writes or executes recovered content"],
        "response": ["Preserve original and decoded artefacts separately", "Do not upload sensitive samples to public services without approval", "Feed stable recovered features into hunting and validation"]
    },
    {
        "technique_id": "T1140",
        "triggers": ["decode", "decompress", "decrypt", "unpack", "base64 decode", "payload extraction"],
        "analyst_summary": "Use when a process decodes or deobfuscates content for subsequent use. The operation is meaningful only when linked to the input, recovered output and follow-on behaviour.",
        "minimum_evidence": ["Input content or identifier", "Decoder process, script or routine", "Recovered output or observable side effect", "Follow-on execution, loading or transfer evidence"],
        "telemetry": ["Script-content and command-line telemetry", "File creation, memory and module-load events", "Process ancestry and consequential network activity"],
        "benign_overlap": ["Installers and update clients", "Application resource extraction", "Administrative encoding and certificate workflows"],
        "pivots": ["Preserve both encoded and decoded hashes", "Identify repeated decoder logic across samples", "Trace output to execution or loading", "Search recovered strings, paths and configuration"],
        "response": ["Acquire original and transformed content", "Contain only when the wider chain supports harmful use", "Add decoder and output examples to regression tests"]
    },
    {
        "technique_id": "T1110.003",
        "triggers": ["password spray", "many accounts", "single password", "authentication failures", "distributed login attempts"],
        "analyst_summary": "Use when one or a small set of passwords is attempted across many accounts. Separate failures, successful authentication and post-authentication activity; source IP alone is not an actor identity.",
        "minimum_evidence": ["Target account and authentication result", "Source address, client and application", "Accurate timestamp and tenant or domain", "Population-level pattern across identities"],
        "telemetry": ["Identity-provider and directory authentication logs", "VPN, SaaS and externally accessible application logs", "Risk, device, session and conditional-access context"],
        "benign_overlap": ["Misconfigured applications using stale credentials", "Password-manager or mobile-client retries", "Authorised identity testing"],
        "pivots": ["Count distinct targets per source and password-independent pattern", "Identify successes after failure clusters", "Correlate device, session and token issuance", "Scope the same targets across applications and addresses"],
        "response": ["Protect successfully accessed identities and sessions", "Apply risk-based controls without locking out the entire target set", "Preserve distributed-source and application context"]
    },
    {
        "technique_id": "T1685",
        "triggers": ["disable antivirus", "stop edr", "tamper protection", "security service stopped", "logging disabled"],
        "analyst_summary": "Use when an adversary disables or modifies security tooling or its configuration. A sensor outage is not automatically tampering; distinguish administrative change, failure and adversary action.",
        "minimum_evidence": ["Security control, service or configuration affected", "Initiating identity and process", "Before-and-after state with timestamp", "Related execution or privilege context"],
        "telemetry": ["Security-product health and tamper events", "Service, process, registry and policy changes", "Administrative audit and endpoint process telemetry"],
        "benign_overlap": ["Approved upgrades and troubleshooting", "Device decommissioning", "Temporary service failure or policy rollout"],
        "pivots": ["Scope the same change across hosts", "Correlate with privilege escalation and tool execution", "Compare against approved change records", "Measure missing telemetry during the impaired interval"],
        "response": ["Restore trustworthy collection before declaring containment", "Isolate systems when deliberate impairment is supported", "Record visibility gaps created by the event"]
    },
    {
        "technique_id": "T1486",
        "triggers": ["ransomware", "files encrypted", "encrypted extension", "mass file modification", "ransom note"],
        "analyst_summary": "Use when data is encrypted to interrupt availability. A ransom note or extension is supporting context; require evidence of the process, affected objects and operational impact.",
        "minimum_evidence": ["Initiating process or account", "Affected files, shares or storage objects", "Rate and timing of modifications", "Recovery, backup and business-impact context"],
        "telemetry": ["Endpoint file and process telemetry", "File-server, storage and cloud audit logs", "Backup, identity and remote-access activity"],
        "benign_overlap": ["Approved encryption and migration", "Backup, compression and archival jobs", "Large developer or media workflows"],
        "pivots": ["Identify the first affected host and account", "Trace lateral access to shares and hypervisors", "Search precursor discovery, credential and recovery-inhibition activity", "Measure unaffected recovery sources"],
        "response": ["Prioritise containment of active encryption and shared access", "Preserve evidence before rebuilding", "Validate recovery paths independently of attacker-controlled systems"]
    }
]


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def candidate_package(guide, technique, catalogue_version, updated):
    technique_id = guide["technique_id"]
    compact_id = technique_id.replace(".", "")
    detections = technique.get("detections", [])
    primary_detection = detections[0] if detections else {
        "id": "ATT&CK CONTEXT",
        "name": f"{technique['name']} detection relationships",
        "url": technique["url"],
    }
    telemetry = guide["telemetry"]
    minimum = guide["minimum_evidence"]
    requirements = []
    requirement_labels = ["Primary behaviour telemetry", "Identity and execution context", "Corroborating outcome telemetry"]
    for index, label in enumerate(requirement_labels):
        requirements.append({
            "source": label,
            "acceptable_sensors": [telemetry[min(index, len(telemetry) - 1)]],
            "required_fields": minimum[index::3] or minimum,
            "quality_checks": [
                "Measure field population and ingestion delay in the intended scope",
                "Confirm timestamps, identities and asset identifiers can be correlated",
                "Document blind spots instead of treating missing data as a negative result",
            ],
        })
    references = [{"title": f"MITRE ATT&CK {technique_id} {technique['name']}", "url": technique["url"]}]
    references.extend({"title": f"MITRE ATT&CK {item['id']} {item['name']}", "url": item["url"]} for item in detections[:3])
    return {
        "id": f"HXD-{technique_id}-CANDIDATE",
        "technique_id": technique_id,
        "title": f"{technique['name']} detection engineering candidate",
        "status": "engineering-candidate",
        "starter": True,
        "scope": {
            "platforms": technique.get("platforms") or ["Environment specific"],
            "behaviour": guide["analyst_summary"],
            "not_covered": [
                "A deployable product query",
                "Proof that the required telemetry exists locally",
                "Validation against the organisation's benign baseline",
            ],
        },
        "hypothesis": guide["analyst_summary"],
        "official_detection": {
            "strategy_id": primary_detection["id"],
            "strategy_name": primary_detection["name"],
            "url": primary_detection["url"],
            "analytic_id": "Local analytic design required",
            "description": "Use the official ATT&CK detection relationship as source context, then translate the behaviour and evidence requirements into the local event model.",
            "platforms": technique.get("platforms", []),
            "log_sources": [
                {"component_id": f"LOCAL-{index + 1:02d}", "component": f"Telemetry requirement {index + 1}", "source": source, "channel": "Map to local schema"}
                for index, source in enumerate(telemetry)
            ],
            "mutable_elements": ["Event schema and field names", "Correlation window", "Environment baseline", "Severity and suppression policy"],
        },
        "data_requirements": requirements,
        "analytic_logic": {
            "required": minimum,
            "elevating_context": guide["pivots"],
            "lowering_context": guide["benign_overlap"],
            "decision": "Require the smallest defensible combination that separates the adversary-relevant claim from documented benign overlap. Keep weaker signals available for hunting.",
        },
        "benign_baseline": guide["benign_overlap"],
        "known_blind_spots": [
            "Required events or join fields are unavailable",
            "A vendor field is assumed equivalent without schema validation",
            "Testing covers only one positive path",
        ],
        "safe_validation_cases": [
            {"id": f"{compact_id}-P01", "class": "positive", "title": "Representative approved behaviour", "procedure": "Use an isolated test system or approved simulation to reproduce the smallest harmless behaviour satisfying the hypothesis.", "expected": ["Required events and fields are present", "The intended relationships survive ingestion", "The result contains enough context for triage"]},
            {"id": f"{compact_id}-N01", "class": "negative", "title": "Documented benign overlap", "procedure": f"Exercise or replay a representative benign case such as: {guide['benign_overlap'][0]}.", "expected": ["Telemetry remains available for hunting", "The analytic does not create unjustified severity", "Any suppression is narrow and documented"]},
            {"id": f"{compact_id}-R01", "class": "resilience", "title": "Missing or degraded context", "procedure": "Repeat validation with one required field or related event unavailable.", "expected": ["The failure mode is visible", "The result does not silently become confirmed coverage", "The gap receives an owner"]},
        ],
        "acceptance_criteria": [
            "Required telemetry and fields are measured in the intended scope",
            "Positive and benign cases behave as expected",
            "An analyst can explain the result",
            "Ownership, review date and response path are recorded",
        ],
        "triage": guide["pivots"],
        "response": guide["response"],
        "lifecycle": {
            "package_owner": "Local detection team",
            "package_status": "engineering candidate",
            "created": updated,
            "last_reviewed": "Not independently reviewed",
            "review_due": "Set during local implementation",
            "attack_version": catalogue_version,
            "technique_version": technique.get("version", "current catalogue"),
            "change_policy": "Review after ATT&CK, telemetry, analytic or validation changes.",
        },
        "references": references,
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh-candidates",
        action="store_true",
        help="regenerate existing engineering candidates while preserving their lifecycle review fields",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    today = date.today().isoformat()
    catalogue = load(CATALOGUE_PATH)
    official_procedures = load(OFFICIAL_PROCEDURES_PATH)
    operations = load(OPERATIONS_PATH)
    evidence = load(EVIDENCE_PATH)
    detections = load(DETECTIONS_PATH)
    governance = load(GOVERNANCE_PATH)

    catalogue_ids = {technique["id"] for technique in catalogue["techniques"]}
    guide_by_id = {guide["technique_id"]: guide for guide in operations["guides"] if guide["technique_id"] in catalogue_ids}
    guide_by_id.update({guide["technique_id"]: guide for guide in ADDITIONAL_GUIDES})
    next_guides = sorted(guide_by_id.values(), key=lambda guide: guide["technique_id"])
    if next_guides != operations.get("guides", []):
        operations["guides"] = next_guides
        operations["updated"] = today
    write(OPERATIONS_PATH, operations)

    technique_by_id = {technique["id"]: technique for technique in catalogue["techniques"]}
    existing_packages = {package["technique_id"]: package for package in detections["packages"]}
    packages = []
    for guide in operations["guides"]:
        technique_id = guide["technique_id"]
        existing = existing_packages.get(technique_id)
        if existing and (not existing.get("starter") or not args.refresh_candidates):
            package = deepcopy(existing)
        else:
            package = candidate_package(guide, technique_by_id[technique_id], catalogue["version"], today)
            if existing:
                package["lifecycle"] = deepcopy(existing.get("lifecycle", package["lifecycle"]))
        if package.get("starter"):
            package["lifecycle"]["last_reviewed"] = "Not independently reviewed"
            package["lifecycle"]["review_due"] = "Set during local implementation"
        packages.append(package)
    next_packages = sorted(packages, key=lambda package: (package.get("starter", False), package["technique_id"]))
    if detections.get("schema_version") != "2.0" or next_packages != detections.get("packages", []):
        detections["schema_version"] = "2.0"
        detections["updated"] = today
        detections["packages"] = next_packages
    write(DETECTIONS_PATH, detections)

    procedure_count = sum(len(group.get("procedures", [])) for group in official_procedures["groups"])
    reviewed_relationships = sum(len(actor.get("evidence", [])) for actor in evidence["actors"])
    previous_governance = deepcopy(governance)
    actor_reviews = [actor.get("review", {}) for actor in evidence["actors"]]
    actor_last_reviewed = max((review["last_reviewed"] for review in actor_reviews), default="Not independently reviewed")
    actor_review_due = min((review["review_due"] for review in actor_reviews), default="Set after review")
    catalogue_tactics = {technique["id"]: set(technique.get("tactics", [])) for technique in catalogue["techniques"]}

    def tactic_mismatch(item):
        return set(item.get("tactics", [])) != catalogue_tactics.get(item.get("technique_id"), set())

    actor_review_gaps = sum(
        tactic_mismatch(item)
        for actor in evidence["actors"]
        for item in actor.get("evidence", [])
    )
    model_review_gaps = sum(
        tactic_mismatch(item)
        for behaviour in evidence.get("behaviours", [])
        for item in behaviour.get("techniques", [])
    )
    evidence_review_gaps = actor_review_gaps + model_review_gaps
    if evidence_review_gaps:
        actor_review_due = "Re-review required"
    reviewed_packages = [package for package in detections["packages"] if not package.get("starter")]
    package_last_reviewed = max((package["lifecycle"]["last_reviewed"] for package in reviewed_packages), default="Not independently reviewed")
    package_review_due = min((package["lifecycle"]["review_due"] for package in reviewed_packages), default="Set after review")

    governance["framework"] = {"name": "MITRE ATT&CK", "domain": "Enterprise", "version": catalogue["version"], "catalogue_generated": catalogue["generated"]}
    governance["curated_layers"] = [
        {"id": "official-catalogue", "label": "Official ATT&CK catalogue", "version": catalogue["version"], "records": len(catalogue["techniques"]), "last_reviewed": "Not independently reviewed", "review_due": "On upstream release", "owner": "MITRE ATT&CK / HECAVEX publication build", "scope": f"{len(catalogue['groups'])} active official groups and {len(catalogue['techniques'])} active Enterprise techniques."},
        {"id": "official-group-procedures", "label": "Official actor procedure relationships", "version": catalogue["version"], "records": procedure_count, "last_reviewed": "Not independently reviewed", "review_due": "On upstream release", "owner": "MITRE ATT&CK / HECAVEX publication build", "scope": "Group-to-technique procedure descriptions and available public citations extracted from the official STIX relationships."},
        {"id": "operational-guides", "label": "Operational guides", "version": "2.0", "records": len(operations["guides"]), "last_reviewed": "Not independently reviewed", "review_due": "Set after review", "owner": "HECAVEX", "scope": "Evidence requirements, telemetry, benign overlap, pivots and response considerations."},
        {"id": "actor-evidence", "label": "HECAVEX-reviewed actor evidence", "version": "1.0", "records": reviewed_relationships, "profiles": len(evidence["actors"]), "review_gaps": evidence_review_gaps, "last_reviewed": actor_last_reviewed, "review_due": actor_review_due, "owner": "HECAVEX / APT Notes", "scope": f"Procedure-level mappings and the phishing model are curated by HECAVEX; {evidence_review_gaps} tactic relationships require re-review against the current catalogue."},
        {"id": "detection-packages", "label": "Detection engineering packages", "version": "2.0", "records": len(detections["packages"]), "validation_ready": len(reviewed_packages), "engineering_candidates": sum(bool(package.get("starter")) for package in detections["packages"]), "last_reviewed": package_last_reviewed, "review_due": package_review_due, "owner": "HECAVEX", "scope": f"Independent lifecycle records: {len(reviewed_packages)} validation-ready; the remaining engineering candidates are unreviewed templates and make no production coverage claim."},
    ]
    if governance != previous_governance:
        governance["updated"] = today
    write(GOVERNANCE_PATH, governance)

    print(f"Built {len(operations['guides'])} guides, {len(detections['packages'])} packages and governance for {procedure_count} official actor procedures.")


if __name__ == "__main__":
    main()
