---
name: snmp-enumeration
description: "SNMP enumeration is querying a target's SNMP service (typically UDP 161) with its documented default community string to pull back device information -- system description, running processes, interface tables, and sometimes routing detail -- that the protocol's older versions authenticate with nothing more than a plaintext string very often left at its factory default. Use this skill once a port scan has flagged SNMP as open or likely open on an in-scope host, to decide whether the exposed service needs a closer, in-scope look. Triggers: 'snmp enumeration', 'snmp community string', 'snmp public private', 'network device recon', 'snmp walk'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["infra-network"]
tags: ["snmp", "community-string", "network-device", "nmap", "network"]
---

# SNMP Enumeration

## What it is
SNMP (Simple Network Management Protocol) lets network devices -- routers, switches, printers, appliances -- be queried for status and configuration information. Its older, still widely deployed versions authenticate a request with a plaintext "community string" rather than a real credential, and the factory-default strings for that string are public knowledge, meaning a device left on its default is effectively unauthenticated. Enumeration means checking whether the default string works and, if it does, what device information it hands back.

## Where it shows up
Network appliances and infrastructure devices are the classic case: routers, switches, printers, and management interfaces that were configured once, at rollout, and never revisited for a setting most administrators do not think of as a credential at all. A device answering to a documented default string will typically disclose enough system detail to be a useful lead on its own, well before anything resembling exploitation happens.

## How Boundhound approaches it
SNMP's default port, UDP 161, sits outside the TCP connect scan Boundhound's bounded `/recon` nmap invocation runs by default; confirming SNMP requires a UDP-aware probe, which can be requested through the same `bh-exec`-mediated nmap call, under the same scope check and non-aggressive timing constraints as every other invocation -- it is a different probe type, not a different tool or a looser safety posture. Boundhound has no dedicated bounded tool for walking an SNMP tree or pulling its information once the service is confirmed. Checking a documented default community string against a confirmed, in-scope device is the same kind of small, fixed-list check described in this library's default-credentials playbook, not an open-ended guessing exercise, and today that check is either a manual, operator-directed step or something a dedicated tool would perform once brought into the system through `bh-exec` with its own scope and safety review.

## Scope & safety
Only a host already confirmed in `scope.yaml` is probed at all, and any community-string check is limited to the small set of publicly documented defaults for that class of device -- never a broader wordlist-style sweep. Boundhound's safety layer's request-rate limits and denial of anything resembling a flood apply here exactly as they do to every other active check.

## Remediation
Change every SNMP community string away from its factory default, disable SNMP entirely on devices that do not need it reachable from the network in question, and prefer a version of the protocol that supports real authentication and encryption over the legacy plaintext-string model.
