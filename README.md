Project Description

This project develops and validates a security-by-design architecture for smart irrigation systems operating in critical agricultural environments. Modern irrigation infrastructures increasingly rely on interconnected sensors, gateways, cloud services, weather-information providers, operator dashboards, and automated actuators. While these technologies improve water efficiency and operational effectiveness, they also introduce multiple cybersecurity and operational risks that may lead to unauthorized irrigation actions, service disruption, data manipulation, or unsafe physical behavior.

The project proposes a reference architecture that treats smart irrigation systems as operational technology (OT) environments rather than simple data-collection applications. The architecture introduces explicit trust-boundary enforcement mechanisms, secure telemetry validation, authenticated command execution, provenance-aware data management, operator authorization controls, and feedback-based actuator verification.

To evaluate the proposed approach, a Python-based proof-of-concept implementation was developed that models a complete irrigation control chain comprising field sensors, gateways, weather-information services, operator interfaces, and irrigation actuators. Two alternative controller designs were implemented and compared:

A conventional controller lacking security enforcement mechanisms.
A secure controller implementing the proposed architectural controls.

The secure controller incorporates:

Device authentication and message integrity verification.
Anti-replay protection using sequence numbers, boot identifiers, and freshness constraints.
Local safety-authority enforcement before actuation.
Feedback-aware command execution with automatic transition to safe states when physical confirmation is absent.
Provenance and freshness validation for external information sources.
Multi-factor authentication and contextual authorization for operator overrides.
Secure firmware-update governance through signature and rollout verification.

Experimental validation was performed using six representative attack and failure scenarios, including spoofed telemetry injection, command replay attacks, feedback suppression, compromised operator sessions, stale third-party weather information, and unsafe firmware updates. Results demonstrated a complete separation between insecure and secure implementations. The baseline controller experienced unsafe outcomes in all six scenarios, whereas the secure architecture successfully blocked or safely contained every attack and failure condition.

In addition to security enforcement, the project integrates provenance-aware auditing using PROV-O-compliant records, enabling traceability of accepted telemetry observations and supporting post-incident investigation and regulatory compliance.

The project demonstrates that effective protection of smart irrigation infrastructures depends not only on cryptographic mechanisms but also on systematic enforcement of identity, freshness, authorization, provenance, and physical-process verification across all trust boundaries. The resulting architecture provides a practical foundation for the development of resilient, secure, and trustworthy smart agriculture systems.
