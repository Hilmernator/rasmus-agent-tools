# Choosing standards, chapters and level

Choose from the profile, not from the repository's language or framework.

## Standards

| The product | Select |
| --- | --- |
| Has a network interface: web app, HTTP, gRPC or WebSocket API, a local server other devices can reach | `asvs` |
| Is a library, CLI or desktop app without a network service | `asvs`, then rule out the chapters that need a server (usually V3, V4, V6 to V10, V12, V17). Note in the profile that ASVS is written for web applications. |
| Calls an LLM or other ML model, embeds text, runs agents or uses MCP | `aisvs` at the same level as `asvs`. AISVS assumes the application is also verified against ASVS. |
| Is a native or cross-platform mobile app | `masvs` for the app; `asvs` as well when its backend is in the repository |
| Is built with AI coding agents in CI, or ships an AI review bot | `aisvs-ac` (AISVS Appendix C), only when the user asks. It is mostly process, so many rows become `unverifiable`. |

The bundled catalogs are the full text of ASVS 5.0.0 (345 requirements), AISVS 1.01 (191
requirements, and 68 in Appendix C as `aisvs-ac`) and MASVS 2.1.0 (24 controls). MASVS 2 assigns no levels,
so every MASVS control is selected at any level. The pinned revisions are in each catalog file.

Not bundled, so name them in the profile under obligations when they apply and do not assess
them from memory: CIS and cloud provider benchmarks, PCI DSS, ISO 27001, SOC 2, GDPR and other
law, and any customer contract.

## Level

| Level | Use for |
| --- | --- |
| 1 | Personal tools and prototypes without sensitive data. A good first pass at any size. |
| 2 | Anything other people use in production, anything with personal data, payments, business data, or authentication exposed to the internet. The default when unsure. |
| 3 | High-value targets: health, finance, critical infrastructure, high-assurance products. |

Use the same level for ASVS and AISVS. Record the assumption behind the level in the profile.

## ASVS 5.0 chapters

| Chapter | Applies when |
| --- | --- |
| V1 Encoding and Sanitization | Untrusted input reaches an interpreter: HTML, SQL, shell, file paths, templates, regular expressions |
| V2 Validation and Business Logic | Always |
| V3 Web Frontend Security | A browser renders the product's UI |
| V4 API and Web Service | It serves HTTP APIs, GraphQL or WebSockets |
| V5 File Handling | It accepts uploads, serves downloads, builds paths from input or extracts archives |
| V6 Authentication | Anyone or anything authenticates, and for every networked service: no authentication is a gap |
| V7 Session Management | It keeps sessions, cookies or session tokens |
| V8 Authorization | Several users, roles or resource owners exist, and for every networked service |
| V9 Self-contained Tokens | It issues or accepts JWTs, PASETOs or signed cookies |
| V10 OAuth and OIDC | It is an OAuth client, resource server or authorization server |
| V11 Cryptography | It encrypts, signs, hashes passwords or makes random tokens |
| V12 Secure Communication | It sends or receives network traffic. TLS at a proxy outside the repository is `unverifiable`. |
| V13 Configuration | Always |
| V14 Data Protection | It stores or handles sensitive data |
| V15 Secure Coding and Architecture | Always |
| V16 Security Logging and Error Handling | Always |
| V17 WebRTC | It uses WebRTC |

## AISVS 1.01 chapters

| Chapter | Applies when |
| --- | --- |
| C1 Training Data | It trains or fine-tunes models or builds datasets |
| C2 Input Validation | Untrusted content reaches a prompt: user text, documents, web pages, email, tool results |
| C3 Model Lifecycle | It deploys, versions or fine-tunes its own models. With a hosted model only, assess row by row; many rows will be `not-applicable`. |
| C4 Infrastructure | It hosts inference, runs model-generated code, or runs AI workloads in containers or sandboxes |
| C5 Access Control and Identity | Always when AI features exist |
| C6 Supply Chain | It downloads models, weights, datasets or adapters |
| C7 Model Behavior and Output | Model output is shown to people or used by code: almost always |
| C8 Memory, Embeddings and Vector DB | It uses RAG, embeddings, a vector store or long-term memory |
| C9 Orchestration and Agentic Action | The model chooses tools or actions, runs in loops, or delegates to other agents |
| C10 MCP Security | It is an MCP client or server |
| C11 Adversarial Robustness | It owns or tunes a model; with a hosted model only, assess row by row |
| C12 Monitoring and Logging | Always when AI features exist |

## Risk lists for tagging gaps

These lists name risks and are not requirements. Use their IDs in `gaps.md` so readers can link
a gap to a familiar risk.

- OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.
- OWASP Top 10 for Agentic Applications 2026: ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.
- OWASP API Security Top 10 2023: API1 Broken Object Level Authorization, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 Server Side Request Forgery, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs.
