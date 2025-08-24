# OWASP Top 10 for Large Language Model Applications (2025)

The OWASP Top 10 for Large Language Model Applications is a standard awareness document representing a broad consensus about the most critical security risks to LLM applications.

## Table of Contents

1. [LLM01:2025 Prompt Injection](#llm01-prompt-injection)
2. [LLM02:2025 Sensitive Information Disclosure](#llm02-sensitive-information-disclosure)
3. [LLM03:2025 Supply Chain](#llm03-supply-chain)
4. [LLM04:2025 Data and Model Poisoning](#llm04-data-and-model-poisoning)
5. [LLM05:2025 Improper Output Handling](#llm05-improper-output-handling)
6. [LLM06:2025 Excessive Agency](#llm06-excessive-agency)
7. [LLM07:2025 System Prompt Leakage](#llm07-system-prompt-leakage)
8. [LLM08:2025 Vector and Embedding Weaknesses](#llm08-vector-and-embedding-weaknesses)
9. [LLM09:2025 Misinformation](#llm09-misinformation)
10. [LLM10:2025 Unbounded Consumption](#llm10-unbounded-consumption)

---

## <a name="llm01-prompt-injection"></a>LLM01:2025 Prompt Injection

### Description

A **Prompt Injection Vulnerability** occurs when user prompts alter the LLM's behavior or output in unintended ways. These inputs can affect the model even if they are imperceptible to humans. Prompt Injection vulnerabilities exist in how models process prompts, and how input may force the model to incorrectly pass prompt data to other parts of the model, potentially causing them to violate guidelines, generate harmful content, enable unauthorized access, or influence critical decisions.

### Types of Prompt Injection Vulnerabilities

- **Direct Prompt Injections**: Occur when a user's prompt input directly alters the behavior of the model in unintended or unexpected ways.
- **Indirect Prompt Injections**: Occur when an LLM accepts input from external sources, such as websites or files, which contains data that alters the model's behavior.

### Prevention and Mitigation Strategies

- **Constrain model behavior**: Provide specific instructions about the model's role, capabilities, and limitations within the system prompt.
- **Define and validate expected output formats**: Specify clear output formats and use deterministic code to validate adherence.
- **Implement input and output filtering**: Define sensitive categories and construct rules for identifying and handling such content.
- **Enforce privilege control and least privilege access**: Restrict the model's access privileges to the minimum necessary for its intended operations.
- **Require human approval for high-risk actions**: Implement human-in-the-loop controls for privileged operations.

---

## <a name="llm02-sensitive-information-disclosure"></a>LLM02:2025 Sensitive Information Disclosure

### Description

This vulnerability involves the risk of LLMs exposing sensitive data, proprietary algorithms, or confidential details through their output. This can result in unauthorized data access, privacy violations, and intellectual property breaches. Sensitive information can include PII, financial details, health records, confidential business data, security credentials, and legal documents.

### Common Examples of Vulnerability

- **PII Leakage**: Personal identifiable information may be disclosed during interactions with the LLM.
- **Proprietary Algorithm Exposure**: Poorly configured model outputs can reveal proprietary algorithms or data.
- **Sensitive Business Data Disclosure**: Generated responses might inadvertently include confidential business information.

### Prevention and Mitigation Strategies

- **Integrate Data Sanitization Techniques**: Implement data sanitization to prevent user data from entering the training model.
- **Enforce Strict Access Controls**: Limit access to sensitive data based on the principle of least privilege.
- **Utilize Federated Learning**: Train models using decentralized data to minimize the need for centralized data collection.
- **Educate Users on Safe LLM Usage**: Provide guidance on avoiding the input of sensitive information.

---

## <a name="llm03-supply-chain"></a>LLM03:2025 Supply Chain

### Description

LLM supply chains are susceptible to various vulnerabilities that can affect the integrity of training data, models, and deployment platforms. These risks can result in biased outputs, security breaches, or system failures. Unlike traditional software vulnerabilities, ML risks also extend to third-party pre-trained models and data, which can be manipulated through tampering or poisoning attacks.

### Common Examples of Risks

- **Traditional Third-party Package Vulnerabilities**: Outdated or deprecated components that attackers can exploit.
- **Vulnerable Pre-Trained Model**: Models containing hidden biases, backdoors, or other malicious features.
- **Weak Model Provenance**: Lack of strong provenance assurances in published models.

### Prevention and Mitigation Strategies

- **Carefully vet data sources and suppliers**: Only use trusted suppliers and regularly review their security posture.
- **Apply comprehensive AI Red Teaming and Evaluations**: Evaluate third-party models, especially for your specific use cases.
- **Maintain an up-to-date inventory of components**: Use a Software Bill of Materials (SBOM) to prevent tampering.

---

## <a name="llm04-data-and-model-poisoning"></a>LLM04:2025 Data and Model Poisoning

### Description

Data poisoning occurs when pre-training, fine-tuning, or embedding data is manipulated to introduce vulnerabilities, backdoors, or biases. This manipulation can compromise model security, performance, or ethical behavior, leading to harmful outputs or impaired capabilities. Data poisoning can target different stages of the LLM lifecycle and is considered an integrity attack.

### Common Examples of Vulnerability

- **Biased Outputs**: Malicious actors introduce harmful data during training, leading to biased outputs.
- **Compromised Output Quality**: Attackers inject harmful content directly into the training process.
- **Unverified Training Data**: Increases the risk of biased or erroneous outputs.

### Prevention and Mitigation Strategies

- **Track data origins and transformations**: Use tools like OWASP CycloneDX or ML-BOM to verify data legitimacy.
- **Implement strict sandboxing**: Limit model exposure to unverified data sources.
- **Test model robustness**: Use red team campaigns and adversarial techniques to minimize the impact of data perturbations.

---

## <a name="llm05-improper-output-handling"></a>LLM05:2025 Improper Output Handling

### Description

Improper Output Handling refers to insufficient validation, sanitization, and handling of the outputs generated by LLMs before they are passed to other components. Since LLM-generated content can be controlled by prompt input, this is similar to providing users indirect access to additional functionality. Successful exploitation can result in XSS, CSRF, SSRF, privilege escalation, or remote code execution.

### Common Examples of Vulnerability

- **Remote Code Execution**: LLM output is entered directly into a system shell or similar function.
- **Cross-Site Scripting (XSS)**: JavaScript or Markdown generated by the LLM is returned to a user and interpreted by the browser.
- **SQL Injection**: LLM-generated SQL queries are executed without proper parameterization.

### Prevention and Mitigation Strategies

- **Treat the model as any other user**: Adopt a zero-trust approach and apply proper input validation.
- **Encode model output**: Mitigate undesired code execution by JavaScript or Markdown.
- **Use parameterized queries**: Or prepared statements for all database operations involving LLM output.

---

## <a name="llm06-excessive-agency"></a>LLM06:2025 Excessive Agency

### Description

Excessive Agency is the vulnerability that enables damaging actions to be performed in response to unexpected, ambiguous, or manipulated outputs from an LLM. The root cause is typically excessive functionality, permissions, or autonomy. This can lead to a broad range of impacts across confidentiality, integrity, and availability.

### Common Examples of Risks

- **Excessive Functionality**: An LLM agent has access to extensions with unneeded functions.
- **Excessive Permissions**: An LLM extension has unnecessary permissions on downstream systems.
- **Excessive Autonomy**: An LLM-based application fails to independently verify and approve high-impact actions.

### Prevention and Mitigation Strategies

- **Minimize extensions**: Limit the extensions that LLM agents can call to the minimum necessary.
- **Minimize extension permissions**: Limit the permissions that LLM extensions are granted to other systems.
- **Require user approval**: Utilize human-in-the-loop control for high-impact actions.

---

## <a name="llm07-system-prompt-leakage"></a>LLM07:2025 System Prompt Leakage

### Description

The system prompt leakage vulnerability refers to the risk that system prompts or instructions used to steer the model's behavior can contain sensitive information that was not intended to be discovered. When discovered, this information can be used to facilitate other attacks. The system prompt should not be considered a secret or used as a security control.

### Common Examples of Risk

- **Exposure of Sensitive Functionality**: The system prompt may reveal sensitive system architecture, API keys, or database credentials.
- **Exposure of Internal Rules**: The system prompt reveals information on internal decision-making processes.
- **Disclosure of Permissions and User Roles**: The system prompt could reveal internal role structures or permission levels.

### Prevention and Mitigation Strategies

- **Separate Sensitive Data from System Prompts**: Avoid embedding sensitive information directly in system prompts.
- **Avoid Reliance on System Prompts for Strict Behavior Control**: Rely on external systems to ensure behavior.
- **Implement Guardrails**: Use a system of guardrails outside of the LLM itself.

---

## <a name="llm08-vector-and-embedding-weaknesses"></a>LLM08:2025 Vector and Embedding Weaknesses

### Description

Vectors and embeddings vulnerabilities present significant security risks in systems utilizing Retrieval Augmented Generation (RAG). Weaknesses in how vectors and embeddings are generated, stored, or retrieved can be exploited to inject harmful content, manipulate model outputs, or access sensitive information.

### Common Examples of Risks

- **Unauthorized Access & Data Leakage**: Inadequate access controls can lead to unauthorized access to embeddings.
- **Embedding Inversion Attacks**: Attackers can invert embeddings to recover source information.
- **Data Poisoning Attacks**: Data poisoning can occur intentionally or unintentionally, leading to manipulated model outputs.

### Prevention and Mitigation Strategies

- **Implement fine-grained access controls**: And permission-aware vector and embedding stores.
- **Implement robust data validation pipelines**: For knowledge sources.
- **Maintain detailed immutable logs**: Of retrieval activities to detect and respond to suspicious behavior.

---

## <a name="llm09-misinformation"></a>LLM09:2025 Misinformation

### Description

Misinformation occurs when LLMs produce false or misleading information that appears credible. This can lead to security breaches, reputational damage, and legal liability. A major cause is hallucination, where the LLM generates fabricated content. Overreliance on LLM-generated content exacerbates the impact of misinformation.

### Common Examples of Risk

- **Factual Inaccuracies**: The model produces incorrect statements, leading to decisions based on false information.
- **Unsupported Claims**: The model generates baseless assertions, harmful in sensitive contexts.
- **Unsafe Code Generation**: The model suggests insecure or non-existent code libraries.

### Prevention and Mitigation Strategies

- **Use Retrieval-Augmented Generation (RAG)**: To enhance the reliability of model outputs.
- **Encourage cross-verification and human oversight**: Especially for critical information.
- **Communicate risks and limitations to users**: Including the potential for misinformation.

---

## <a name="llm10-unbounded-consumption"></a>LLM10:2025 Unbounded Consumption

### Description

Unbounded Consumption occurs when an LLM application allows users to conduct excessive and uncontrolled inferences, leading to denial of service (DoS), economic losses, model theft, and service degradation. The high computational demands of LLMs make them vulnerable to resource exploitation.

### Common Examples of Vulnerability

- **Variable-Length Input Flood**: Attackers overload the LLM with numerous inputs of varying lengths.
- **Denial of Wallet (DoW)**: Attackers exploit the cost-per-use model of cloud-based AI services.
- **Model Extraction via API**: Attackers query the model API to collect outputs and replicate a partial model.

### Prevention and Mitigation Strategies

- **Implement strict input validation**: To ensure inputs do not exceed reasonable size limits.
- **Apply rate limiting and user quotas**: To restrict the number of requests a single source can make.
- **Monitor and manage resource allocation dynamically**: To prevent excessive resource consumption.

---

## Relevance to Sanguine Scribe

This document serves as a security reference for the Sanguine Scribe project, ensuring that our LLM-based character AI platform follows industry best practices for security. Special attention should be paid to:

- **Prompt Injection (LLM01)**: Critical for character AI systems where users interact with multiple character personalities
- **Sensitive Information Disclosure (LLM02)**: Important for protecting user conversations and character data
- **System Prompt Leakage (LLM07)**: Essential for protecting character personality prompts and system instructions
- **Vector and Embedding Weaknesses (LLM08)**: Crucial for our RAG-based context system and lorebook functionality
- **Unbounded Consumption (LLM10)**: Important for managing costs and preventing DoS attacks in our streaming chat system

Regular security reviews should reference this document to ensure Sanguine Scribe maintains robust defenses against LLM-specific vulnerabilities.