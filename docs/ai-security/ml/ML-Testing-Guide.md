# **Adversarial Machine Learning: Red Team Field Guide**

A technical guide to the taxonomy, theory, and execution of attacks against Machine Learning systems. This page moves beyond "bugs" to explore how mathematical vulnerabilities in decision boundaries can be exploited.

The Adversarial Mindset  
Unlike traditional software vulnerabilities (buffer overflows, SQLi), adversarial ML attacks exploit the probabilistic nature of learning. An adversarial example is not a "bug" in the code; it is a feature of high-dimensional spaces where models act unpredictably.

## **1\. Attack Taxonomy**

Attacks on ML systems are generally categorized by the attacker's goal and their access level (White Box vs. Black Box).

### **A. Evasion (Adversarial Examples)**

The "Optical Illusion" for AI.  
The attacker modifies the input data (e.g., adding invisible noise to an image) to force the model into a misclassification. This occurs during the Inference phase.

* **White Box:** Attacker has access to model weights and gradients (e.g., Open Source models).  
* **Black Box:** Attacker can only query the API and see the output (e.g., SaaS AI).

### **B. Poisoning (Supply Chain)**

The "Sleeper Agent".  
The attacker corrupts the training data or the model itself during the Training/Fine-Tuning phase.

* **Availability Attacks:** Degrade overall model accuracy (Denial of Service).  
* **Integrity Attacks (Backdoors):** The model behaves normally for 99% of inputs but triggers a specific malicious behavior when it sees a "trigger" (e.g., a post-it note on a stop sign).

### **C. Model Extraction & Inversion**

**The "Intellectual Property Theft".**

* **Model Stealing:** Replicating a proprietary model by querying it repeatedly and training a surrogate model on the outputs.  
* **Inversion/Membership Inference:** Reconstructing sensitive training data (e.g., patient records) by analyzing the model's confidence scores.

## **2\. Theoretical Concepts**

### **The Gradient**

In White Box attacks, the attacker calculates the **Gradient** of the loss function with respect to the *input* (not the weights).

* **Standard Training:** "Adjust weights to minimize error."  
* **Adversarial Attack:** "Adjust input to maximize error."

### **Perturbation Constraints**

Attacks must often remain undetectable to humans. This is mathematically defined by **L-norms**:

* **L0:** Change only a few specific pixels (e.g., one-pixel attack).  
* **L2:** Change all pixels slightly (standard Euclidean distance).  
* **L∞ (Infinity):** Change all pixels by a maximum small amount (e.g., shifting RGB values by \+/- 1).

### **Transferability**

A critical risk factor: **Adversarial examples often transfer between models.** An attack generated against a local ResNet-50 model (the "Substitute") will often fool a completely different proprietary model (the "Target") because they learn similar decision boundaries.

## **3\. Industry Standard Frameworks**

Do not write custom attack scripts from scratch. Use verified libraries that implement state-of-the-art papers correctly.

### **Adversarial Robustness Toolbox (ART)**

Maintained by the Linux Foundation, ART is the "Swiss Army Knife" of ML Security. It supports TensorFlow, PyTorch, Keras, and Scikit-learn.

**Installation:**

```bash
pip install adversarial-robustness-toolbox
```

**White Box Attack Workflow (FGSM):**

The Fast Gradient Sign Method (FGSM) takes one large step in the direction of the gradient.

```python
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import PyTorchClassifier

# 1. Wrap your PyTorch/TF model in an ART classifier
# This normalizes inputs and handles gradient access
classifier = PyTorchClassifier(
    model=model,
    loss=criterion,
    input_shape=(3, 224, 224),
    nb_classes=10
)

# 2. Initialize the attack
# epsilon: The "strength" of the attack (how much noise to add)
attack = FastGradientMethod(estimator=classifier, eps=0.1)

# 3. Generate adversarial examples
x_test_adv = attack.generate(x=x_test)
```

### **Microsoft Counterfit**

Counterfit is a command-line automation tool designed for Red Teams. It abstracts the coding away, allowing pentesters to run attacks similar to Metasploit. It wraps ART and other libraries.

**Installation:**

```bash
# Clone the repo from Azure's GitHub
git clone https://github.com/Azure/counterfit.git
cd counterfit
python3 -m pip install -r requirements.txt
python3 counterfit.py
```

**Assessment Workflow:**

```bash
> interact target_name
> load cfa_target
> set_params --url http://127.0.0.1:5000/predict
> scan
> list attacks
> use hop_skip_jump
> run
```

### **Foolbox**

A library specifically optimized for benchmarking computer vision robustness. It is extremely fast and effective for comparing model defenses.

```python
import foolbox as fb

fmodel = fb.PyTorchModel(model, bounds=(0, 1))

# L-infinity Projected Gradient Descent (PGD) Attack
# PGD is considered the universal "standard" for robustness
attack = fb.attacks.LinfPGD()
_, advs, success = attack(fmodel, images, labels, epsilons=[0.03])
```

## **4\. Deep Dive: Model Extraction Methodology**

If you have no access to the model weights (Black Box), your primary goal is often **Model Extraction** (creating a copy).

**The Knockoff Attack:**

1. **Select a Victim:** An API endpoint (e.g., api.insurance.com/risk-score).  
2. **Generate Proxy Data:** Create a dataset of random or semi-realistic inputs.  
3. **Query the Victim:** Send inputs to the API and record the labels/confidence scores.  
4. **Train Surrogate:** Train a local model (e.g., ResNet) using your inputs and the Victim's labels.  
5. **Result:** You now possess a "stolen" version of the model that you can analyze offline to find Evasion vulnerabilities.

## **5\. Defense: Adversarial Training**

The only mathematically proven defense against evasion attacks (so far) is **Adversarial Training**.

**Concept:**

Instead of training on just clean images, the training loop generates adversarial examples on the fly and forces the model to label them correctly.

**ART Implementation:**

```python
from art.defences.trainer import AdversarialTrainer

# Train the model on adversarial examples generated by PGD
trainer = AdversarialTrainer(classifier, attacks=pgd_attack, ratio=0.5)
trainer.fit(x_train, y_train, nb_epochs=50)
```

**Warning:** Adversarial Training often reduces accuracy on *clean* data. Security is a trade-off with performance.

## **6\. Compliance & Risk Assessment: The Consultant's Playbook**

Clients often request an "AI Pentest" because it sounds familiar, but for AI systems, a traditional pentest (finding bugs in code) is insufficient. As a consultant, your job is to pivot the engagement from "breaking the model" to "assessing the system's risk."

### **The "Pentest" Misconception**

In network security, a vulnerability (e.g., unpatched SMB) is binary: it exists or it doesn't.  
In AI security, vulnerabilities are inherent. Every ML model can be tricked with enough perturbation.

* **Client Ask:** "Can you pentest our Fraud Detection Model?"  
* **Wrong Approach:** Spending 40 hours generating noise to bypass the model once. (This proves nothing; all models have an error rate).  
* **Right Approach:** "We will assess the *impact* of a bypass and validate your detection capabilities."

### **The Pivot: From "Break It" to "Risk It"**

When a client asks for a pentest, steer them toward a **Threat Model-First** approach. Use Adversarial Testing only to *validate* the high-risk paths identified in the threat model.

**The Narrative Pivot:**

"I can definitely bypass your model; that is mathematically guaranteed. The real question is: *If* I bypass it, what happens? Does the system fail open? Is there a human in the loop? Let's build a Threat Model to identify which bypasses actually matter to your business."

### **Phase 1: Threat Modeling (The Core Value)**

Before running a single script, map the system using industry frameworks.

* **STRIDE with ATLAS/MAESTRO context:** Apply Microsoft's STRIDE framework with AI-specific threat scenarios mapped to MITRE ATLAS tactics.
  * **S**poofing: Impersonating a biometric sensor.
  * **T**ampering: Poisoning the training data pipeline.
  * **R**epudiation: Denying actions taken by an AI agent.
  * **I**nformation Disclosure: Model Inversion (extracting private data).
  * **D**enial of Service: Sponge attacks (high-latency inputs).
  * **E**levation of Privilege: Prompt injection to gain admin rights.
* **MITRE ATLAS:** The "ATT&CK" framework for AI. Use this to map specific threats to real-world tactics.

### **Phase 2: Adversarial Testing as Evidence (POC)**

Once the Threat Model identifies a high risk (e.g., "If the Fraud Model is bypassed, we lose $1M/day"), *then* you use the tools in Section 3 (ART/Counterfit).

**The Goal of Testing is NOT to find bugs, but to:**

1. **Validate Assumptions:** "You claimed the model is robust to random noise. We proved it fails at epsilon=0.03."  
2. **Measure Degradation:** "Under attack, your accuracy drops from 99% to 12%."  
3. **Test Guardrails:** "The model failed, but did your secondary anomaly detector catch the high-frequency noise?"

### **Phase 3: The Deliverables (Maturity & Governance)**

The true value of the engagement is shifting the client from "Unaware" to "Managed" maturity. The output is not just a PDF with screenshots of terminal windows; it is a governance foundation.

* Robust Risk & Threat Registers:  
  We translate technical findings into a formal Risk Register. This documents specific threats (e.g., "Model Inversion via API") alongside their business impact, likelihood, and current control status. Unlike a pentest report which is "fixed in time," this register is designed to be maintained by the internal GRC team.  
* The "Living" Matrix:  
  We deliver a Traceability Matrix mapping Business Process \-\> AI Component \-\> ATLAS Tactic \-\> Mitigation. This becomes a living document that the organization uses to track risk reduction over time as models are retrained or guardrails are updated.  
* Auditor Assurance:  
  For external auditors (ISO 42001, EU AI Act), possessing a maintained, empirically validated risk register is a significant indicator of organizational maturity. It proves that security is a continuous process, not a one-time checklist, directly satisfying "Continuous Monitoring" requirements.

### **Regulatory Drivers (The "Why")**

Use these regulations to justify the comprehensive assessment budget.

#### **EU AI Act**

This is the strongest lever. It categorizes AI by risk.

* **High-Risk Systems (Annex III):** Credit scoring, HR tools, Biometrics, Critical Infrastructure.  
* **Requirement (Article 15):** You must prove **Accuracy, Robustness, and Cybersecurity**.  
* **Consultant's Note:** A simple pentest report ("we found 3 bugs") is **not compliant**. The client needs a *Risk Assessment Technical File* showing they have anticipated errors and attacks and have mitigations in place.

#### **NIST AI Risk Management Framework (AI RMF)**

For US/Global clients, map your findings to the NIST functions:

* **Map:** Did we identify the context of use? (Threat Modeling)  
* **Measure:** Did we quantitatively test resilience? (Adversarial Testing with ART)  
* **Manage:** Do we have controls for the risks found? (Mitigation)