# Adversarial Machine Learning: Testing and Defense Tools

Practical tools and techniques for testing ML model robustness, detecting adversarial attacks, and implementing defenses against adversarial examples in production systems.

## Adversarial Testing Frameworks

### Adversarial Robustness Toolbox (ART)

```bash
# Install IBM's Adversarial Robustness Toolbox
pip install adversarial-robustness-toolbox

# Basic adversarial attack testing
python -c "
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import PyTorchClassifier
import torch

# Create ART classifier wrapper
model = torch.load('model.pth')
classifier = PyTorchClassifier(model=model, loss=torch.nn.CrossEntropyLoss(),
                              input_shape=(3, 224, 224), nb_classes=10)

# FGSM attack
attack = FastGradientMethod(estimator=classifier, eps=0.1)
x_test_adv = attack.generate(x=x_test)
"

# Robustness evaluation
python art_evaluate.py --model resnet50.pth --attack fgsm --epsilon 0.1 --dataset cifar10

# Generate adversarial examples for testing
python art_generate.py --attack pgd --model model.pth --output adversarial_samples.npy

# Defense evaluation
python art_defend.py --defense adversarial_training --model model.pth --test-set test_data.npy
```

### Foolbox - Model Robustness Testing

```bash
# Install Foolbox
pip install foolbox

# Test model robustness
python -c "
import foolbox as fb
import torch

model = torch.load('model.pth')
fmodel = fb.PyTorchModel(model, bounds=(0, 1))

# L-infinity PGD attack
attack = fb.attacks.LinfPGD()
epsilons = [0.0, 0.001, 0.01, 0.03, 0.1, 0.3, 0.5, 1.0]
_, advs, success = attack(fmodel, images, labels, epsilons=epsilons)
"

# Batch robustness testing
foolbox-test --model model.pth --dataset cifar10 --attacks fgsm,pgd,cw --output results.json

# Model comparison
foolbox-compare --models model1.pth,model2.pth --attacks all --output comparison.html
```

### CleverHans Security Testing

```bash
# Install CleverHans
pip install cleverhans

# Adversarial training
python cleverhans_train.py --model resnet --dataset cifar10 --attack pgd --epochs 10

# Security evaluation
python cleverhans_eval.py --model model.pth --attack-config attacks.yaml

# Generate test cases
python cleverhans_generate.py --attack fgsm --epsilon 0.1 --output test_cases/
```

## Model Robustness Assessment

### AutoAttack - Comprehensive Evaluation

```bash
# Install AutoAttack
pip install autoattack

# Comprehensive robustness evaluation
python -c "
from autoattack import AutoAttack
import torch

model = torch.load('model.pth')
adversary = AutoAttack(model, norm='Linf', eps=8/255, version='standard')

# Run all attacks
x_adv = adversary.run_standard_evaluation(x_test, y_test, bs=250)
"

# Adaptive attack evaluation
python autoattack_eval.py --model model.pth --dataset cifar10 --threat-model Linf --epsilon 0.031

# Custom attack configuration
python autoattack_custom.py --config custom_attacks.yaml --model model.pth
```

### RobustBench - Standardized Evaluation

```bash
# Install RobustBench
pip install git+https://github.com/RobustBench/robustbench.git

# Evaluate against standard benchmarks
python -c "
from robustbench import benchmark
from robustbench.utils import load_model

model = load_model('Standard_R50', dataset='cifar10', threat_model='Linf')
clean_acc, robust_acc = benchmark(model, dataset='cifar10', threat_model='Linf')
print(f'Clean accuracy: {clean_acc:.2%}')
print(f'Robust accuracy: {robust_acc:.2%}')
"

# Model leaderboard comparison
robustbench-eval --model-name Custom_Model --dataset cifar10 --threat-model Linf --eps 0.031

# Submit results to leaderboard
robustbench-submit --model model.pth --results results.json --dataset cifar10
```

## Real-Time Defense Systems

### Adversarial Example Detection

```bash
# Deploy adversarial detection service
docker run -d --name adv-detector \
  -p 8080:8080 \
  -v /models:/app/models \
  adversarial-detector:latest

# Configure detection thresholds
curl -X POST http://localhost:8080/config \
  -H "Content-Type: application/json" \
  -d '{
    "detection_threshold": 0.7,
    "statistical_tests": ["gradcam", "local_outlier", "mahalanobis"],
    "preprocessing": ["jpeg_compression", "gaussian_blur"]
  }'

# Real-time detection API
curl -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -F "image=@suspicious_image.jpg"

# Batch processing
curl -X POST http://localhost:8080/batch_detect \
  -F "images=@image_batch.zip" \
  -F "config=@detection_config.json"
```

### Input Preprocessing Pipeline

```bash
# Install preprocessing tools
pip install torchvision pillow opencv-python

# JPEG compression defense
python preprocess_defense.py --method jpeg_compression --quality 75 --input images/ --output processed/

# Gaussian noise injection
python preprocess_defense.py --method gaussian_noise --std 0.1 --input images/ --output processed/

# Quantization defense
python preprocess_defense.py --method quantization --bits 4 --input images/ --output processed/

# Feature squeezing
python preprocess_defense.py --method feature_squeezing --depth_reduction 4 --spatial_smoothing 2
```

## Model Training and Hardening

### Adversarial Training Implementation

```bash
# Install adversarial training tools
pip install torch torchvision advertorch

# Standard adversarial training
python adversarial_train.py \
  --model resnet18 \
  --dataset cifar10 \
  --attack pgd \
  --epsilon 0.031 \
  --alpha 0.007 \
  --steps 10 \
  --epochs 100

# TRADES training (TRadeoff-inspired Adversarial DEfense)
python trades_train.py \
  --model wide_resnet \
  --dataset cifar10 \
  --lambda 6.0 \
  --epsilon 0.031 \
  --step-size 0.007

# MART training (Misclassification Aware adveRsarial Training)
python mart_train.py \
  --model resnet50 \
  --dataset imagenet \
  --beta 5.0 \
  --epsilon 4/255
```

### Certified Defense Training

```bash
# Install certified defense tools
pip install auto_LiRPA

# IBP (Interval Bound Propagation) training
python ibp_train.py \
  --model small_cnn \
  --dataset mnist \
  --epsilon 0.1 \
  --schedule linear \
  --epochs 100

# CROWN-IBP training
python crown_ibp_train.py \
  --model cnn_7layer \
  --dataset cifar10 \
  --epsilon 2/255 \
  --beta-start 0.0 \
  --beta-end 1.0

# Verification of trained models
python verify_robustness.py \
  --model certified_model.pth \
  --dataset test_set \
  --epsilon 0.1 \
  --timeout 300
```

## Adversarial Attack Tools

### Attack Generation and Testing

```bash
# Generate FGSM attacks
python generate_attacks.py --method fgsm --epsilon 0.1 --model model.pth --data test_images/

# PGD attacks with multiple restarts
python generate_attacks.py --method pgd --epsilon 0.031 --alpha 0.007 --steps 20 --restarts 10

# C&W attacks for evasion
python generate_attacks.py --method cw --confidence 0 --learning_rate 0.01 --max_iterations 1000

# Universal adversarial perturbations
python generate_uap.py --dataset cifar10 --model model.pth --delta 0.2 --max_iter 10

# Physical world attack patches
python generate_patch.py --target_class 1 --patch_size 50 --transformations rotation,brightness,contrast
```

### Model Extraction Tools

```bash
# Model extraction via query-based attacks
python model_extraction.py \
  --target_api https://api.service.com/predict \
  --queries 10000 \
  --architecture resnet18 \
  --output extracted_model.pth

# Membership inference attacks
python membership_inference.py \
  --target_model model.pth \
  --shadow_models shadow_models/ \
  --attack_model logistic \
  --output mia_results.json

# Property inference attacks
python property_inference.py \
  --model model.pth \
  --property age_group \
  --queries 5000 \
  --output property_results.json
```

## Defense Deployment and Monitoring

### Production Defense Systems

```bash
# Deploy ML model with built-in defenses
docker run -d --name ml-service-defended \
  -p 8080:8080 \
  -e ENABLE_ADVERSARIAL_DETECTION=true \
  -e PREPROCESSING_PIPELINE=jpeg,blur,quantize \
  -e DETECTION_THRESHOLD=0.8 \
  ml-service:defended

# Configure ensemble defense
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ml-ensemble-defense
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ml-defense
  template:
    spec:
      containers:
      - name: detector
        image: adversarial-detector:latest
        ports:
        - containerPort: 8080
      - name: preprocessor
        image: input-preprocessor:latest
        ports:
        - containerPort: 8081
      - name: model-server
        image: model-server:robust
        ports:
        - containerPort: 8082
EOF

# Monitor adversarial attacks
prometheus-query 'rate(adversarial_attacks_detected_total[5m])' --output metrics.txt
```

### Continuous Robustness Testing

```bash
# Set up automated robustness testing
cat > robustness_test.sh << 'EOF'
#!/bin/bash
# Continuous robustness evaluation

MODEL_PATH=$1
TEST_DATA=$2
RESULTS_DIR="robustness_results_$(date +%Y%m%d)"

mkdir -p $RESULTS_DIR

# Run multiple attack evaluations
python autoattack_eval.py --model $MODEL_PATH --dataset $TEST_DATA --output $RESULTS_DIR/autoattack.json
python art_evaluate.py --model $MODEL_PATH --attacks fgsm,pgd,cw --output $RESULTS_DIR/art_results.json
python foolbox_eval.py --model $MODEL_PATH --epsilons 0.001,0.01,0.1 --output $RESULTS_DIR/foolbox.json

# Generate robustness report
python generate_report.py --results_dir $RESULTS_DIR --output $RESULTS_DIR/robustness_report.html

# Alert if robustness drops below threshold
python check_robustness_threshold.py --results $RESULTS_DIR --threshold 0.7 --alert_webhook https://alerts.company.com
EOF

chmod +x robustness_test.sh

# Schedule regular testing
echo "0 2 * * * /usr/local/bin/robustness_test.sh /models/production_model.pth /data/test_set" | crontab -
```

## Commercial Security Platforms

### Microsoft Counterfit

```bash
# Install Counterfit
pip install counterfit

# Initialize Counterfit environment
counterfit init --target-path /models/target_model.py

# Run automated security assessment
counterfit assess --framework pytorch --model resnet50 --attacks all

# Generate security report
counterfit report --output security_assessment.pdf --format pdf

# Integration with Azure ML
counterfit azure-ml --workspace security-workspace --experiment adversarial-test
```

### AWS SageMaker Model Monitor

```bash
# Configure model monitoring for adversarial inputs
aws sagemaker create-monitoring-schedule \
  --monitoring-schedule-name adversarial-monitor \
  --monitoring-schedule-config file://monitoring-config.json

# Data quality baseline with adversarial detection
aws sagemaker create-data-quality-job-definition \
  --job-definition-name adversarial-quality-check \
  --data-quality-app-specification file://quality-spec.json

# Model bias monitoring
aws sagemaker create-model-bias-job-definition \
  --job-definition-name bias-detection \
  --model-bias-app-specification file://bias-spec.json
```

### Google Cloud AI Platform Security

```bash
# Enable adversarial input detection
gcloud ai-platform models create secure-model \
  --region us-central1 \
  --enable-adversarial-detection \
  --detection-threshold 0.8

# Configure input validation
gcloud ai-platform versions create v1 \
  --model secure-model \
  --origin gs://models/robust-model/ \
  --python-version 3.8 \
  --framework tensorflow \
  --preprocessing-function preprocess_inputs

# Monitor model security metrics
gcloud logging read "resource.type=ml_job" \
  --filter 'jsonPayload.adversarial_detected=true' \
  --format json
```

## Compliance and Regulatory Tools

### NIST AI Risk Management

```bash
# AI robustness assessment tool
python ai_risk_assessment.py \
  --framework NIST-AI-RMF \
  --model model.pth \
  --test-suite comprehensive \
  --output nist_compliance_report.pdf

# Continuous compliance monitoring
./compliance_monitor.sh --standard NIST-AI-RMF --check-interval daily
```

### EU AI Act Compliance

```bash
# High-risk AI system assessment
python eu_ai_act_compliance.py \
  --model model.pth \
  --category high-risk \
  --domain computer_vision \
  --output eu_compliance_report.html

# Document security measures
python security_documentation.py \
  --model model.pth \
  --tests robustness_results/ \
  --output security_documentation.pdf
```

This practical approach focuses on actionable tools and commands that security teams can immediately deploy to assess, defend against, and monitor adversarial attacks on ML systems in production environments.

### Poisoning Attacks

Poisoning attacks compromise the training process by injecting malicious data.

#### Data Poisoning

**Label Flipping Attack**
```python
def label_flipping_attack(train_data, train_labels, poison_rate=0.1, target_class=7, flip_to=1):
    """Flip labels of target class to reduce accuracy"""
    poisoned_labels = train_labels.clone()

    # Find indices of target class
    target_indices = (train_labels == target_class).nonzero().flatten()

    # Select subset to poison
    num_poison = int(len(target_indices) * poison_rate)
    poison_indices = target_indices[:num_poison]

    # Flip labels
    poisoned_labels[poison_indices] = flip_to

    return train_data, poisoned_labels
```

**Backdoor Attacks**
```python
def insert_backdoor_trigger(image, trigger_pattern, trigger_mask, target_label):
    """Insert backdoor trigger into training image"""
    backdoored_image = image.clone()
    backdoored_image[trigger_mask] = trigger_pattern[trigger_mask]
    return backdoored_image, target_label

def create_backdoor_dataset(clean_data, clean_labels, backdoor_rate=0.05):
    """Create dataset with backdoor samples"""
    num_samples = len(clean_data)
    num_backdoor = int(num_samples * backdoor_rate)

    # Define trigger pattern (e.g., small square in corner)
    trigger_pattern = torch.zeros_like(clean_data[0])
    trigger_pattern[:, -5:, -5:] = 1  # White square trigger
    trigger_mask = torch.zeros_like(clean_data[0], dtype=torch.bool)
    trigger_mask[:, -5:, -5:] = True

    backdoored_data = clean_data.clone()
    backdoored_labels = clean_labels.clone()

    # Insert triggers into random samples
    backdoor_indices = torch.randperm(num_samples)[:num_backdoor]

    for idx in backdoor_indices:
        backdoored_data[idx], backdoored_labels[idx] = insert_backdoor_trigger(
            clean_data[idx], trigger_pattern, trigger_mask, target_label=0
        )

    return backdoored_data, backdoored_labels
```

### Model Extraction Attacks

Stealing model functionality through query-based attacks.

#### Black-Box Model Extraction

```python
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class ModelExtractionAttack:
    def __init__(self, target_model, input_shape):
        self.target_model = target_model
        self.input_shape = input_shape
        self.extracted_model = RandomForestClassifier(n_estimators=100)

    def generate_synthetic_queries(self, num_queries=10000):
        """Generate synthetic inputs for querying target model"""
        if len(self.input_shape) == 1:  # Tabular data
            synthetic_inputs = np.random.randn(num_queries, self.input_shape[0])
        else:  # Image data
            synthetic_inputs = np.random.rand(num_queries, *self.input_shape)

        return synthetic_inputs

    def query_target_model(self, inputs):
        """Query target model and collect responses"""
        outputs = []
        for input_sample in inputs:
            # Simulate API calls to target model
            output = self.target_model.predict(input_sample.reshape(1, -1))
            outputs.append(output[0])
        return np.array(outputs)

    def extract_model(self, num_queries=10000):
        """Perform model extraction attack"""
        # Generate synthetic queries
        synthetic_inputs = self.generate_synthetic_queries(num_queries)

        # Query target model
        target_outputs = self.query_target_model(synthetic_inputs)

        # Train surrogate model
        self.extracted_model.fit(synthetic_inputs, target_outputs)

        return self.extracted_model
```

#### Membership Inference Attacks

```python
class MembershipInferenceAttack:
    def __init__(self, target_model):
        self.target_model = target_model
        self.attack_model = None

    def extract_features(self, data, labels):
        """Extract features for attack model"""
        predictions = self.target_model.predict_proba(data)

        features = []
        for i, (pred, label) in enumerate(zip(predictions, labels)):
            # Confidence of correct class
            correct_confidence = pred[label]
            # Entropy of prediction
            entropy = -np.sum(pred * np.log(pred + 1e-8))
            # Max confidence
            max_confidence = np.max(pred)

            features.append([correct_confidence, entropy, max_confidence])

        return np.array(features)

    def train_attack_model(self, member_data, member_labels, non_member_data, non_member_labels):
        """Train attack model to distinguish members vs non-members"""
        # Extract features for members
        member_features = self.extract_features(member_data, member_labels)
        member_membership = np.ones(len(member_features))

        # Extract features for non-members
        non_member_features = self.extract_features(non_member_data, non_member_labels)
        non_member_membership = np.zeros(len(non_member_features))

        # Combine data
        all_features = np.vstack([member_features, non_member_features])
        all_membership = np.hstack([member_membership, non_member_membership])

        # Train binary classifier
        from sklearn.linear_model import LogisticRegression
        self.attack_model = LogisticRegression()
        self.attack_model.fit(all_features, all_membership)

    def infer_membership(self, test_data, test_labels):
        """Infer if test samples were in training set"""
        test_features = self.extract_features(test_data, test_labels)
        membership_probs = self.attack_model.predict_proba(test_features)[:, 1]
        return membership_probs
```

## Defense Mechanisms

### Adversarial Training

Training models with adversarial examples to improve robustness.

```python
def adversarial_training(model, train_loader, optimizer, epochs=10, eps=0.1):
    """Train model with adversarial examples"""
    model.train()

    for epoch in range(epochs):
        for batch_idx, (data, target) in enumerate(train_loader):
            optimizer.zero_grad()

            # Generate adversarial examples
            adv_data = pgd_attack(model, data, target, eps=eps)

            # Train on both clean and adversarial examples
            clean_output = model(data)
            adv_output = model(adv_data)

            clean_loss = F.cross_entropy(clean_output, target)
            adv_loss = F.cross_entropy(adv_output, target)

            # Combined loss
            total_loss = 0.5 * clean_loss + 0.5 * adv_loss

            total_loss.backward()
            optimizer.step()

            if batch_idx % 100 == 0:
                print(f'Epoch {epoch}, Batch {batch_idx}, Loss: {total_loss.item():.4f}')
```

### Defensive Distillation

Using temperature scaling to make models more robust.

```python
def defensive_distillation(teacher_model, student_model, train_loader, temperature=20):
    """Implement defensive distillation"""
    # Step 1: Train teacher with high temperature
    teacher_model.train()
    for data, target in train_loader:
        output = teacher_model(data) / temperature
        soft_targets = F.softmax(output, dim=1)
        loss = F.cross_entropy(output, target)
        # ... training loop

    # Step 2: Train student to match teacher's soft outputs
    student_model.train()
    teacher_model.eval()

    for data, target in train_loader:
        with torch.no_grad():
            teacher_output = teacher_model(data) / temperature
            soft_targets = F.softmax(teacher_output, dim=1)

        student_output = student_model(data) / temperature
        loss = F.kl_div(F.log_softmax(student_output, dim=1), soft_targets, reduction='batchmean')
        # ... training loop
```

### Input Preprocessing Defenses

```python
class AdversarialDetector:
    def __init__(self, model, threshold=0.1):
        self.model = model
        self.threshold = threshold

    def detect_adversarial(self, input_batch):
        """Detect adversarial examples using statistical tests"""
        batch_size = input_batch.shape[0]
        is_adversarial = torch.zeros(batch_size, dtype=torch.bool)

        for i, sample in enumerate(input_batch):
            # Test 1: Gradient magnitude
            sample.requires_grad = True
            output = self.model(sample.unsqueeze(0))
            grad = torch.autograd.grad(output.sum(), sample)[0]
            grad_magnitude = torch.norm(grad)

            # Test 2: Prediction confidence
            confidence = F.softmax(output, dim=1).max()

            # Test 3: Local smoothness
            noise = torch.randn_like(sample) * 0.01
            noisy_output = self.model((sample + noise).unsqueeze(0))
            prediction_change = torch.norm(output - noisy_output)

            # Combine detection criteria
            if (grad_magnitude > self.threshold or
                confidence < 0.5 or
                prediction_change > 0.1):
                is_adversarial[i] = True

        return is_adversarial

    def sanitize_input(self, input_batch):
        """Apply input transformations to reduce adversarial effect"""
        # JPEG compression simulation
        compressed = self.jpeg_compress_decompress(input_batch)

        # Gaussian blur
        blurred = F.conv2d(compressed, self.gaussian_kernel, padding=1)

        # Quantization
        quantized = torch.round(blurred * 255) / 255

        return quantized
```

## Model Poisoning Detection

### Statistical Detection Methods

```python
def detect_poisoned_model(model, clean_test_set, suspicious_triggers):
    """Detect if model has been backdoored"""
    model.eval()

    # Test 1: Performance on clean data
    clean_accuracy = evaluate_model(model, clean_test_set)

    # Test 2: Response to trigger patterns
    trigger_activations = []

    for trigger in suspicious_triggers:
        triggered_samples = apply_trigger_to_samples(clean_test_set, trigger)
        trigger_predictions = model(triggered_samples)

        # Check if trigger causes consistent misclassification
        prediction_consistency = check_prediction_consistency(trigger_predictions)
        trigger_activations.append(prediction_consistency)

    # Test 3: Neuron activation analysis
    suspicious_neurons = analyze_neuron_activations(model, clean_test_set, suspicious_triggers)

    # Combine detection signals
    is_poisoned = (clean_accuracy > 0.8 and  # Model performs well on clean data
                   max(trigger_activations) > 0.9 and  # Strong trigger response
                   len(suspicious_neurons) > 5)  # Multiple suspicious neurons

    return is_poisoned, {
        'clean_accuracy': clean_accuracy,
        'trigger_activations': trigger_activations,
        'suspicious_neurons': suspicious_neurons
    }
```

## Advanced Attack Techniques

### Universal Adversarial Perturbations

```python
def generate_universal_perturbation(model, dataset, delta=0.2, max_iter=10, xi=10):
    """Generate universal adversarial perturbation"""
    v = torch.zeros_like(dataset[0][0])  # Initialize perturbation

    for i in range(max_iter):
        np.random.shuffle(dataset)

        for data, label in dataset:
            if torch.norm(v, p=np.inf) > delta:
                break

            # Check if current perturbation fools the model
            perturbed = torch.clamp(data + v, 0, 1)
            pred_original = model(data.unsqueeze(0)).argmax()
            pred_perturbed = model(perturbed.unsqueeze(0)).argmax()

            if pred_original == pred_perturbed:
                # Generate minimal perturbation for this sample
                dr = minimal_perturbation(model, data, v)
                v = v + dr
                v = torch.clamp(v, -delta, delta)

    return v
```

### Physical-World Attacks

```python
class PhysicalAttack:
    def __init__(self, model, camera_model):
        self.model = model
        self.camera_model = camera_model

    def generate_physical_patch(self, target_class, patch_size=(50, 50)):
        """Generate adversarial patch for physical world"""
        patch = torch.rand(3, *patch_size, requires_grad=True)
        optimizer = torch.optim.Adam([patch], lr=0.01)

        for epoch in range(1000):
            # Sample random transformations (rotation, scaling, lighting)
            transformations = self.sample_transformations()

            total_loss = 0
            for transform in transformations:
                # Apply physical transformations
                transformed_patch = self.apply_transformation(patch, transform)

                # Simulate camera capture
                captured_image = self.camera_model.capture(transformed_patch)

                # Evaluate model response
                output = self.model(captured_image)
                loss = F.cross_entropy(output, torch.tensor([target_class]))
                total_loss += loss

            optimizer.zero_grad()
            total_loss.backward()
            optimizer.step()

            # Ensure patch values are valid
            patch.data = torch.clamp(patch.data, 0, 1)

        return patch.detach()
```

## Evaluation Metrics

### Robustness Metrics

```python
def evaluate_adversarial_robustness(model, test_loader, attack_methods):
    """Comprehensive robustness evaluation"""
    results = {}

    for attack_name, attack_func in attack_methods.items():
        correct_clean = 0
        correct_adversarial = 0
        total = 0

        for data, target in test_loader:
            # Clean accuracy
            clean_output = model(data)
            clean_pred = clean_output.argmax(dim=1)
            correct_clean += (clean_pred == target).sum().item()

            # Adversarial accuracy
            adv_data = attack_func(model, data, target)
            adv_output = model(adv_data)
            adv_pred = adv_output.argmax(dim=1)
            correct_adversarial += (adv_pred == target).sum().item()

            total += target.size(0)

        results[attack_name] = {
            'clean_accuracy': correct_clean / total,
            'adversarial_accuracy': correct_adversarial / total,
            'robustness_gap': (correct_clean - correct_adversarial) / total
        }

    return results
```

## Real-World Case Studies

### Case Study 1: Tesla Autopilot Attack (2019)

**Attack Vector**: Adversarial road markings
**Technique**: Physical lane detection bypass using strategically placed tape
**Impact**: Caused vehicle to swerve into oncoming traffic lane
**Defense**: Multi-sensor fusion and anomaly detection

### Case Study 2: Face ID Bypass (2020)

**Attack Vector**: Adversarial eyeglass frames
**Technique**: Optimized patterns printed on eyewear to fool facial recognition
**Impact**: Unauthorized device access
**Defense**: Liveness detection and multi-modal authentication

### Case Study 3: Medical AI Poisoning (2021)

**Attack Vector**: Backdoor injection in medical imaging model
**Technique**: Subtle trigger patterns in X-ray images during training
**Impact**: Misdiagnosis of critical conditions
**Defense**: Federated learning with Byzantine-robust aggregation

## Regulatory and Compliance

### NIST AI Risk Management Framework

Adversarial attacks align with several NIST categories:
- **MEASURE-2.1**: Test sets and metrics reflect real-world conditions
- **MEASURE-2.11**: Fairness and bias are evaluated and results documented
- **MANAGE-4.2**: Model monitoring and regular re-assessment

### EU AI Act Compliance

Requirements for high-risk AI systems:
- Robustness testing against adversarial inputs
- Documentation of security measures
- Incident reporting for adversarial attacks

## Tools and Frameworks

### Open Source Libraries

```bash
# Install popular adversarial ML libraries
pip install adversarial-robustness-toolbox  # IBM ART
pip install foolbox                         # Foolbox framework
pip install cleverhans                      # CleverHans library
pip install autoattack                      # AutoAttack ensemble
```

### Commercial Solutions

- **Microsoft Counterfit**: Adversarial testing platform
- **IBM Adversarial Robustness 360**: Comprehensive toolbox
- **Google What-If Tool**: ML interpretability and robustness

## Future Research Directions

### Emerging Attack Vectors

- **Quantum Adversarial Examples**: Exploiting quantum ML models
- **Federated Learning Attacks**: Poisoning distributed training
- **Multi-Modal Attacks**: Combining text, image, and audio adversarial examples
- **Neuromorphic Computing Attacks**: Targeting brain-inspired architectures

### Defense Innovation

- **Certified Defenses**: Provable robustness guarantees
- **Adaptive Defenses**: Dynamic response to detected attacks
- **Privacy-Preserving Robustness**: Differential privacy for adversarial training
- **Biological-Inspired Defenses**: Learning from natural immune systems

## References

- [Adversarial Examples in the Physical World](https://arxiv.org/abs/1607.02533)
- [Explaining and Harnessing Adversarial Examples](https://arxiv.org/abs/1412.6572)
- [Towards Deep Learning Models Resistant to Adversarial Attacks](https://arxiv.org/abs/1706.06083)
- [The Space of Transferable Adversarial Examples](https://arxiv.org/abs/1704.03453)