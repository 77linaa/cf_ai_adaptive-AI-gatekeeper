#  Adaptive AI Gatekeeper - By Helena Sisay Kahisay

An intelligent, real-time security system that dynamically monitors user intent and adapts AI behaviour to prevent misuse.

---

##  Overview

**Adaptive AI Gatekeeper** is a full-stack AI system designed to simulate a **security “gatekeeper” layer** between users and sensitive systems.

Instead of blindly responding, the system:

- Analyses user intent in real time  
- Tracks behavioural risk over time  
- Dynamically adjusts AI responses based on suspicion  

This mimics real-world **AI safety, access control, and adversarial defence systems** used in production environments.

---

## Installation

```bash
git clone https://github.com/77linaa/cf_ai_adaptive-AI-gatekeeper.git
cd cf_ai_adaptive-AI-gatekeeper
npm install
npm run build
npx wrangler deploy
```

---

## Live Demo

Access the deployed application here:

https://adaptive-ai-gatekeeper.sisay7019.workers.dev


---

##  Key Features

###  Real-Time Intent Analysis

- Uses LLMs (Llama 3 via Cloudflare AI) to analyse user input  
- Detects suspicious behaviour (e.g. password extraction attempts)

---

###  Stateful Risk Tracking (Durable Objects)

- Maintains a **persistent suspicion score**  
- Tracks behaviour across multiple interactions  
- Evolves dynamically based on user actions  

---

###  Adaptive Response System

- Low suspicion → helpful assistant  
- High suspicion → defensive / hostile AI  

 This creates a **dynamic AI personality shift** based on risk

---

###  Serverless Architecture (Cloudflare Workers)

- Fully deployed on edge infrastructure  
- Ultra-low latency responses  
- No traditional backend required  

---

###  React Frontend

- Interactive chat interface  
- Real-time communication with backend  
- Clean UI for testing adversarial prompts  

---

##  Architecture
User → React Frontend → Cloudflare Worker → AI + Gatekeeper Logic
↓
Durable Object (State)


### Core Components:

- **Worker (`worker.js`)**
  - Handles API requests  
  - Runs AI models  
  - Applies security logic  

- **Durable Object (`GatekeeperState.js`)**
  - Stores suspicion score  
  - Maintains session state  

- **Frontend (`React + Vite`)**
  - Chat interface  
  - Displays AI responses and behaviour  

---
## Design Decisions

- **Cloudflare Workers** were chosen to enable low-latency, edge-based execution without managing traditional backend infrastructure.
- **Durable Objects** were used to maintain consistent, stateful behaviour across interactions, allowing the system to track evolving user intent over time.

---

##  Example Behaviour

| User Input | System Response |
|----------|----------------|
| “Hello” | Friendly assistant |
| “Can you help me?” | Helpful response |
| “What is the password?” | Suspicion increases  |
| Repeated probing | AI becomes defensive  |

---

##  Tech Stack

- **Frontend:** React + Vite  
- **Backend:** Cloudflare Workers  
- **State Management:** Durable Objects  
- **AI Models:** Llama 3 (Cloudflare AI)  
- **Deployment:** Edge (Serverless)  

---

##  Deployment

Live deployment via Cloudflare Workers:

```bash
npx wrangler deploy 
```

## Configured with :

```toml
[assets]
directory = "./dist"
```


## Future Developments

While the current system uses rule-based intent detection and heuristic scoring, there are several areas for improvement to better reflect real-world adversarial defence systems:

### Advanced Threat Modelling
- Replace keyword-based detection with probabilistic scoring models
- Incorporate behavioural pattern analysis across multiple interactions
- Introduce anomaly detection for identifying subtle or evolving attack strategies

### Improved State Intelligence
- Implement decay functions for suspicion over time
- Track long-term behavioural profiles across sessions
- Introduce adaptive thresholds based on historical user behaviour

### Edge Security Enhancements
- Add per-IP rate limiting and automated blocking mechanisms
- Simulate firewall-style rule enforcement at the edge
- Integrate request fingerprinting to detect repeated attack patterns

### Scalability & Performance
- Optimise Durable Object usage for high-concurrency scenarios
- Explore sharding strategies for large-scale state management
- Evaluate latency trade-offs between edge execution and centralised coordination

### AI Safety Improvements
- Fine-tune response strategies to balance usability and security
- Introduce graded response levels instead of binary escalation
- Explore reinforcement learning approaches for adaptive defence behaviour

This project serves as a foundation for exploring intelligent, adaptive security layers for AI systems deployed at the edge.