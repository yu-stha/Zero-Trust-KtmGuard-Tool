## UPDATE — Problem SOLVED on AWS (but not on Kali)

### What Changed
The same ktmguard.py code (after adding --tap flag) was tested on two 
different environments with different results:

**Kali Linux VM (local):**
- Result: Tap only detected 3 edges (all frontend → X)
- Missing: checkoutservice → paymentservice, checkoutservice → cartservice, 
  checkoutservice → productcatalogservice
- Root cause: unclear — possibly limited traffic generation, or checkout 
  service's outbound calls were not triggered during the tap window on 
  a resource-constrained VM (3.8GB RAM, 2 CPU)

**AWS EC2 m7i-flex.large (2 vCPU, 8GB RAM, 30GB storage):**
- Result: Tap detected 6 out of 7 expected edges successfully
- Detected: frontend → cartservice, frontend → checkoutservice, 
  frontend → productcatalogservice, checkoutservice → cartservice, 
  checkoutservice → paymentservice, checkoutservice → productcatalogservice
- Still missing: cartservice → redis-cart (likely because redis uses 
  raw TCP protocol, not HTTP/gRPC, so Linkerd tap does not label it 
  with a deployment name the same way)

### Why AWS Worked and Kali Didn't (Hypothesis)
Most likely explanation: on Kali, limited CPU/RAM (2 cores, 3.8GB) caused 
slower pod startup and the checkoutservice's internal calls to 
paymentservice/cartservice/productcatalogservice may not have been 
triggered within the 30-second tap window, OR the traffic generator 
script only hit GET endpoints on frontend without triggering a real 
checkout flow that calls downstream services. On AWS with more resources 
and possibly more complete traffic generation, these internal calls did 
occur during the tap window and were captured.

### Current Status
- Environment: AWS EC2 m7i-flex.large, 30GB storage (initially 20GB, 
  increased to 30GB before this test)
- Named service accounts created for all 6 deployments (frontend, 
  cartservice, checkoutservice, paymentservice, productcatalogservice, 
  redis-cart)
- Linkerd injected into boutique namespace (all pods 2/2)
- scan --tap successfully detects 6/7 edges
- Next step: investigate why cartservice → redis-cart is not detected, 
  likely need TCP-specific handling since redis-cart uses raw TCP 
  protocol (port 6379) not HTTP/2

### Next Steps
1. Run: python3 ktmguard.py generate --namespace boutique
2. Review generated YAML files
3. Apply and verify Zero Trust enforcement works
4. Fix cartservice → redis-cart detection gap (TCP-specific edge case)