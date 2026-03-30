CRT Fault Leak in RSA
Overview

This project demonstrates a critical vulnerability in RSA implementations that use the Chinese Remainder Theorem (CRT) for performance optimization. While CRT significantly improves computational efficiency, it introduces susceptibility to fault injection attacks. In particular, the project implements the Bellcore (Boneh–DeMillo–Lipton) attack, which shows that even a single faulty RSA-CRT signature can lead to recovery of private key components.

The project includes a complete pipeline covering vulnerable implementation, fault simulation, attack execution, and a secure countermeasure. It also provides experimental analysis through graphs and extended simulations.

Project Structure
crypto-project/
│
├── attack.py              # Fault injection and Bellcore attack logic
├── rsa.py                 # RSA key generation and CRT-based signing
├── utils.py               # Mathematical utilities (GCD, modular inverse, primes)
├── graphs.py              # Graph generation and result visualization
├── main.py                # GUI application for running simulations
├── multi_simulation.py    # Extended simulations (multiple fault scenarios)
├── .gitignore
├── README.md
└── venv/                  # Virtual environment (optional)
Key Features
Implementation of RSA with CRT optimization
Simulation of fault injection in modular exponentiation
Demonstration of Bellcore fault attack
Recovery of RSA private key using GCD
Secure implementation using verification and recomputation
Comparative analysis between vulnerable and secure systems
Graphical visualization of performance and attack success
Working Principle
RSA-CRT Optimization

Instead of computing:

𝑠
=
𝑚
𝑑
m
o
d
 
 
𝑛
s=m
d
modn

CRT computes:

𝑠
𝑝
=
𝑚
𝑑
𝑝
m
o
d
 
 
𝑝
s
p
	​

=m
d
p
	​

modp
𝑠
𝑞
=
𝑚
𝑑
𝑞
m
o
d
 
 
𝑞
s
q
	​

=m
d
q
	​

modq

Then recombines:

ℎ
=
𝑞
−
1
(
𝑠
𝑝
−
𝑠
𝑞
)
m
o
d
 
 
𝑝
h=q
−1
(s
p
	​

−s
q
	​

)modp
𝑠
=
𝑠
𝑞
+
ℎ
⋅
𝑞
s=s
q
	​

+h⋅q
Fault Injection

A fault is introduced in either:

𝑠
𝑝
s
p
	​

 (modulo 
𝑝
p)
𝑠
𝑞
s
q
	​

 (modulo 
𝑞
q)

This produces a faulty signature 
𝑠
′
s
′
.

Bellcore Attack

The attack computes:

𝑔
=
gcd
⁡
(
∣
𝑠
−
𝑠
′
∣
,
𝑛
)
g=gcd(∣s−s
′
∣,n)
If 
𝑔
=
𝑝
g=p or 
𝑞
q, the private key is recovered
A single faulty signature is sufficient
Prevention Mechanism

The secure implementation verifies:

𝑠
𝑒
≡
𝑚
m
o
d
 
 
𝑛
s
e
≡mmodn

If verification fails:

The signature is recomputed using full exponentiation
Faulty outputs are never exposed
How to Run
1. Install Requirements

Ensure Python 3.x is installed. No external libraries are required except matplotlib for graphs.

pip install matplotlib
2. Run the Main Application
python main.py

This launches the GUI where you can:

Generate RSA keys
Run attack simulations
Apply prevention
Visualize results
3. Run Attack Module (CLI)
python attack.py
4. Run Extended Simulations
python multi_simulation.py

This includes:

Multiple fault attempts
Dual fault scenarios
Comparative analysis
Results

The implementation demonstrates:

High success rate of Bellcore attack on vulnerable RSA-CRT
Complete failure of attack after applying verification
Minimal performance overhead for secure implementation
Clear distinction between confidentiality and integrity behavior
Security Insights
RSA is mathematically secure but implementation-dependent
CRT optimization introduces exploitable fault points
A single faulty computation can compromise the entire system
Verification-based countermeasures effectively prevent leakage
Limitations
Fault injection is simulated and does not model physical hardware faults
Experiments are limited to standard key sizes (1024, 2048 bits)
Only single-fault Bellcore attack is implemented
Advanced side-channel attacks are not considered
Conclusion

This project highlights the gap between theoretical cryptographic security and real-world implementation vulnerabilities. While CRT significantly improves RSA performance, it introduces critical risks under fault conditions. The Bellcore attack demonstrates that even a single faulty signature can lead to complete key compromise. However, a simple verification-based countermeasure ensures system security with minimal overhead.

References
B. Schneier, Applied Cryptography, Wiley, 1996.
Menezes et al., Handbook of Applied Cryptography, CRC Press, 1996.
Katz and Lindell, Introduction to Modern Cryptography, CRC Press, 2014.
W. Stallings, Cryptography and Network Security, Pearson, 2017.
D. Stinson, Cryptography: Theory and Practice, CRC Press, 2018.
Boneh and Shoup, A Graduate Course in Applied Cryptography, 2020.
Paar and Pelzl, Understanding Cryptography, Springer, 2010.
Ross Anderson, Security Engineering, Wiley, 2008.
