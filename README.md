CRT Fault Leak in RSA
Overview

This project demonstrates a critical vulnerability in RSA implementations that use the Chinese Remainder Theorem (CRT) for performance optimization. While CRT significantly improves computational efficiency, it introduces susceptibility to fault injection attacks. In particular, the project implements the Bellcore (Boneh–DeMillo–Lipton) attack, which shows that even a single faulty RSA-CRT signature can lead to recovery of private key components.

The project includes a complete pipeline covering vulnerable implementation, fault simulation, attack execution, and a secure countermeasure. It also provides experimental analysis through graphs and extended simulations
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
