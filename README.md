# AMDStackGuard

This repository implements a **proof-of-concept (PoC) Windows kernel driver** designed to validate the integrity of user-mode call stacks from ring 0 on AMD64 processors.

The project serves as a fundamental software layer for a broader research initiative on **hardware-assisted control flow integrity (CFI)**. The current implementation focuses on secure introspection of user memory pages and detection of simulated return address spoofing anomalies.

> Tested on Windows 10 22H2 
<img width="687" height="532" alt="image" src="https://github.com/user-attachments/assets/f7d83651-43d7-4539-b5b0-76650d1a487e" />

## Research Context


  Modern adversarial techniques (such as stack spoofing) manipulate the `RSP` register to decouple the logical call stack from the actual execution flow, effectively blinding traditional security tools (EDR/Anti-Cheats) that rely on stack traversal.  


## Technical Architecture

<p>
    <img src="https://github.com/user-attachments/assets/80ff0d1f-b383-45c9-93ea-060b2b2eb44c"
       align="right"
       width="35%"
       style="margin-left: 12px; margin-bottom: 8px;" />
The solution consists of two components:

1.  **Kernel driver (`.sys`):**
*   Implements safe memory checking using `ProbeForRead` and structured exception handling (SEH) to prevent blue screens of death when accessing paged user memory 
*  Exposes an IOCTL interface to validate a specific memory address against an expected value
*  Operates at `PASSIVE_LEVEL` for initial testing stability

2. **CLI/user mode simulation:**
* **Validation client:** Retrieves the actual return address and passes the stack pointer (`RSP`) to the driver for verification.
    * **Adversarial simulation:** Includes a routine to artificially modify the return address on the stack (spoofing), demonstrating how the driver detects the discrepancy between memory contents and the expected execution flow.

</p>

## Current Capabilities

- [x] **Secure memory introspection:** The driver correctly reads memory in user mode without blocking the system, gracefully handling page faults.
- [x] **Anomaly detection logic:** Implements the comparison logic `[RSP] == ExpectedReturn`.
- [x] **Adversarial test case:** Correctly flags a manipulated stack where the return address has been overwritten.

> **Note:** This driver requires test signing mode to be enabled (`bcdedit /set testsigning on`).

## Disclaimer

This code is intended for educational and research purposes only. Its purpose is to demonstrate core programming concepts and memory management techniques.

## TODO

- [ ] **MDL support:**
- Transition from `ProbeForRead` to `IoAllocateMdl` / `MmProbeAndLockPages` for robust memory access during high IRQL scenarios (preparation for PMI drivers).
- [ ] **MSR configuration:**
- Implement `__writemsr` logic to enable IBS execution sampling (`IbsOpCtl`).
- [ ] **Interrupt handling:**
- Register a callback for performance monitor interrupts (PMI) or examine IBS logs periodically.
- [ ] **Data correlation:**
- Correlate `IbsBrTarget` (hardware truth) with the value in `[UserRsp]` (memory truth).
- [ ] Perform overhead analysis using benchmarks (e.g., frame rate impact on graphics applications).
