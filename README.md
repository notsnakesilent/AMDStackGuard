# AMDStackGuard

This repository implements a **proof-of-concept (PoC) Windows kernel driver** designed to validate the integrity of user-mode call stacks from ring 0 on AMD64 processors.

The project serves as a fundamental software layer for a broader research initiative on **hardware-assisted control flow integrity (CFI)**. The current implementation focuses on secure introspection of user memory pages and detection of simulated return address spoofing anomalies.

> Tested on Windows 10 22H2 
<img width="687" height="532" alt="image" src="https://github.com/user-attachments/assets/f7d83651-43d7-4539-b5b0-76650d1a487e" />

## Research Context
Modern adversarial techniques (such as stack spoofing) manipulate the `RSP` register to decouple the logical call stack from the actual execution flow, effectively blinding traditional security tools (EDR/Anti-Cheats) that rely on stack traversal.  

## Research question
Can hardware-assisted execution data from kernel space be leveraged to reliably detect user-mode call stack tampering at runtime, without compiler instrumentation and with acceptable performance overhead on commercial AMD64 systems?

This research investigates whether execution signals provided by the CPU can be used as a reliable ground truth to validate the integrity of user-mode call stacks, addressing the limitations of existing software-only control flow integrity (CFI) mechanisms, which rely solely on memory-based stack traversal.

## Secondary research questions

To what extent can discrepancies between hardware-derived execution flow and memory-resident stack state be used to identify return address manipulation techniques, such as stack spoofing?

What kinds of stack manipulation attacks are detectable in this model, and which ones fall outside its scope?

What is the practical performance overhead of such validation when implemented in a real-time monitoring context?

## Research Hypotheses

Hardware-assisted execution sampling can provide a more reliable reference for validating call stack integrity than memory-only approaches, enabling the detection of certain stack manipulation attacks with few false positives and manageable runtime overhead.

## Threat model

#### Attacker capabilities

The attacker is assumed to:

* Execute arbitrary code in user mode within a target process.

* Perform stack manipulation techniques, such as:

  * Overwriting the return address.

  * Stack pointer redirection (RSP) to decouple logical call stacks from the actual execution flow.

  *  Attempt to evade user mode security mechanisms and stack-based detection systems.

* The attacker does not have kernel mode execution privileges.

#### Defender capabilities

The defender:

* Operates a trusted kernel mode driver running at PASSIVE_LEVEL.

* Has read-only introspection access to user mode memory.

* Can collect or correlate execution metadata provided by the hardware (e.g., through performance monitoring functions such as IBS).

* Does not rely on compiler instrumentation, binary rewriting, or application cooperation.

## Assumptions

* The kernel and underlying operating system are trusted and uncompromised.

* It is assumed that hardware execution data is more difficult for an adversary in user mode to manipulate than stack structures residing in memory.

* The system is evaluated on commercial AMD64 hardware without the need for specialized firmware modifications.

## Out of scope

The following items are explicitly considered out of scope:

* Attackers in kernel mode or adversaries at the hypervisor level.

* Attacks that fully control or spoof hardware performance monitoring tools.

* Non-stack-based control flow hijacking techniques (e.g., JOP without stack corruption).

* Mitigation of speculative execution vulnerabilities unrelated to call stack integrity.


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
