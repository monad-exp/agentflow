## Introduction

Monad Foundation is an organization dedicated to supporting the development, decentralization, security, and adoption of the Monad protocol by providing a wide range of services including community engagement, business development, developer and user education, and marketing services.

## Prohibited Actions

- **No Unauthorized Testing on Production Environments:** Do not test vulnerabilities on mainnet or public testnet deployments without prior authorization. Use local test environments or private test setup.
    - The README.md contains [instructions](https://github.com/category-labs/monad-bft/blob/master/README.md#getting-started) for setting up a local installation with Docker as a recommended environment.
- **No Public Disclosure Without Consent:** Do not publicly disclose details of any vulnerability before it has been addressed and you have received written permission to disclose.
- **No Exploitation or Data Exfiltration:** Do not exploit the vulnerability beyond the minimum steps necessary to demonstrate the issue. Do not access private data, engage in social engineering, or disrupt service.
- **No Conflict of Interest:**
Individuals currently or formerly employed by the Monad Foundation, Category Labs, or who contributed to the development of the affected code, are ineligible to participate. Former auditors ARE permitted to participate so long as 3 months have passed since their audit ended.
- **Social Engineering:** Social engineering attacks are out of scope and not permitted for testing.
- **Physical security:** Testing of physical security is out of scope and not permitted for testing.

## Disclosure Requirements

Please report vulnerabilities directly to Cantina Platform. Include:

- A clear description of the vulnerability and its impact.
- Steps to reproduce the issue (proof of concept preferred).
- Conditions under which the issue occurs.
- Potential implications if exploited.

Reports should be submitted as soon as possible—ideally within 24 hours of discovery.

## Eligibility

To be eligible for consideration and any reward, a researcher must:

- Be the first to report a previously unknown, non-public vulnerability within scope.
- Provide sufficient information to reproduce and fix the issue.
- Provide all KYC and other documents as requested
- Not have exploited the vulnerability in a malicious manner.
- Not have disclosed the vulnerability to third parties prior to receiving permission.
- Comply with all Program rules and applicable laws.


You must also be of legal age in your jurisdiction and not reside in a country under sanctions or restrictions, as required by applicable laws.

## Proof of Concept (PoC) Requirements

- Reports of High or Critical severity **must** include a working proof of concept using a [local devnet](https://github.com/category-labs/monad-bft?tab=readme-ov-file#using-docker) or [monad-solonet](https://github.com/monad-crypto/monad-solonet#quick-start) setup. Submissions at these severity levels that do not include a PoC will be rejected.
- For reports involving hardware-specific impact (e.g., out-of-memory conditions, CPU exhaustion), note that Docker-based development environments may not accurately reflect production resource constraints. To validate resource-based attack submissions with confidence, we recommend running a [baremetal node](https://docs.monad.xyz/node-ops/full-node-installation) on [minimum hardware](https://docs.monad.xyz/node-ops/hardware-requirements) specs. This will help confirm realistic impact and accelerate review of your submission.
- Reports claiming DoS via resource exhaustion (memory, CPU, disk, file descriptors, network, etc.) must demonstrate the impact against a local full node, and the PoC must show the exhaustion is caused by the node binary's handling of attacker-controlled input, not by unrelated host-level resource consumption.
- PoCs exercising internal functionality (such as Rust or C++ specific internal functions classes or otherwise) must demonstrate their impact through a full node's publicly accessible entry point. A local full node setup will let us confirm your submission quicker.

NOTE: Please see the following to run a [local devnet (full node)](https://github.com/category-labs/monad-bft?tab=readme-ov-file#using-docker) ([please note hardware requirements](https://docs.monad.xyz/node-ops/hardware-requirements)).

## Severity and Rewards

Vulnerabilities are classified by Impact and Likelihood. The combination determines the severity and guides the reward amount.


### Risk Classification Matrix

Report issue severity is determined by the issue’s impact and likelihood. Findings with higher impact and likelihood result in higher severity. Review the definitions and table below select a severity when making a report.


**Impact Definitions**

- **Critical**: Leads to severe loss of user funds, permanent system disruption, or widespread compromise. Examples include:
    - Infinite MON minting
    - Consensus safety failure 
    - Client bug leading to key compromise / exfiltration
    - Permanent freezing of funds requiring hardfork to remediate

- **High**: Causes notable financial loss or significantly harms user trust, but on a lesser scale than Critical.
    - Network halt

- **Medium**: Results in limited financial damage or moderate system impact.
- **Low / Informational**: Minimal direct risk but may indicate areas for improvement.

NOTE: Applies to bugs/issues with the network code itself. Smart contract bugs in applications running on the Monad Network (Defi protocols, DEXes, etc.) are not within the scope of this program.




**Likelihood Definitions**


- High: Very easy to exploit or highly incentivized.
- Medium: Exploitation is possible under certain conditions.
- Low: Difficult to exploit or requires very specific conditions.

| Severity Level    | Impact: Critical | Impact: High | Impact: Medium | Impact: Low |
|-------------------|------------------|--------------|----------------|-------------|
| Likelihood: High   | Critical         | High         | Medium         | Low         |
| Likelihood: Medium | High             | High         | Medium         | Low         |
| Likelihood: Low    | Medium           | Medium / Low   | Low            | Informational |

## Issue Severity Extended Guidance

### Safety and Correctness

- These issues are of great interest and can range from low impact (e.g. minor spec divergence) to critical (e.g. double spend, infinite mint, etc.).

### Liveness

- Byzantine Fault Tolerance accommodates some nodes going down. For an issue to cause a network halt, one third of the validator set must be affected.
- Examples of a **high severity** issue
    - A network halting error that is propagated by the leader.
    - A bug that can halt a node in a single block and is repeatable across the network to many nodes (i.e. greater than one third).
- Examples of a **low severity** issue:
    - A node halting error that only affects a **single peer** during a **narrow window** such as responding to a `StateSyncRequest`.
    - A bug that causes a node to log excessively and run out of disk space. Node operators are expected to monitor their hardware for resource utilization.

### RPC

- Major RPC providers implement defenses against a range of potential problems through rate limiting, reverse proxies, and more. Reports of issues that Monad Network RPC providers already defend against may be classified as informational to low severity.
- Findings capable of surpassing these RPC provider defenses and halting RPC nodes are classified as medium severity, unless further chain impact itself is identified. To achieve a higher severity impact where the underlying issue is via the RPC, further severe impact outside of the RPC must be demonstrated. Some examples: RCE, private transaction state leakage, state persisted modifications, impactful cryptographic material leakage.
   - Please note, the fact that transactions are not able to be broadcast via the RPC is not in and of itself a higher severity chain impact outside of the RPC and is capped at a medium severity payout.

### Overall

- The baseline assumption is that node operators are applying customary industry practices including common levels of hardening and monitoring. In such an environment, a one time reboot for a single node would be limited in impact.
- A persistent outage affecting many nodes at once would demonstrate higher impact.



## Areas of concern (where to focus for bugs)
The team's primary concerns for the Monad protocol are focused on the following components:
- Consensus Safety: The stability of the MonadBFT consensus mechanism is paramount.
    - Malicious validator activity and its potential to disrupt the consensus process.
    - General safety or liveness issues and disruption of the consensus process that can arise from a byzantine validator activity (within protocol assumptions of < 1/3 stake)
    - The possibility of a faulty node causing a chain split or incorrect finality.
    - Exploitation of the leader election process for unfair advantage.
- Networking Layer (RaptorCast): The custom message delivery protocol is a potential attack surface.
    - Abuse of the broadcast tree by a malicious node to delay block propagation.
    - Denial-of-Service (DoS) attacks via spamming with invalid or malformed RaptorCast chunks.
    - Vulnerabilities in the signature and Merkle tree verification logic.
    - Incorrect encoding or decoding of messages, or tampering of messages
    - Exploitation of the local mempool and transaction forwarding to create race conditions.
- Parallel Execution and State Integrity: Parallel execution is a core innovation and a critical area of concern.
    - Potential for non-deterministic outcomes or state mismatches between nodes.
    - Accurate and robust read/write set analysis.
    - Risk of non-deterministic outcomes from asynchronous execution.
- Transaction and Fee Model: The custom gas model requires scrutiny.
    - Manipulation of the gas limit for DoS attacks.
    - Correctness and resistance to overflow/underflow in fee calculations.
    - Correct handling of unexpected state reversions.
- MonadDB Integrity: The custom database (MonadDB) is essential for state management.
    - Corruption or bypassing of database integrity checks.
    - Race conditions in parallel state access.
- JIT VM and Interpreter: The Just-In-Time (JIT) compiler is a highly sensitive component.
    - Differences in execution output between interpreted and JIT-compiled EVM bytecode.
    - Potential for a malicious contract to achieve remote code execution (RCE).
    - Data persistence or corruption in the cache after a transaction rollback.
   
**Main invariants**
- Consensus: The network must achieve consensus on a single, canonical block order if a supermajority of stake weight is non-faulty. All honest nodes must arrive at the exact same committed final state.
- Chain finality: Speculative execution results of a previous block will be finalized within the designated system parameters if a supermajority of nodes are participating in consensus
- Execution: The outcome of any transaction, including failure, is deterministic regardless of the execution path (interpreter or JIT). The final state of a block must be identical across all nodes.
- State Integrity: The blockchain state must be consistent and verifiable at all block heights. The merkle root from a delayed block D must be agreed upon by all nodes to prevent state divergence. The total native token supply shall not exceed the maximum configured supply.
- Transactions: The total token deduction from a sender's balance must be equal to the sum of value and the product of gas_price and gas_limit. A transaction's max_expenditure shall not exceed the sender's available balance at the time of consensus.
- Networking: All RaptorCast chunks must have a valid signature from the originator. The network must guarantee reliable message delivery to all non-faulty nodes if a supermajority of - stake weight is non-faulty.
- EVM Compatibility: Aside from the known deviations mentioned, execution of a transaction should conform to existing EVM specifications.

### All trusted roles in the protocol
- StateSync Peer
    - Purpose: Trusted nodes that provide state synchronization data during initial sync or catch-up
    - Who can be a StateSync Peer: Nodes explicitly configured in the state_sync_peers list, which defaults to bootstrap nodes if none specified



