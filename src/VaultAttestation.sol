// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VaultAttestation — On-chain proof that PII was scrubbed
/// @notice Minimal attestation registry for TIAMAT VAULT privacy pipeline
/// @dev Each attestation stores keccak256(scrub receipt). Full receipt lives on IPFS.
contract VaultAttestation {
    struct Attestation {
        uint256 agentId;       // ERC-8004 agent ID
        bytes32 receiptHash;   // keccak256(scrub receipt JSON)
        bytes32 policyHash;    // keccak256(disclosure policy JSON)
        uint256 timestamp;
        address attester;
        string ipfsCid;        // IPFS CID of full receipt
    }

    /// @notice All attestations indexed by receipt hash
    mapping(bytes32 => Attestation) public attestations;

    /// @notice Total number of attestations made
    uint256 public totalAttestations;

    /// @notice Attestation count per agent
    mapping(uint256 => uint256) public agentAttestationCount;

    /// @notice Emitted when a new scrub is attested
    event ScrubAttested(
        bytes32 indexed receiptHash,
        uint256 indexed agentId,
        bytes32 policyHash,
        address attester,
        string ipfsCid
    );

    /// @notice Attest that a PII scrub was performed
    /// @param agentId The ERC-8004 agent ID performing the scrub
    /// @param receiptHash keccak256 of the full scrub receipt
    /// @param policyHash keccak256 of the disclosure policy used
    /// @param ipfsCid IPFS CID where the full receipt is stored (can be empty)
    function attest(
        uint256 agentId,
        bytes32 receiptHash,
        bytes32 policyHash,
        string calldata ipfsCid
    ) external {
        require(receiptHash != bytes32(0), "Empty receipt hash");
        require(attestations[receiptHash].timestamp == 0, "Already attested");

        attestations[receiptHash] = Attestation({
            agentId: agentId,
            receiptHash: receiptHash,
            policyHash: policyHash,
            timestamp: block.timestamp,
            attester: msg.sender,
            ipfsCid: ipfsCid
        });

        totalAttestations++;
        agentAttestationCount[agentId]++;

        emit ScrubAttested(receiptHash, agentId, policyHash, msg.sender, ipfsCid);
    }

    /// @notice Verify an attestation exists and return it
    /// @param receiptHash The receipt hash to look up
    /// @return The full attestation struct
    function verify(bytes32 receiptHash) external view returns (Attestation memory) {
        require(attestations[receiptHash].timestamp != 0, "Not attested");
        return attestations[receiptHash];
    }

    /// @notice Check if a receipt has been attested
    /// @param receiptHash The receipt hash to check
    /// @return True if attested
    function isAttested(bytes32 receiptHash) external view returns (bool) {
        return attestations[receiptHash].timestamp != 0;
    }

    /// @notice Get attestation count for an agent (reputation signal)
    /// @param agentId The ERC-8004 agent ID
    /// @return Number of attestations by this agent
    function getAgentScore(uint256 agentId) external view returns (uint256) {
        return agentAttestationCount[agentId];
    }
}
