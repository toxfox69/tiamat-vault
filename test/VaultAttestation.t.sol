// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VaultAttestation.sol";

contract VaultAttestationTest is Test {
    VaultAttestation vault;
    uint256 constant AGENT_ID = 29931; // TIAMAT's ERC-8004 ID

    function setUp() public {
        vault = new VaultAttestation();
    }

    function test_attest() public {
        bytes32 receiptHash = keccak256("test-receipt-1");
        bytes32 policyHash = keccak256("test-policy-1");
        string memory cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

        vault.attest(AGENT_ID, receiptHash, policyHash, cid);

        VaultAttestation.Attestation memory a = vault.verify(receiptHash);
        assertEq(a.agentId, AGENT_ID);
        assertEq(a.receiptHash, receiptHash);
        assertEq(a.policyHash, policyHash);
        assertEq(a.attester, address(this));
        assertEq(keccak256(bytes(a.ipfsCid)), keccak256(bytes(cid)));
        assertGt(a.timestamp, 0);
    }

    function test_totalAttestations() public {
        vault.attest(AGENT_ID, keccak256("r1"), keccak256("p1"), "");
        vault.attest(AGENT_ID, keccak256("r2"), keccak256("p1"), "");
        vault.attest(AGENT_ID, keccak256("r3"), keccak256("p2"), "");

        assertEq(vault.totalAttestations(), 3);
        assertEq(vault.agentAttestationCount(AGENT_ID), 3);
    }

    function test_isAttested() public {
        bytes32 h = keccak256("receipt-check");
        assertFalse(vault.isAttested(h));

        vault.attest(AGENT_ID, h, keccak256("p"), "");
        assertTrue(vault.isAttested(h));
    }

    function test_revert_emptyHash() public {
        vm.expectRevert("Empty receipt hash");
        vault.attest(AGENT_ID, bytes32(0), keccak256("p"), "");
    }

    function test_revert_duplicate() public {
        bytes32 h = keccak256("dup-receipt");
        vault.attest(AGENT_ID, h, keccak256("p"), "");

        vm.expectRevert("Already attested");
        vault.attest(AGENT_ID, h, keccak256("p"), "");
    }

    function test_verify_reverts_nonexistent() public {
        vm.expectRevert("Not attested");
        vault.verify(keccak256("nope"));
    }

    function test_multipleAgents() public {
        uint256 agent2 = 99999;
        vault.attest(AGENT_ID, keccak256("r-tiamat"), keccak256("p"), "");
        vault.attest(agent2, keccak256("r-other"), keccak256("p"), "");

        assertEq(vault.agentAttestationCount(AGENT_ID), 1);
        assertEq(vault.agentAttestationCount(agent2), 1);
        assertEq(vault.totalAttestations(), 2);
    }

    function test_getAgentScore() public {
        assertEq(vault.getAgentScore(AGENT_ID), 0);
        vault.attest(AGENT_ID, keccak256("s1"), keccak256("p"), "");
        vault.attest(AGENT_ID, keccak256("s2"), keccak256("p"), "");
        assertEq(vault.getAgentScore(AGENT_ID), 2);
    }

    function test_emptyIpfsCid() public {
        bytes32 h = keccak256("no-ipfs");
        vault.attest(AGENT_ID, h, keccak256("p"), "");
        VaultAttestation.Attestation memory a = vault.verify(h);
        assertEq(bytes(a.ipfsCid).length, 0);
    }

    function test_event_emitted() public {
        bytes32 rh = keccak256("event-test");
        bytes32 ph = keccak256("policy-event");
        string memory cid = "QmTest";

        vm.expectEmit(true, true, false, true);
        emit VaultAttestation.ScrubAttested(rh, AGENT_ID, ph, address(this), cid);

        vault.attest(AGENT_ID, rh, ph, cid);
    }
}
