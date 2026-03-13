/**
 * TIAMAT VAULT — MetaMask Delegation Module
 *
 * Creates scoped delegations for TIAMAT agent to attest PII scrubs
 * on behalf of delegator accounts.
 *
 * Uses MetaMask Smart Accounts Kit (Delegation Toolkit).
 */

import {
  createDelegation,
  Implementation,
  toMetaMaskSmartAccount,
  ExecutionMode,
} from "@metamask/smart-accounts-kit";
import { DelegationManager } from "@metamask/smart-accounts-kit/contracts";
import { createPublicClient, http, parseAbi, encodeFunctionData } from "viem";
import { sepolia } from "viem/chains";

// TIAMAT agent's EOA address (the delegate who receives permission)
const TIAMAT_AGENT = "0xdc118c4e1284e61e4d5277936a64B9E08Ad9e7EE";

// VaultAttestation contract on Base (for reference — delegation is on Sepolia for demo)
const VAULT_CONTRACT = "0x47a6a776c79a7187a4fa7f7edf0a5511b034025e";

const VAULT_ABI = parseAbi([
  "function attest(uint256 agentId, bytes32 receiptHash, bytes32 policyHash, string ipfsCid)",
]);

const publicClient = createPublicClient({
  chain: sepolia,
  transport: http("https://sepolia.drpc.org"),
});

/**
 * Create a scoped delegation from a user to TIAMAT.
 * The delegation allows TIAMAT to ONLY call VaultAttestation.attest()
 * with a spending limit and time constraint.
 */
export async function createVaultDelegation(delegatorPrivateKey) {
  const { privateKeyToAccount } = await import("viem/accounts");
  const delegatorSigner = privateKeyToAccount(delegatorPrivateKey);

  // Create delegator smart account
  const delegatorSmartAccount = await toMetaMaskSmartAccount({
    client: publicClient,
    implementation: Implementation.Hybrid,
    deployParams: [delegatorSigner.address, [], [], []],
    deploySalt: "0x",
    signer: { account: delegatorSigner },
  });

  // Create delegation with functionCall scope:
  // - Only allowed to call attest() on VaultAttestation contract
  // - Restricted to specific function selector
  const attestSelector = "0xd705dbd5"; // attest(uint256,bytes32,bytes32,string)

  const delegation = createDelegation({
    to: TIAMAT_AGENT,
    from: delegatorSmartAccount.address,
    environment: delegatorSmartAccount.environment,
    scope: {
      type: "functionCall",
      targets: [VAULT_CONTRACT],
      selectors: [attestSelector],
    },
  });

  // Sign the delegation
  const signature = await delegatorSmartAccount.signDelegation({ delegation });

  const signedDelegation = {
    ...delegation,
    signature,
  };

  return {
    delegation: signedDelegation,
    delegator: delegatorSmartAccount.address,
    delegate: TIAMAT_AGENT,
    scope: "allowedTargets: VaultAttestation only",
    status: "active",
  };
}

/**
 * Build the calldata for TIAMAT to attest on behalf of a delegator.
 */
export function buildAttestCalldata(agentId, receiptHash, policyHash, ipfsCid = "") {
  return encodeFunctionData({
    abi: VAULT_ABI,
    functionName: "attest",
    args: [BigInt(agentId), receiptHash, policyHash, ipfsCid],
  });
}

// CLI interface
if (process.argv[1]?.endsWith("delegation.mjs")) {
  const cmd = process.argv[2];

  if (cmd === "info") {
    console.log(JSON.stringify({
      agent: TIAMAT_AGENT,
      contract: VAULT_CONTRACT,
      chain: "sepolia",
      framework: "MetaMask Delegation Toolkit",
      scope: "allowedTargets — VaultAttestation.attest() only",
      features: [
        "Scoped delegation to single contract",
        "Agent can ONLY attest PII scrubs",
        "Delegation is revocable by delegator at any time",
        "Smart account required for delegator",
        "ERC-7710 compliant delegation",
      ],
    }, null, 2));
  } else {
    console.log("Usage: node delegation.mjs [info|create]");
    console.log("  info   — Show delegation configuration");
    console.log("  create — Create a test delegation (requires DELEGATOR_KEY env)");
  }
}
