/**
 * TIAMAT VAULT — MetaMask Delegation Module (Full E2E)
 *
 * Creates scoped delegations for TIAMAT agent to attest PII scrubs
 * on behalf of delegator accounts, using MetaMask Smart Accounts Kit.
 *
 * Bundler: Pimlico public endpoint (no API key needed)
 * Chain: Sepolia testnet
 * Framework: ERC-7710 Delegation via MetaMask Delegation Toolkit
 */

import {
  createDelegation,
  Implementation,
  toMetaMaskSmartAccount,
  ExecutionMode,
  createExecution,
  signDelegation,
  redeemDelegations,
  getSmartAccountsEnvironment,
} from "@metamask/smart-accounts-kit";
import { erc7710BundlerActions } from "@metamask/smart-accounts-kit/actions";
import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  encodeFunctionData,
  formatEther,
} from "viem";
import { createBundlerClient } from "viem/account-abstraction";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

// ─── Configuration ───────────────────────────────────────────────────

// TIAMAT agent's EOA address (the delegate who receives permission)
const TIAMAT_AGENT = "0xdc118c4e1284e61e4d5277936a64B9E08Ad9e7EE";

// VaultAttestation contract (Sepolia for delegation demo)
const VAULT_CONTRACT = "0x47a6a776c79a7187a4fa7f7edf0a5511b034025e";

const VAULT_ABI = parseAbi([
  "function attest(uint256 agentId, bytes32 receiptHash, bytes32 policyHash, string ipfsCid)",
]);

const PIMLICO_BUNDLER = "https://public.pimlico.io/v2/11155111/rpc";
const SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com";

// ─── Clients ─────────────────────────────────────────────────────────

const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(SEPOLIA_RPC),
});

// ─── Smart Account Helpers ───────────────────────────────────────────

/**
 * Create a MetaMask smart account from a private key.
 */
async function createSmartAccount(privateKey) {
  const signer = privateKeyToAccount(privateKey);

  const smartAccount = await toMetaMaskSmartAccount({
    client: publicClient,
    implementation: Implementation.Hybrid,
    deployParams: [signer.address, [], [], []],
    deploySalt: "0x",
    signer: { account: signer },
  });

  return { smartAccount, signer };
}

/**
 * Get the counterfactual address for a private key's smart account
 * (the address it WILL have once deployed, even before deployment).
 */
export async function getSmartAccountAddress(privateKey) {
  const { smartAccount } = await createSmartAccount(privateKey);
  return smartAccount.address;
}

// ─── Delegation: Create & Sign ───────────────────────────────────────

/**
 * Create a scoped delegation from a delegator to TIAMAT.
 * TIAMAT can ONLY call VaultAttestation.attest() — nothing else.
 *
 * This is an off-chain operation (EIP-712 signature only, no gas needed).
 */
export async function createVaultDelegation(delegatorPrivateKey) {
  const { smartAccount: delegatorAccount, signer } =
    await createSmartAccount(delegatorPrivateKey);

  const environment = getSmartAccountsEnvironment(sepolia.id);

  // attest(uint256,bytes32,bytes32,string) selector
  const attestSelector = "0xd705dbd5";

  // Create delegation with functionCall scope:
  // - Only VaultAttestation contract
  // - Only attest() function
  // - Zero ETH value (no transfers)
  const delegation = createDelegation({
    to: TIAMAT_AGENT,
    from: delegatorAccount.address,
    environment,
    scope: {
      type: "functionCall",
      targets: [VAULT_CONTRACT],
      selectors: [attestSelector],
    },
  });

  // Sign off-chain via EIP-712
  const signature = await signDelegation({
    privateKey: delegatorPrivateKey,
    delegation,
    delegationManager: environment.DelegationManager,
    chainId: sepolia.id,
  });

  const signedDelegation = { ...delegation, signature };

  return {
    delegation: signedDelegation,
    delegator: delegatorAccount.address,
    delegatorEOA: signer.address,
    delegate: TIAMAT_AGENT,
    delegationManager: environment.DelegationManager,
    scope: {
      contract: VAULT_CONTRACT,
      function: "attest(uint256,bytes32,bytes32,string)",
      selector: attestSelector,
      maxValue: "0 ETH",
    },
    status: "signed",
  };
}

// ─── Delegation: Redeem (TIAMAT executes on behalf of delegator) ─────

/**
 * TIAMAT redeems a delegation to call attest() on behalf of a delegator.
 * This sends a real on-chain UserOperation via the Pimlico bundler.
 *
 * @param {string} tiamatPrivateKey - TIAMAT agent's private key
 * @param {object} signedDelegation - The signed delegation from createVaultDelegation
 * @param {object} attestParams - { agentId, receiptHash, policyHash, ipfsCid }
 */
export async function redeemVaultDelegation(
  tiamatPrivateKey,
  signedDelegation,
  attestParams
) {
  const { smartAccount: tiamatAccount } =
    await createSmartAccount(tiamatPrivateKey);

  const environment = getSmartAccountsEnvironment(sepolia.id);

  // Build the attest() calldata
  const calldata = encodeFunctionData({
    abi: VAULT_ABI,
    functionName: "attest",
    args: [
      BigInt(attestParams.agentId),
      attestParams.receiptHash,
      attestParams.policyHash,
      attestParams.ipfsCid || "",
    ],
  });

  // Create bundler client with Pimlico + ERC-7710 delegation actions
  const bundlerClient = createBundlerClient({
    chain: sepolia,
    transport: http(PIMLICO_BUNDLER),
    client: publicClient,
  }).extend(erc7710BundlerActions());

  // Build execution: call attest() on VaultAttestation
  const execution = createExecution({
    target: VAULT_CONTRACT,
    value: 0n,
    callData: calldata,
  });

  // Send UserOperation that redeems the delegation
  const userOpHash = await bundlerClient.sendUserOperationWithDelegation({
    account: tiamatAccount,
    calls: [
      {
        to: environment.DelegationManager,
        data: encodeFunctionData({
          abi: parseAbi([
            "function redeemDelegations(bytes[] permissionContexts, uint256[] modes, bytes[] executionCalldatas)",
          ]),
          functionName: "redeemDelegations",
          args: [
            [[signedDelegation]], // permissionContexts
            [ExecutionMode.SingleDefault], // modes
            [[execution]], // executionCalldatas
          ],
        }),
      },
    ],
  });

  console.log("UserOperation hash:", userOpHash);

  // Wait for receipt
  const receipt = await bundlerClient.waitForUserOperationReceipt({
    hash: userOpHash,
    timeout: 60_000,
  });

  return {
    userOpHash,
    txHash: receipt.receipt.transactionHash,
    blockNumber: Number(receipt.receipt.blockNumber),
    status: receipt.receipt.status === "success" ? "success" : "reverted",
    delegator: signedDelegation.delegator,
    delegate: TIAMAT_AGENT,
    attestParams,
    sepoliaUrl: `https://sepolia.etherscan.io/tx/${receipt.receipt.transactionHash}`,
  };
}

// ─── Direct Redemption (EOA calls DelegationManager directly) ────────

/**
 * Alternative: TIAMAT's EOA directly calls DelegationManager.redeemDelegations().
 * Simpler than UserOperation approach — no bundler/smart account needed for delegate.
 */
export async function redeemDirect(
  tiamatPrivateKey,
  signedDelegation,
  attestParams
) {
  const tiamatSigner = privateKeyToAccount(tiamatPrivateKey);
  const environment = getSmartAccountsEnvironment(sepolia.id);

  const walletClient = createWalletClient({
    account: tiamatSigner,
    chain: sepolia,
    transport: http(SEPOLIA_RPC),
  });

  // Build attest calldata
  const calldata = encodeFunctionData({
    abi: VAULT_ABI,
    functionName: "attest",
    args: [
      BigInt(attestParams.agentId),
      attestParams.receiptHash,
      attestParams.policyHash,
      attestParams.ipfsCid || "",
    ],
  });

  // Use the redeemDelegations helper from the kit
  const txHash = await redeemDelegations(walletClient, publicClient, environment.DelegationManager, [
    {
      permissionContext: [signedDelegation],
      executions: [
        createExecution({
          target: VAULT_CONTRACT,
          value: 0n,
          callData: calldata,
        }),
      ],
      mode: ExecutionMode.SingleDefault,
    },
  ]);

  // Wait for tx confirmation
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: txHash,
    timeout: 60_000,
  });

  return {
    txHash,
    blockNumber: Number(receipt.blockNumber),
    status: receipt.status === "success" ? "success" : "reverted",
    delegator: signedDelegation.delegator,
    delegate: tiamatSigner.address,
    attestParams,
    sepoliaUrl: `https://sepolia.etherscan.io/tx/${txHash}`,
  };
}

// ─── Utilities ───────────────────────────────────────────────────────

export function buildAttestCalldata(
  agentId,
  receiptHash,
  policyHash,
  ipfsCid = ""
) {
  return encodeFunctionData({
    abi: VAULT_ABI,
    functionName: "attest",
    args: [BigInt(agentId), receiptHash, policyHash, ipfsCid],
  });
}

/**
 * Check balance of a Sepolia address.
 */
async function checkBalance(address) {
  const balance = await publicClient.getBalance({ address });
  return { address, balance: formatEther(balance), wei: balance.toString() };
}

// ─── CLI ─────────────────────────────────────────────────────────────

if (process.argv[1]?.endsWith("delegation.mjs")) {
  const cmd = process.argv[2];

  if (cmd === "info") {
    const env = getSmartAccountsEnvironment(sepolia.id);
    console.log(
      JSON.stringify(
        {
          agent: TIAMAT_AGENT,
          contract: VAULT_CONTRACT,
          chain: "sepolia",
          bundler: PIMLICO_BUNDLER,
          framework: "MetaMask Delegation Toolkit v0.4.0-beta.1",
          delegationManager: env.DelegationManager,
          entryPoint: env.EntryPoint,
          enforcers: {
            allowedTargets: env.caveatEnforcers.AllowedTargetsEnforcer,
            allowedMethods: env.caveatEnforcers.AllowedMethodsEnforcer,
            valueLte: env.caveatEnforcers.ValueLteEnforcer,
          },
          scope: "functionCall — VaultAttestation.attest() only",
          features: [
            "Scoped delegation to single contract + single function",
            "Zero ETH value cap (no transfers possible)",
            "Delegation is off-chain (EIP-712 signature, no gas)",
            "Revocable by delegator at any time on-chain",
            "ERC-7710 compliant",
          ],
        },
        null,
        2
      )
    );
  } else if (cmd === "create") {
    // Create a test delegation using env var
    const key = process.env.DELEGATOR_KEY || process.env.TIAMAT_WALLET_KEY;
    if (!key) {
      console.error(
        "Set DELEGATOR_KEY or TIAMAT_WALLET_KEY environment variable"
      );
      process.exit(1);
    }

    console.log("Creating scoped delegation to TIAMAT...");
    try {
      const result = await createVaultDelegation(key);
      console.log(JSON.stringify(result, null, 2));
    } catch (e) {
      console.error("Error:", e.message);
      process.exit(1);
    }
  } else if (cmd === "balance") {
    const address = process.argv[3] || TIAMAT_AGENT;
    const bal = await checkBalance(address);
    console.log(JSON.stringify(bal, null, 2));
  } else if (cmd === "test-e2e") {
    // Full end-to-end test: create delegation → redeem via direct call
    const key = process.env.TIAMAT_WALLET_KEY;
    if (!key) {
      console.error("Set TIAMAT_WALLET_KEY environment variable");
      process.exit(1);
    }

    console.log("=== E2E Delegation Test ===\n");

    // Step 1: Create delegation (delegator = TIAMAT for testing)
    console.log("Step 1: Creating scoped delegation...");
    const delegationResult = await createVaultDelegation(key);
    console.log(`  Delegator (smart account): ${delegationResult.delegator}`);
    console.log(`  Delegate: ${delegationResult.delegate}`);
    console.log(`  Scope: ${JSON.stringify(delegationResult.scope)}`);
    console.log(`  Status: ${delegationResult.status}\n`);

    // Step 2: Check balance
    console.log("Step 2: Checking balances...");
    const tiamatBal = await checkBalance(TIAMAT_AGENT);
    const delegatorBal = await checkBalance(delegationResult.delegator);
    console.log(`  TIAMAT EOA: ${tiamatBal.balance} ETH`);
    console.log(`  Delegator SA: ${delegatorBal.balance} ETH\n`);

    // Step 3: Deploy delegator smart account via bundler (if needed)
    console.log("Step 3: Deploying delegator smart account via bundler...");
    try {
      const { smartAccount: delegatorSA } = await createSmartAccount(key);
      const code = await publicClient.getCode({ address: delegatorSA.address });
      if (!code || code === "0x") {
        console.log("  Smart account not deployed yet, deploying via bundler...");
        const bundlerClient = createBundlerClient({
          chain: sepolia,
          transport: http(PIMLICO_BUNDLER),
          client: publicClient,
        });

        // Fetch current gas prices from Pimlico
        const gasPrice = await bundlerClient.request({
          method: "pimlico_getUserOperationGasPrice",
        });
        const fast = gasPrice.fast;
        console.log(`  Gas price: maxFee=${fast.maxFeePerGas}, priority=${fast.maxPriorityFeePerGas}`);

        // Send a no-op UserOperation to deploy the smart account
        const deployHash = await bundlerClient.sendUserOperation({
          account: delegatorSA,
          calls: [{ to: delegatorSA.address, value: 0n, data: "0x" }],
          maxFeePerGas: BigInt(fast.maxFeePerGas),
          maxPriorityFeePerGas: BigInt(fast.maxPriorityFeePerGas),
        });
        console.log(`  Deploy UserOp: ${deployHash}`);
        const deployReceipt = await bundlerClient.waitForUserOperationReceipt({
          hash: deployHash,
          timeout: 90_000,
        });
        console.log(`  Deploy TX: ${deployReceipt.receipt.transactionHash}`);
        console.log(`  Deploy status: ${deployReceipt.receipt.status}\n`);
      } else {
        console.log(`  Smart account already deployed at ${delegatorSA.address}\n`);
      }
    } catch (e) {
      console.error(`  Deploy error: ${e.message}`);
      console.log("  Trying redemption anyway...\n");
    }

    // Step 4: Redeem delegation (attest on behalf of delegator)
    console.log("Step 4: Redeeming delegation (direct call)...");
    try {
      const redeemResult = await redeemDirect(
        key,
        delegationResult.delegation,
        {
          agentId: 29931,
          receiptHash:
            "0x3ba9dfab9400fd38c6946b0ad1667d452c8e710f725e2fb400b1f142e8e00a74",
          policyHash:
            "0x0000000000000000000000000000000000000000000000000000000000000001",
          ipfsCid: "",
        }
      );
      console.log(`  TX: ${redeemResult.txHash}`);
      console.log(`  Block: ${redeemResult.blockNumber}`);
      console.log(`  Status: ${redeemResult.status}`);
      console.log(`  Explorer: ${redeemResult.sepoliaUrl}`);
    } catch (e) {
      console.error(`  Redemption error: ${e.message}`);
      console.log("  Trying bundler approach...\n");

      // Fallback: try the bundler-based redemption
      console.log("Step 4b: Redeeming via bundler (UserOperation)...");
      try {
        const bundlerResult = await redeemVaultDelegation(
          key,
          delegationResult.delegation,
          {
            agentId: 29931,
            receiptHash:
              "0x3ba9dfab9400fd38c6946b0ad1667d452c8e710f725e2fb400b1f142e8e00a74",
            policyHash:
              "0x0000000000000000000000000000000000000000000000000000000000000001",
            ipfsCid: "",
          }
        );
        console.log(`  TX: ${bundlerResult.txHash}`);
        console.log(`  Block: ${bundlerResult.blockNumber}`);
        console.log(`  Status: ${bundlerResult.status}`);
        console.log(`  Explorer: ${bundlerResult.sepoliaUrl}`);
      } catch (e2) {
        console.error(`  Bundler redemption error: ${e2.message}`);
      }
    }
  } else {
    console.log("TIAMAT VAULT — MetaMask Delegation Module");
    console.log("Usage: node delegation.mjs <command>\n");
    console.log("Commands:");
    console.log("  info       — Show delegation configuration & contract addresses");
    console.log("  create     — Create a test delegation (requires TIAMAT_WALLET_KEY)");
    console.log("  balance    — Check Sepolia ETH balance");
    console.log("  test-e2e   — Full end-to-end delegation test");
  }
}
