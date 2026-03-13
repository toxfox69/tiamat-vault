// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/VaultAttestation.sol";

contract DeployVault is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);
        VaultAttestation vault = new VaultAttestation();
        vm.stopBroadcast();

        console.log("VaultAttestation deployed at:", address(vault));
    }
}
