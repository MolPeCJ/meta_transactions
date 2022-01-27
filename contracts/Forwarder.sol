// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Forwarder
 * @author MolPeCJ
 * @dev Simple forwarder for extensible meta-transaction forwarding
 */

contract Forwarder is Ownable, EIP712 {
    using ECDSA for bytes32;

    struct ForwardRequest {
        address from;       // Externally-owned account making the request
        address to;         // Destination address, normally a smart contract
        uint256 value;      // Amount of ether to transfer to the destination
        uint256 gas;        // Amount of gas limit to set for the execution
        uint256 nonce;      // On-chain tracked nonce of a transaction
        bytes data;         // Data to be sent to the destination
    }

    /// @dev The _TYPEHASH is designed to turn into a compile time constant in Solidity
    bytes32 private constant _TYPEHASH = keccak256("ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data)");

    mapping(address => uint256) private _nonces;
    mapping(address => bool) private _senderWhitelist;

    event MetaTransactionExecuted(address indexed from, address indexed to, bytes indexed data);
    event AddressWhitelisted(address indexed sender);
    event AddressRemovedFromWhitelist(address indexed sender);

    /**
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     */
    constructor(string memory name, string memory version) EIP712(name, version) {
        address msgSender = msg.sender;
        addSenderToWhitelist(msgSender);
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function getNonce(address from) public view returns (uint256) {
        return _nonces[from];
    }

    function verify(ForwardRequest calldata req, bytes calldata signature) public view returns (bool) {
        address signer = _hashTypedDataV4(keccak256(abi.encode(
            _TYPEHASH,
            req.from,
            req.to,
            req.value,
            req.gas,
            req.nonce,
            keccak256(req.data)
        ))).recover(signature);
        return _nonces[req.from] == req.nonce && signer == req.from;
    }

    function execute(ForwardRequest calldata req, bytes calldata signature) public payable returns (bool, bytes memory) {
        require(_senderWhitelist[msg.sender], "Forwarder: sender of meta-transaction is not whitelisted");
        require(verify(req, signature), "Forwarder: signature does not match request");
        _nonces[req.from] = req.nonce + 1;

        (bool success, bytes memory returndata) = req.to.call(abi.encodePacked(req.data, req.from));
        
        if (!success) {
            assembly {
            returndatacopy(0, 0, returndatasize())
            revert(0, returndatasize())
            }
        }

        emit MetaTransactionExecuted(req.from, req.to, req.data);

        return (success, returndata);
    }

    function addSenderToWhitelist(address sender) public onlyOwner() {
        require(!isWhitelisted(sender), "Forwarder: sender address is already whitelisted");
        _senderWhitelist[sender] = true;
        emit AddressWhitelisted(sender);
    }

    function removeSenderFromWhitelist(address sender) public onlyOwner() {
        _senderWhitelist[sender] = false;
        emit AddressRemovedFromWhitelist(sender);
    }

    function isWhitelisted(address sender) public view returns (bool) {
        return _senderWhitelist[sender];
    }
}