// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @dev Intentionally vulnerable vault for BALONCORE testing.
 *      Contains: reentrancy, missing access control, rounding errors,
 *      missing reentrancy guard on payable function, and donation attack.
 */
contract VulnerableVault {
    string public name = "VulnerableVault";
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public shares;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 shares);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Deposit ETH into the vault. Vulnerable to reentrancy because
     *      state is updated AFTER the external call.
     */
    function deposit() public payable {
        require(msg.value > 0, "Cannot deposit 0");

        // VULNERABILITY: State update happens after effect
        // An attacker can reenter deposit() before totalSupply is updated

        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
        totalAssets += msg.value;

        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Withdraw shares. Classic reentrancy vulnerability:
     *      balance is checked BEFORE external call, but updated AFTER.
     */
    function withdraw(uint256 _shares) public {
        uint256 userBalance = shares[msg.sender];
        require(_shares <= userBalance, "Insufficient shares");

        // VULNERABILITY: Checks-effects-interactions violation
        // External call BEFORE state update = reentrancy
        (bool success, ) = msg.sender.call{value: _shares}("");
        require(success, "Transfer failed");

        // State update AFTER external call
        shares[msg.sender] -= _shares;
        balanceOf[msg.sender] -= _shares;
        totalSupply -= _shares;
        totalAssets -= _shares;

        emit Withdraw(msg.sender, _shares);
    }

    /**
     * @dev Transfer tokens. No reentrancy guard needed here since
     *      no external call, but missing zero-address check.
     */
    function transfer(address _to, uint256 _amount) public returns (bool) {
        // VULNERABILITY: Missing check for address(0)
        balanceOf[msg.sender] -= _amount;
        balanceOf[_to] += _amount;

        emit Transfer(msg.sender, _to, _amount);
        return true;
    }

    /**
     * @dev Approve spending. No check for zero address or over-approval.
     */
    function approve(address _spender, uint256 _amount) public returns (bool) {
        // VULNERABILITY: Missing check for address(0)
        // Also allows overwriting existing approval without setting to 0 first
        allowance[msg.sender][_spender] = _amount;

        return true;
    }

    /**
     * @dev TransferFrom. No allowance check (BFLA vulnerability).
     *      This should check allowance but doesn't.
     */
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool) {
        // VULNERABILITY: Missing allowance check - anyone can transfer from anyone
        balanceOf[_from] -= _amount;
        balanceOf[_to] += _amount;

        // Should have: require(allowance[_from][msg.sender] >= _amount)
        emit Transfer(_from, _to, _amount);
        return true;
    }

    /**
     * @dev Owner-only function WITHOUT access control modifier.
     *      Anyone can call this and set arbitrary balance.
     */
    function setBalance(address _account, uint256 _balance) public {
        // VULNERABILITY: Missing onlyOwner modifier - anyone can call this
        balanceOf[_account] = _balance;
    }

    /**
     * @dev Donate ETH to the vault. This creates a rounding error attack vector.
     *      When totalAssets > totalSupply, share price is inflated.
     */
    function donate() public payable {
        // This inflates totalAssets without increasing totalSupply,
        // causing a rounding error in share conversion
        totalAssets += msg.value;
    }

    /**
     * @dev Convert assets to shares. Vulnerable to rounding.
     *      If totalAssets is inflated via donation, this returns fewer shares.
     */
    function convertToShares(uint256 _assets) public view returns (uint256) {
        // VULNERABILITY: Rounding error when totalSupply is small
        // integer division rounds down, attacker can exploit via donation
        if (totalSupply == 0) {
            return _assets;
        }
        return (_assets * totalSupply) / totalAssets;
    }

    /**
     * @dev Convert shares to assets.
     */
    function convertToAssets(uint256 _shares) public view returns (uint256) {
        if (totalSupply == 0) {
            return _shares;
        }
        return (_shares * totalAssets) / totalSupply;
    }

    receive() external payable {
        totalAssets += msg.value;
    }
}