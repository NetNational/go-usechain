pragma solidity >=0.4.0 <0.6.0;

import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/access/roles/SignerRole.sol";

contract CreditSystem is SignerRole{

    address public owner;
    //string public signed;

    struct UserInfo {
        address addr;
        uint creditScore;
        string cert;
        string publicKey;
        string encWithUserPubKey;
        string encWithCommPubKey;
    }

    constructor() public {
        owner = msg.sender;
    }
    
    mapping (string => UserInfo) unRegUsers;
    mapping (string => UserInfo) regUsers;
    
    function register(string memory _publicKey,
                    string memory _encWithUserPubKey,
                    string memory _encWithCommPubKey,
                    string memory _cert,
                    string memory _userId)
        public
        payable
        //onlySigner
        returns(bool) {
        //signed = signedMsg;
        address addr = msg.sender;
        unRegUsers[_userId].addr = addr;
        unRegUsers[_userId].creditScore = 0;
        unRegUsers[_userId].cert = _cert;
        unRegUsers[_userId].publicKey = _publicKey;
        unRegUsers[_userId].encWithUserPubKey = _encWithUserPubKey;
        unRegUsers[_userId].encWithCommPubKey = _encWithCommPubKey;
        return true;
    }
    
    function verify(address addr) public onlySigner {
        
    }

    function getUserInfo(string userId)
        public
        view
        returns(address, uint, string memory, string memory, string memory, string memory)
    {
        return (unRegUsers[userId].addr,
        unRegUsers[userId].creditScore,
        unRegUsers[userId].publicKey,
        unRegUsers[userId].encWithUserPubKey,
        unRegUsers[userId].encWithCommPubKey,
        unRegUsers[userId].cert);
    }
    
    //function updateScore() public {
    //    Users[msg.sender].creditScore++;
    //}
    
    //function getUserCredit(address userAddr) public view returns(uint) {
    //    return Users[userAddr].creditScore;
    //}
}