const readline = require('readline');
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
const fs = require('fs');
const chalk = require('chalk');
const crypto = require('crypto');
const hashFile = require('hash-file');
//const Version = hashFile.sync(__filename)
const Version = "IndevTestBeta"
const VersionNumber = "1.0.0"
const randomWords = require('random-words')

function getServerList() {
    if (fs.existsSync(process.cwd() + "/" + config.SRVR_UUID)) {
        return JSON.parse(fs.readFileSync(process.cwd() + "/" + config.SRVR_UUID, 'utf-8'))
    } else {
        return {};
    }
}

function savePublicKey(key) {
    var ExistingList = getServerList();
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT);
    const data = {
        UUID: ExistingList[SERVER_ENTRY].UUID,
        PUBKEY: key
    }
    ExistingList[SERVER_ENTRY] = data;
    fs.writeFileSync(process.cwd() + "/" + config.SRVR_UUID, JSON.stringify(ExistingList));
}

function saveUUID(uuid) {
    var ExistingList = getServerList();
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT);
    const data = {
        UUID: uuid,
        PUBKEY: null
    }
    ExistingList[SERVER_ENTRY] = data;
    fs.writeFileSync(process.cwd() + "/" + config.SRVR_UUID, JSON.stringify(ExistingList));
}

const letterMap = {
    a: 0, b: 1, c: 2, d: 3, e: 4, f: 5, 
    g: 6, h: 7, i: 8, j: 9, k: 10, l: 11,
    m: 12, n: 13, o: 14, p: 15, q: 16, r: 17, 
    s: 18, t: 19, u: 20, v: 21, w: 22, x: 23, 
    y: 24, z: 25
};
let caesarCipher = function (str, key) {
    return str.toUpperCase().replace(/[A-Z]/g, c => String.fromCharCode((c.charCodeAt(0)-65 + key ) % 26 + 65));
}

function obfuscateStringByUUID(string, uuid, zeroMinus = false) {
    string = string.toLowerCase()
    //const serverlist = getServerList();
    //var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT);
    const UUID = uuid.replace(/[-]/g, "");
    var OutputString = "";
    var UUID_ITERATOR = 0;
    for (i = 0; i < string.length; i++) {
        var CaesarMap = 0;
        UUID_ITERATOR++;
        if (UUID_ITERATOR > UUID.length) {
            UUID_ITERATOR = 0;
        }
        if (isNaN(UUID[UUID_ITERATOR])) {
            CaesarMap = Number(letterMap[UUID[UUID_ITERATOR]]);
        } else {
            CaesarMap = Number(UUID[UUID_ITERATOR]);
        }
        if (zeroMinus) {
            OutputString += caesarCipher(string[i], 0 - CaesarMap)
        } else {
            OutputString += caesarCipher(string[i], CaesarMap)
        }
        //console.log(`uuid_len: ${UUID.length}, letter: ${string[i]}, uuid_it: ${UUID_ITERATOR}, CM: ${CaesarMap}, output: ${caesarCipher(string[i], CaesarMap)}`)
    }
    return OutputString;
}

function deObfuscateStringByUUID(string, uuid) {
    return obfuscateStringByUUID(string, uuid, true);
}

var aesjs = require('aes-js');

var encryptKey = function(toEncrypt, pubkey) {
    var publicKey = pubkey;
    var buffer = Buffer.from(toEncrypt);
    var encrypted = crypto.publicEncrypt({key: publicKey}, buffer);
    return encrypted.toString("base64");
};

var decryptKey = function(toDecrypt, pubkey) {
    var privateKey = pubkey;
    var buffer = Buffer.from(toDecrypt, "base64");
    var decrypted = crypto.privateDecrypt({key: privateKey}, buffer);
    //return decrypted.toString("hex");
    return Buffer.from(decrypted, "hex")
};

function createEncryptedPacket(packetdata, publickey) {
    var password = crypto.randomBytes(32);
    packetdata = JSON.stringify(packetdata)
    function encrypt(text){
        var textBytes = aesjs.utils.utf8.toBytes(text);
        var aesCtr = new aesjs.ModeOfOperation.ctr(password);
        var encryptedBytes = aesCtr.encrypt(textBytes);
        return aesjs.utils.hex.fromBytes(encryptedBytes);
    }
    const encrypted_pck_dat = encrypt(packetdata);
    const packet = {
        packetdata: encrypted_pck_dat,
        enc_key: encryptKey(password, publickey),
    }
    return packet
}

function decryptEncryptedPacket(encrypted_packet, privateKey) {
    var password = decryptKey(encrypted_packet.enc_key, privateKey)
    function decrypt(text){
        var encryptedBytes = aesjs.utils.hex.toBytes(text);
        var aesCtr = new aesjs.ModeOfOperation.ctr(password);
        var decryptedBytes = aesCtr.decrypt(encryptedBytes);
        return aesjs.utils.utf8.fromBytes(decryptedBytes);
    }
    //console.log(encrypted_packet.packetdata)
    var StringObj = decrypt(encrypted_packet.packetdata)
    return JSON.parse(StringObj)
}

function ExitProgram(message = "exit") {
    console.log(chalk.yellowBright(message))
    RequestServerDisconnect()
    process.exit()
}

function ProgramError(ErrorName, ErrorMessage) {
    console.log(`${chalk.redBright("[" + ErrorName + "]")} ${chalk.whiteBright(ErrorMessage)}`);
    ExitProgram();
}

if (!fs.existsSync('./data/')) {
    fs.mkdirSync('./data/')
}

if (!fs.existsSync('./config.js')) {
    ProgramError("MISSING_CONFIG_FILE", "Missing config file: this is needed for this program to function")
}

const config = require('./config');
function cleanStr(c) {
    return c.replace(/[^A-Za-z0-9_]/g,"");
}
var SERVER_ADDRESS = config.SERVER_ADDR;
if (SERVER_ADDRESS.trim() == "" || SERVER_ADDRESS === undefined) {
    ProgramError("MISSING_CONFIG_VALUE", "Please add a SERVER_ADDR value to config.js for the program to connect to a server")
}
var SERVER_DETAILS = {
    IP: null,
    PORT: null
}
if (SERVER_ADDRESS.includes(":")) {
    SERVER_ADDRESS = SERVER_ADDRESS.split(":");
    SERVER_DETAILS.IP = "http://" + SERVER_ADDRESS[0];
    SERVER_DETAILS.PORT = Number(SERVER_ADDRESS[1]);
} else {
    SERVER_DETAILS.IP = "http://" + SERVER_ADDRESS;
    SERVER_DETAILS.PORT = 6162;
}
var HOSTNAME = config.HOSTNAME; 
if (HOSTNAME.trim() == "" || HOSTNAME === undefined) {
    ProgramError("MISSING_CONFIG_VALUE", "Please add a HOSTNAME value to config.js")
}
var PEER_SERVER_ID = null;
var PEER_PUBLIC_KEY = null;
var PEER = "none";
var TALKING_TO_PEER = false;
const FRIENDS_LIST_FILE = config.FRIENDS_LIST;

function loadFriendList() {
    if (!fs.existsSync(FRIENDS_LIST_FILE)) {
        fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, "[]");
    }
    return JSON.parse(fs.readFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, 'utf-8'))
}

function addFriend(friendID) {
    if (friendID == null || friendID == undefined) {
        console.log(chalk.redBright('Add Friend: error: ') + "Unspecified friendID");
        return;
    }
    var friendslist = loadFriendList();
    friendslist.push(friendID);
    fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, JSON.stringify(friendslist));
    console.log(chalk.greenBright(`Friend with ID '${friendID}' added successfully!`));
}

function removeArrayItem(arr, value) {
    var i = 0;
    while (i < arr.length) {
      if (arr[i] === value) {
        arr.splice(i, 1);
      } else {
        ++i;
      }
    }
    return arr;
}

function removeFriend(friendID) {
    if (friendID == null || friendID == undefined) {
        console.log(chalk.redBright('Remove Friend: error: ') + "Unspecified friendID");
        return;
    }
    var friendslist = loadFriendList();
    if (friendslist.includes(friendID)) {
        friendslist = removeArrayItem(friendslist, friendID);
    } else {
        console.log(`That person ('${friendID}') is not in your friends list!`)
        return;
    }
    fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, JSON.stringify(friendslist));
    console.log(chalk.greenBright(`Friend with ID '${friendID}' removed successfully!`));
}

function listFriend() {
    var friendslist = loadFriendList();
    var friends = 0;
    var FriendsString = "";
    for (i = 0; i < friendslist.length; i++) {
        friends++;
        if (i !== friendslist.length && friends > 1) {
            FriendsString += ", " + friendslist[i]
        } else {
            FriendsString += friendslist[i]         
        }
    }
    if (friends == 0) {
        console.log("You do not have any friends :(\nAdd some to get started!");
    } else {
        console.log("Your friends: " + FriendsString);
    }
}

function parser(Command = "", Args = []) {
    function throwErr(ErrorName, OptionalErrorDetails = "None") {
        console.log(chalk.redBright('ERROR: ['+ErrorName+'] ') + `Passed command: ${Command}; Passed arguments: ${ReadableArgs}; Additional Error Details: ${OptionalErrorDetails}`)
    }
    var Command = Command.toLowerCase();
    var ReadableArgs = "none"
    if (Args.length == 0) {
        Args = [null];
    } else {
        ReadableArgs = Args;
    }
    if (Command == "exit") {
        ExitProgram();
        return;
    }
    if (Command == "add-friend") {
        addFriend(Args[0]);
        return;
    }
    if (Command == "remove-friend" || Command == "rem-friend") {
        removeFriend(Args[0]);
        return;
    }
    if (Command == "ls-friend" || Command == "list-friend" || Command == "friend-list") {
        listFriend();
        return;
    }
    if (Command == "clear") {
        console.clear();
        return;
    }
    if (Command == "disconnect") {
        RequestServerDisconnect();
        return;
    }
    if (Command == "conn" || Command == "connect") {
        ConnectToPeer(Args[0]);
        return;
    }
    throwErr("command not found")
    return;
}

async function input(prompt) {
    process.stdout.write(prompt);
    rl.setPrompt(prompt)
    return (await rl[Symbol.asyncIterator]().next()).value;
}

async function prompt() {
    var UserInput = await input(`${chalk.greenBright(`[${HOSTNAME}/${PEER}]`)}: `);
    if (UserInput === null || UserInput === undefined) { 
        ExitProgram();
    }
    UserInput = UserInput.trim();
    if (UserInput == "") return prompt();
    if (TALKING_TO_PEER) {
        sendMessage(UserInput);
        return prompt();
    }
    const Command = UserInput.replace(/ .*/,'');
    var Args = []
    if (!UserInput.replace(Command, "").trim() == "") {
        Args = UserInput.replace(Command, "").trim().split(" ");
    }
    parser(Command, Args);
    return prompt()
}

function setupChecks() {
    if (!fs.existsSync(".setup")) {
        console.clear()
        console.log(chalk.yellowBright(`It seems to be your first time here, welcome to C2CC, the console-based chat app!`))
        console.log(chalk.italic('All configuration for this can be edited in the "config.js" in the C2CC program directory.'))
        console.log(`\n${chalk.magentaBright("Here is your prompt:")}`)
        console.log(`${chalk.greenBright(`[${HOSTNAME}/${PEER}]`)}: `);
        var Label1 = "";
        var Label2 = "";
        var hostnameHalf = Math.floor(HOSTNAME.length / 2);
        var curdbHalf = Math.floor(PEER.length / 2);
        for (i = 0; i < HOSTNAME.length; i++) {
            if (i == hostnameHalf) {
                Label1 += chalk.yellowBright('1');
            } else {
                Label1 += " ";
            }
        }
        for (i = 0; i < PEER.length; i++) {
            if (i == curdbHalf) {
                Label2 += chalk.yellowBright('2');
            } else {
                Label2 += " ";
            }
        }
        console.log(` ${Label1} ${Label2}\n`);
        console.log(chalk.yellowBright('1') + ": This is your username, you can change this in the config")
        console.log(chalk.yellowBright('2') + ": This is the current peer you are talking to.")
        console.log(chalk.greenBright('For help in the prompt, just type "help"!'));
        fs.writeFileSync(".setup", "This file stops the welcome screen from appearing, you can remove it to make it appear again the next time the program starts")
    }
}

console.clear();
setupChecks()
console.log(`Establishing connection with '${SERVER_DETAILS.IP}:${SERVER_DETAILS.PORT}'...`);
//console.log(Version)

console.log(`${chalk.magentaBright('DEV NOTE: MAKE SURE TO MAKE THE HASHES ACTUAL FILE HASHES INSTEAD OF THE TEMPORARY INDEV HASH')}`)

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
}); 

const io = require("socket.io-client");
const socket = io(`${SERVER_DETAILS.IP}:${SERVER_DETAILS.PORT}`, {
    timeout: 10000,
    query: "userid=" + config.C2CC_ID
});
socket.connect()

// Runtime flags
const flags = {
    PEER_CONNECT_TIMEOUT: null,
    PEER_ACCEPT_VERIF_STRING: null
}

const USER_C2CC_ID = config.C2CC_ID;
var UUID = null;
if (fs.existsSync(process.cwd() + "/" + config.SRVR_UUID)) {
    var UUID_LIST = JSON.parse(fs.readFileSync(process.cwd() + "/" + config.SRVR_UUID, 'utf-8'))
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
    UUID = UUID_LIST[SERVER_ENTRY].UUID;
}
const ServerConnectionData = {
    SockID: USER_C2CC_ID,
    SockPubKey: publicKey,
    MyUUID: UUID,
    VersionHash: Version,
    VersionNumber: VersionNumber
}
socket.on('connect', function () {
    socket.emit("socket_provide_data", ServerConnectionData);
});
socket.on("connect_error", (err) => {
    var CAUSE = "Unknown"
    if (err.message == "xhr poll error") {
        CAUSE = "The server may be down or you do not have a proper internet connection";
    } else {
        CAUSE = `Generic error: ${err.message}`
    }
    ProgramError('SOCKET_ERR', 'Cannot connect to server -> ' + CAUSE);
});
socket.on("disconnect", function() {
    console.log(chalk.redBright('[Disconnect]:') + ` Disconnected from ${SERVER_DETAILS.IP}:${SERVER_DETAILS.PORT}`);
    ExitProgram("");
});
socket.on('server_warning',function(data) {
    data = data.split("{NEWLINE}");
    console.log("[Server]: " + chalk.yellowBright(data[0]));
    for (i = 1; i < data.length; i++) {
        console.log('          ' + chalk.yellowBright(data[i]))
    }
});
socket.on('server_message',function(data) {
    data = data.split("{NEWLINE}");
    console.log("[Server]: " + chalk.whiteBright(data[0]));
    for (i = 1; i < data.length; i++) {
        console.log('          ' + chalk.whiteBright(data[i]))
    }
});

socket.on('server_connection_accepted', function(Encdata) {
    const data = decryptEncryptedPacket(Encdata, privateKey);
    saveUUID(data.uuid);
    savePublicKey(data.pubkey);
    console.log(`\n${chalk.greenBright('Connected!')}`);
    var ServerName = data.servername;
    var MOTD = data.motd;
    console.log(`Server name: ${chalk.magentaBright(ServerName)}\nMessage of the day: ${chalk.magentaBright(MOTD)}\n`)
    //var one = obfuscateStringByUUID("test")
    //var two = deObfuscateStringByUUID(one)
    //console.log(one, two)
    prompt();
})

socket.on('peer_conn_res', function(Encdata) {
    clearTimeout(flags.PEER_CONNECT_TIMEOUT)
    const data = decryptEncryptedPacket(Encdata, privateKey);
    if (data.acc == false) {
        console.log(chalk.redBright("\nConnectToPeer: error: ") + "ConnectionRequest was denied by peer. Reason: " + data.reason)
        return;
    }
    if (data.vstring !== flags.PEER_ACCEPT_VERIF_STRING) {
        console.log(chalk.redBright("\nConnectToPeer: error: ") + "Inconsistent data - someone may have tampered with the data.")
        return;
    }
})

function ConnectToPeer(PeerID) {
    if (PeerID === undefined || PeerID === null) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "Need a PeerID argument.");
        return;
    }
    const FriendsList = loadFriendList();
    if (!FriendsList.includes(PeerID)) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "You can't connect to someone who is not in your friends list, or they cannot respond to you.\nDo: "+ chalk.magentaBright('add-friend ' + PeerID));
        return;
    }
    process.stdout.write(chalk.whiteBright("Sending a connect request..."))
    const PeerConnectData = {
        MyID: config.C2CC_ID,
        AcceptVerifString: randomWords({ min: 3, max: 10, join: ' ' })
    }
    flags.PEER_ACCEPT_VERIF_STRING = PeerConnectData.AcceptVerifString;
    const ServerList = getServerList();
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
    var PUBKEY = ServerList[SERVER_ENTRY].PUBKEY;
    const EncryptedData = createEncryptedPacket(PeerConnectData, PUBKEY);
    //console.log(EncryptedData)
    socket.emit("peer_conn_req", EncryptedData)
    process.stdout.write(chalk.greenBright(' done!') + "\nIt may take up to 10 seconds for a request to be accepted.\n")
    flags.PEER_CONNECT_TIMEOUT = setTimeout(function(){console.log(chalk.redBright('\nConnectToPeer: error: ') + "No response to connection request, did we lose connection?")},10000);
}

function sendMessage(message) {
    if (PeerServerID == null) {
        ProgramError("UNKNOWN_PEER_DATA", "You are trying to send a message without a destination")
    }
    if (SERVER_DETAILS.IP == null || SERVER_DETAILS.PORT == null) {
        ProgramError("UNKNOWN_SERVER_DATA", "Unknown server data -> server is required to route messages to peer")
    }
    const FriendsList = loadFriendList();
    if (!FriendsList.includes(PeerServerID)) {
        console.log(chalk.redBright('SendMessage: error: ') + "You can't send a message to someone who is not in your friends list, or they cannot respond to you.\nDo: "+ chalk.magentaBright('add-friend ' + PeerServerID));
        return;
    }
}

function RequestServerDisconnect() {
    try {
        socket.disconnect()
    } catch {
        // failed to disconnect from server
    }
}
//prompt();