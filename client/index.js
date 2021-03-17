const readline = require('readline');
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
const fs = require('fs');
const chalk = require('chalk');
const crypto = require('crypto');
const Version = 0001
const randomWords = require('random-words')
const promptsync = require('prompt-sync')();
var PROGRAM_INITALISED = false;
var DECRYPTION_KEY = "";
console.clear();

function ExitProgram(message = "exit") {
    console.log(chalk.yellowBright(message))
    RequestServerDisconnect()
    process.exit()
}

function ProgramError(ErrorName, ErrorMessage) {
    console.log(`${chalk.redBright("[" + ErrorName + "]")} ${chalk.whiteBright(ErrorMessage)}`);
    ExitProgram("Program exited on error.");
}

if (!fs.existsSync('./config.js')) {
    ProgramError("MISSING_CONFIG_FILE", "Missing config file: this is needed for this program to function")
}
var config = require('./config');
var ENCRYPT_DATA = config.ENCRYPT_DATA;

function isAppropriatePeerID(providedID) {
    if (providedID == config.C2CC_ID) {
        console.log("isAppropriatePeerID(): failed check: " + `${providedID} (peerID) is the same as ${config.C2CC_ID} (C2CC_ID)`)
        return false;
    }
    if (providedID === null || providedID === undefined) {
        console.log("isAppropriatePeerID(): failed check: " + `${providedID} (peerID) is null or undefined`)
        return false;
    }
    return true;
}

if (ENCRYPT_DATA === null || ENCRYPT_DATA === undefined) {
    ProgramError("MISSING_CONFIG_VALUE", "Please configure the 'ENCRYPT_DATA' setting in the config file.")
}

function hashString(data) {
    return crypto.createHash("sha512").update(data, "binary").digest("base64");
}
if (ENCRYPT_DATA) {
    if (!fs.existsSync(process.cwd()+config.MASTER_HASH_LOC)) {
        var KeyInput = promptsync("Create a master key to encrypt and decrypt your server data: ", {echo: "*"});
        if (KeyInput === undefined || KeyInput === null) {
            console.log("Malformed input. Exiting...");
            process.exit();
        }
        KeyInput = KeyInput.trim();
        if (KeyInput == "") {
            console.log("Input cannot be empty. Exiting...");
            process.exit();
        }
        InputHash = hashString(KeyInput);
        fs.writeFileSync(process.cwd() + config.MASTER_HASH_LOC, InputHash);
        InputBuffer = Buffer.from(KeyInput, 'utf-8');
        if (InputBuffer.length < 32) {
            var PaddingBufferLength = 32 - InputBuffer.length;
            var PaddingBuffer = Buffer.alloc(PaddingBufferLength);
            var TotalBufferLength = InputBuffer.length + PaddingBuffer.length;
            DECRYPTION_KEY = Buffer.concat([InputBuffer, PaddingBuffer], TotalBufferLength);
        } else if (InputBuffer.length > 32) {
            var RemovalBytes = InputBuffer.length - 32;
            DECRYPTION_KEY = InputBuffer.slice(0, InputBuffer.length - RemovalBytes);
        } else {
            DECRYPTION_KEY = InputBuffer
        }
        //DECRYPTION_KEY = Buffer.from(input, 'utf-8');
    } else {
        var KeyInput = promptsync("Enter server master key: ", {echo: "*"});
        if (KeyInput === undefined || KeyInput === null) {
            console.log("Malformed input. Exiting...");
            process.exit();
        }
        KeyInput = KeyInput.trim();
        if (KeyInput == "") {
            console.log("Input cannot be empty. Exiting...");
            process.exit();
        }
        InputHash = hashString(KeyInput);
        const CorrectInputHash = fs.readFileSync(process.cwd() + config.MASTER_HASH_LOC, 'utf-8');
        if (CorrectInputHash == InputHash) {
            console.log("Key correct!");
            InputBuffer = Buffer.from(KeyInput, 'utf-8');
            if (InputBuffer.length < 32) {
                var PaddingBufferLength = 32 - InputBuffer.length;
                var PaddingBuffer = Buffer.alloc(PaddingBufferLength);
                var TotalBufferLength = InputBuffer.length + PaddingBuffer.length;
                DECRYPTION_KEY = Buffer.concat([InputBuffer, PaddingBuffer], TotalBufferLength);
            } else if (InputBuffer.length > 32) {
                var RemovalBytes = InputBuffer.length - 32;
                DECRYPTION_KEY = InputBuffer.slice(0, InputBuffer.length - RemovalBytes);
            } else {
                DECRYPTION_KEY = InputBuffer
            }
        } else {
            console.log("Incorrect key :(");
            process.exit();
        }
    }
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
    return obfuscateStringByUUID(string, uuid, true); // run obfuscate on reverse, with a minus.
}

var aesjs = require('aes-js');

var encryptKey = function(toEncrypt, pubkey) {
    try {
        var publicKey = pubkey;
        var buffer = Buffer.from(toEncrypt);
        var encrypted = crypto.publicEncrypt({key: publicKey}, buffer);
        return encrypted.toString("base64");
    } catch (e) {
        console.log(chalk.redBright("EncryptKey: error: ") + e.message);
        return;
    }
};

var decryptKey = function(toDecrypt, pubkey) {
    try {
        var privateKey = pubkey;
        var buffer = Buffer.from(toDecrypt, "base64");
        var decrypted = crypto.privateDecrypt({key: privateKey}, buffer);
        //return decrypted.toString("hex");
        return Buffer.from(decrypted, "hex")
    } catch (e) {
        console.log(chalk.redBright("DecryptKey: error: ") + e.message);
        return;
    }
};
function encrypt(text, password){
    try {
        var textBytes = aesjs.utils.utf8.toBytes(text);
        var aesCtr = new aesjs.ModeOfOperation.ctr(password);
        var encryptedBytes = aesCtr.encrypt(textBytes);
        return aesjs.utils.hex.fromBytes(encryptedBytes);
    } catch (e) {
        console.log(chalk.redBright("AES-Encrypt: error: ") + e.message);
        return;
    }
}
function createEncryptedPacket(packetdata, publickey) {
    try {
        var password = crypto.randomBytes(32);
        packetdata = JSON.stringify(packetdata)
        const encrypted_pck_dat = encrypt(packetdata, password);
        const packet = {
            packetdata: encrypted_pck_dat,
            enc_key: encryptKey(password, publickey),
        }
        return packet
    } catch (e) {
        console.log(chalk.redBright("CreateEncryptedPacket: error: ") + e.message);
        return;
    }
}
function decrypt(text, password){
    try {
        var encryptedBytes = aesjs.utils.hex.toBytes(text);
        var aesCtr = new aesjs.ModeOfOperation.ctr(password);
        var decryptedBytes = aesCtr.decrypt(encryptedBytes);
        return aesjs.utils.utf8.fromBytes(decryptedBytes);
    } catch (e) {
        console.log(chalk.redBright("AES-Decrypt: error: ") + e.message);
        return;
    }
}
function decryptEncryptedPacket(encrypted_packet, privateKey) {
    try {
        var password = decryptKey(encrypted_packet.enc_key, privateKey)
        //console.log(encrypted_packet.packetdata)
        var StringObj = decrypt(encrypted_packet.packetdata, password)
        return JSON.parse(StringObj)
    } catch (e) {
        console.log(chalk.redBright("DecryptEncryptedPacket: error: ") + e.message);
        return;
    }
}

function getServerList() {
    if (fs.existsSync(process.cwd() + "/" + config.SRVR_UUID)) {
        if (ENCRYPT_DATA) {
            var encryptedData = fs.readFileSync(process.cwd() + "/" + config.SRVR_UUID, 'utf-8');
            var decryptedData = decrypt(encryptedData, DECRYPTION_KEY);
            return JSON.parse(decryptedData);
        } else {
            return JSON.parse(fs.readFileSync(process.cwd() + "/" + config.SRVR_UUID));
        }
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
    if (ENCRYPT_DATA) {
        var decryptedData = JSON.stringify(ExistingList);
        var encryptedData = encrypt(decryptedData, DECRYPTION_KEY);
        fs.writeFileSync(process.cwd() + "/" + config.SRVR_UUID, encryptedData);
    } else {
        fs.writeFileSync(process.cwd() + "/" + config.SRVR_UUID, ExistingList);
    }
}

function saveUUID(uuid) {
    var ExistingList = getServerList();
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT);
    const data = {
        UUID: uuid,
        PUBKEY: null
    }
    ExistingList[SERVER_ENTRY] = data;
    if (ENCRYPT_DATA) {
        var decryptedData = JSON.stringify(ExistingList);
        var encryptedData = encrypt(decryptedData, DECRYPTION_KEY);
        fs.writeFileSync(process.cwd() + "/" + config.SRVR_UUID, encryptedData);
    } else {
        fs.writeFileSync(process.cwd() + "/" + config.SRVR_UUID, ExistingList);
    }
}

if (!fs.existsSync('./data/')) {
    fs.mkdirSync('./data/')
}


config.C2CC_ID = config.C2CC_ID.trim()
function cleanStr(c) {
    return c.replace(/[^A-Za-z0-9_]/g,"");
}
var SERVER_DETAILS = {
    IP: null,
    PORT: null
}

var HOSTNAME = config.HOSTNAME; 
if (HOSTNAME.trim() == "" || HOSTNAME === undefined) {
    ProgramError("MISSING_CONFIG_VALUE", "Please add a HOSTNAME value to config.js")
}

console.log(`${chalk.magentaBright('Welcome to C2CC!')}\n\n${chalk.yellowBright('How do you want to connect?')}\n${chalk.greenBright('U')}se server from config\n${chalk.greenBright('E')}nter own server details\n`)
function FirstBootChoice() {
    var Input = promptsync('Enter U or E: ');
    try {
        if (Input.trim().toLowerCase() == "u") {
            var SERVER_ADDRESS = config.SERVER_ADDR;
            if (SERVER_ADDRESS.trim() == "" || SERVER_ADDRESS === undefined) {
                ProgramError("MISSING_CONFIG_VALUE", "Please add a SERVER_ADDR value to config.js for the program to connect to a server")
            }
            if (SERVER_ADDRESS.includes(":")) {
                SERVER_ADDRESS = SERVER_ADDRESS.split(":");
                SERVER_DETAILS.IP = "http://" + SERVER_ADDRESS[0];
                SERVER_DETAILS.PORT = Number(SERVER_ADDRESS[1]);
            } else {
                SERVER_DETAILS.IP = "http://" + SERVER_ADDRESS;
                SERVER_DETAILS.PORT = 6162;
            }
        } else if (Input.trim().toLowerCase() == "e") {
            var ServerName = "";
            function getURL() {
                ServerName = promptsync('Enter server address (exclude http://): ');
            }
            var ServerPort = "";
            function getPort() {
                ServerPort = promptsync('Enter server port: ');
            }
            getURL();
            if (ServerName === null || ServerName === undefined) {
                ExitProgram();
            }
            getPort();
            if (ServerPort === null || ServerPort === undefined) {
                ExitProgram();
            }
            if (ServerName.trim() == "") {
                console.log(`${chalk.redBright('X')} Input cannot be blank`);
                return getURL();
            }
            if (ServerPort.trim() == "") {
                console.log(`${chalk.redBright('X')} Input cannot be blank`);
                return getPort();
            }
            if (isNaN(ServerPort)) {
                console.log(`${chalk.redBright('X')} Input must be a number`);
                return getPort();
            }
            if (ServerName === null || ServerName === undefined || ServerPort === null || ServerPort === undefined) {
                ExitProgram();
            }
            SERVER_DETAILS.IP = "http://" + ServerName;
            SERVER_DETAILS.PORT = Number(ServerPort);
        } else {
            console.log(`${chalk.yellowBright('?')} Unknown input`);
            return FirstBootChoice();
        }
    } catch {
        ExitProgram()
    }
}
if (config.GIVE_SRVR_CHOICE) {
    FirstBootChoice();
} else {
    var SERVER_ADDRESS = config.SERVER_ADDR;
    if (SERVER_ADDRESS.trim() == "" || SERVER_ADDRESS === undefined) {
        ProgramError("MISSING_CONFIG_VALUE", "Please add a SERVER_ADDR value to config.js for the program to connect to a server")
    }
    if (SERVER_ADDRESS.includes(":")) {
        SERVER_ADDRESS = SERVER_ADDRESS.split(":");
        SERVER_DETAILS.IP = "http://" + SERVER_ADDRESS[0];
        SERVER_DETAILS.PORT = Number(SERVER_ADDRESS[1]);
    } else {
        SERVER_DETAILS.IP = "http://" + SERVER_ADDRESS;
        SERVER_DETAILS.PORT = 6162;
    }
}
var PEER_SERVER_ID = null;
var PEER_PUBLIC_KEY = null;
var PEER = "none";
var TALKING_TO_PEER = false;
const FRIENDS_LIST_FILE = config.FRIENDS_LIST;

function loadFriendList() {
    if (!fs.existsSync(FRIENDS_LIST_FILE)) {
        if (ENCRYPT_DATA) {
            var DecryptedData = [];
            var EncryptedData = encrypt(JSON.stringify(DecryptedData), DECRYPTION_KEY);
            fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, EncryptedData);
        } else {
            fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, "[]");
        }
    }
    if (ENCRYPT_DATA) {
        var EncryptedData = fs.readFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, 'utf-8');
        var DecryptedData = decrypt(EncryptedData,  DECRYPTION_KEY)
        return JSON.parse(DecryptedData)
    } else {
        return JSON.parse(fs.readFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, 'utf-8'))
    }
}

function addFriend(friendID) {
    if (!isAppropriatePeerID(friendID)) {
        console.log(chalk.redBright('Add Friend: error: ') + "failed check isAppropriatePeerID()");
        return;
    }
    if (friendID == null || friendID == undefined) {
        console.log(chalk.redBright('Add Friend: error: ') + "Unspecified friendID");
        return;
    }
    var friendslist = loadFriendList();
    friendslist.push(friendID);
    if (ENCRYPT_DATA) {
        var DecryptedData = JSON.stringify(friendslist);
        fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, encrypt(DecryptedData, DECRYPTION_KEY))
    } else {
        fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, JSON.stringify(friendslist));
    }
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

function getFriendsList() { // Alias for loadFriendList();
    return loadFriendList();
}

function removeFriend(friendID) {
    if (!isAppropriatePeerID(friendID)) {
        console.log(chalk.redBright('Add Friend: error: ') + "failed check isAppropriatePeerID()");
        return;
    }
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
    if (ENCRYPT_DATA) {
        var DecryptedData = JSON.stringify(friendslist);
        fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, encrypt(DecryptedData, DECRYPTION_KEY))
    } else {
        fs.writeFileSync(process.cwd() + "/" + FRIENDS_LIST_FILE, JSON.stringify(friendslist));
    }
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
    if (Command == "disconnect-server") {
        RequestServerDisconnect();
        return;
    }
    if (Command == "discon" || Command == "disconnect") {
        requestDisconnectFromMe()
        return;
    }
    if (Command == "conn" || Command == "connect") {
        ConnectToPeer(Args[0]);
        return;
    }
    if (Command == "show-config") {
        console.log(config);
        return;
    }
    throwErr("command not found")
    return;
}

async function input(prompt) {
    process.stdout.write(prompt);
    rl.setPrompt(prompt);
    return (await rl[Symbol.asyncIterator]().next()).value;
}

async function prompt(inputMessage = `${chalk.greenBright(`[${HOSTNAME}/${PEER}]`)}: `) {
    if (TALKING_TO_PEER) {
        inputMessage = "> ";
    }
    var UserInput = await input(inputMessage);
    if (UserInput === null || UserInput === undefined) { 
        ExitProgram();
    }
    if (TALKING_TO_PEER) {
        process.stdout.write("\r   \r");
    }
    UserInput = UserInput.trim();
    if (UserInput == "") return prompt();
    if (TALKING_TO_PEER) {
        if (UserInput.startsWith(config.CHAT_COMMAND_PREFIX)) {
            const Command = UserInput.replace(config.CHAT_COMMAND_PREFIX,'');
            var Args = []
            if (!UserInput.replace(Command, "").trim() == "") {
                Args = UserInput.replace(Command, "").trim().split(" ");
            }
            parser(Command, Args);
            return;
        }
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

console.log(`${chalk.magentaBright('If you lose your prompt (the command finished but the prompt does not return) press ENTER')}`)

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
const { Client } = require('socket.io/dist/client');
const socket = io(`${SERVER_DETAILS.IP}:${SERVER_DETAILS.PORT}`, {
    timeout: 10000,
    query: "userid=" + config.C2CC_ID
});
socket.connect()

// Runtime flags
var flags = {
    PEER_CONNECT_TIMEOUT: null,
    PEER_ACCEPT_VERIF_STRING: null,
    IGNORE_CONN_RESPONSE: false,
    PEER_CONN_REQ_IN_PROGRESS: false,
    PEER_CONN_REQ_SENT: false,
    MSG_SENT_VERIF_STRING: null,
    MSG_SEND_TIMEOUT: null
}


const USER_C2CC_ID = config.C2CC_ID;
var UUID = null;
if (fs.existsSync(process.cwd() + "/" + config.SRVR_UUID)) {
    var UUID_LIST = getServerList();
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
    try {
        UUID = UUID_LIST[SERVER_ENTRY].UUID;
    } catch {
        UUID = null
    }
}
const ServerConnectionData = {
    SockID: USER_C2CC_ID,
    SockPubKey: publicKey,
    MyUUID: UUID,
    Version: Version,
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
    saveUUID(JSON.stringify(data.uuid));
    savePublicKey(data.pubkey);
    console.log(`\n${chalk.greenBright('Connected to server as')} ${chalk.whiteBright(config.C2CC_ID)}`);
    var ServerName = data.servername;
    var MOTD = data.motd;
    console.log(`Server name: ${chalk.magentaBright(ServerName)}\nMessage of the day: ${chalk.magentaBright(MOTD)}\n`)
    //var one = obfuscateStringByUUID("test")
    //var two = deObfuscateStringByUUID(one)
    //console.log(one, two)
    PROGRAM_INITALISED = true
    prompt();
})

socket.on('peer_conn_res', function(Encdata) {
    if (flags.IGNORE_CONN_RESPONSE) {
        flags.IGNORE_CONN_RESPONSE = false;
        return;
    }
    flags.PEER_CONN_REQ_SENT = false;
    clearTimeout(flags.PEER_CONNECT_TIMEOUT)
    const data = decryptEncryptedPacket(Encdata, privateKey);
    if (data.vstring !== flags.PEER_ACCEPT_VERIF_STRING) {
        console.log(chalk.redBright("\nConnectToPeer: error: ") + "Inconsistent data - someone may have tampered with the data.")
        prompt();
        return;
    }
    if (data.acc == false) {
        console.log(chalk.redBright("\nConnectToPeer: error: ") + "ConnectionRequest was denied by peer. Reason: " + data.reason)
        prompt();
        return;
    } else {
        TALKING_TO_PEER = true;
        PEER_SERVER_ID = data.responseFrom;
        PEER_PUBLIC_KEY = data.peerPublicKey;
        PEER = PEER_SERVER_ID;
        console.log(chalk.greenBright("\nConnected to " + PEER_SERVER_ID));
        console.log(chalk.magentaBright("\nYou are in chat mode. Anything you send will be interpreted as a message and will be sent to the peer.\nTo do a command, begin your command with a '"+config.CHAT_COMMAND_PREFIX+"'\nTo disconnect from the peer, do '"+config.CHAT_COMMAND_PREFIX+"disconnect'\n"))
        prompt("chat:" + PEER_SERVER_ID + "> ");
    }
})


socket.on('disconnect_from_user', function(Encdata) {
    const data = decryptEncryptedPacket(Encdata, privateKey);
    if (TALKING_TO_PEER && PEER_SERVER_ID == data.PeerID) {
        TALKING_TO_PEER = false;
        PEER_SERVER_ID = null;
        PEER_PUBLIC_KEY = null;
        PEER = "none";
        console.log(chalk.redBright('Disconnected from ' + data.PeerID));
        prompt();
    } else {
        return;
    }
})

socket.on('server_peerConn_req', async function(data) {
    if (flags.PEER_CONN_REQ_IN_PROGRESS) {
        return;
    }
    flags.PEER_CONN_REQ_IN_PROGRESS = true;
    const user = data.userID;
    const FriendsList = loadFriendList();
    const HandlingMethod = config.PEER_CONN_HANDLING;
    const ServerList = getServerList();
    const SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
    const PUBKEY = ServerList[SERVER_ENTRY].PUBKEY;
    var ResponseData = {
        response: "deny",
        reason: "Unable to understand your request, try again later."
    };
    if (HandlingMethod == "SYNC") {
        if (TALKING_TO_PEER) {
            ResponseData = {
                response: "deny",
                reason: "The user is talking to someone else and is using Synchronous Communication"
            }
        } else {
            if (FriendsList.includes(user)) {
                ResponseData = {
                    response: "allow",
                    reason: ""
                }
                var AcceptInput = true;
                rl.pause()
                var TimeBefore = new Date().getTime();
                var Input = promptsync(`\n${chalk.magentaBright('ConnectionRequest')}: ${user} wants to connect to you.\nConnect to ${user}? y/n: `)
                var TimeAfter = new Date().getTime();
                rl.resume()
                if (eval(Number(TimeAfter) - Number(TimeBefore)) > 8000) {
                    console.log(chalk.redBright('Error:') + " Could not connect: Sorry, you took too long to respond :(");
                    AcceptInput = false;
                }
                if (Input.trim().toLowerCase() == "y") {
                    if (AcceptInput) {
                        const data = decryptEncryptedPacket(data.encData, privateKey);
                        const pubkey = data.pubKey;
                        TALKING_TO_PEER = true;
                        PEER_SERVER_ID = user;
                        PEER_PUBLIC_KEY = pubkey;
                        PEER = user;
                        console.log(chalk.greenBright('Connected to ' + user));
                        console.log(chalk.magentaBright("\nYou are in chat mode. Anything you send will be interpreted as a message and will be sent to the peer.\nTo do a command, begin your command with a '"+config.CHAT_COMMAND_PREFIX+"'\nTo disconnect from the peer, do '"+config.CHAT_COMMAND_PREFIX+"disconnect'\n"))
                        prompt("chat:" + PEER_SERVER_ID + "> ");
                    } else {
                        ResponseData = {
                            response: "deny",
                            reason: "User denied connection request"
                        }
                    }
                } else {
                    ResponseData = {
                        response: "deny",
                        reason: "User denied connection request"
                    }
                    console.log("Abort.")
                }
            } else {
                ResponseData = {
                    response: "deny",
                    reason: "You are not in the user's friends list."
                }
            }
        }
    }
    socket.emit("peerConn_res", createEncryptedPacket(ResponseData, PUBKEY));
    flags.PEER_CONN_REQ_IN_PROGRESS = false;
    prompt();
})

function ConnectToPeer(PeerID) {
    flags.IGNORE_CONN_RESPONSE = false;
    if (!isAppropriatePeerID(PeerID)) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "The PeerID failed check 'isAppropriatePeerID()'.")
        return;
    }
    if (flags.PEER_CONN_REQ_SENT) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "You are already trying to connect to someone.");
        prompt();
        return;
    }
    if (TALKING_TO_PEER) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "You are already connected to a peer. Disconnect from them first");
        prompt();
        return;
    }
    if (PeerID === undefined || PeerID === null) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "Need a PeerID argument.");
        prompt();
        return;
    }
    const FriendsList = loadFriendList();
    if (!FriendsList.includes(PeerID)) {
        console.log(chalk.redBright('ConnectToPeer: error: ') + "You can't connect to someone who is not in your friends list, or they cannot respond to you.\nDo: "+ chalk.magentaBright('add-friend ' + PeerID));
        prompt();
        return;
    }
    process.stdout.write(chalk.whiteBright("Sending a connect request..."))
    const PeerConnectData = {
        MyID: config.C2CC_ID,
        ConnectToID: PeerID,
        AcceptVerifString: randomWords({ min: 3, max: 10, join: ' ' })
    }
    flags.PEER_ACCEPT_VERIF_STRING = PeerConnectData.AcceptVerifString;
    const ServerList = getServerList();
    var SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
    var PUBKEY = ServerList[SERVER_ENTRY].PUBKEY;
    const EncryptedData = createEncryptedPacket(PeerConnectData, PUBKEY);
    //console.log(EncryptedData)
    socket.emit("peer_conn_req", EncryptedData)
    flags.PEER_CONN_REQ_SENT = true;
    process.stdout.write(chalk.greenBright(' done!') + "\nIt may take up to 10 seconds for a request to be accepted.\n")
    flags.PEER_CONNECT_TIMEOUT = setTimeout(function(){console.log(chalk.redBright('\nConnectToPeer: error: ') + "No response to connection request, did we lose connection?"); flags.IGNORE_CONN_RESPONSE = true; prompt(); flags.PEER_CONN_REQ_SENT = false; return; },10000);
    //prompt();
}

socket.on('_sentMessage_', function(messageData) {
    if (TALKING_TO_PEER) {
        if (PEER_SERVER_ID == messageData.PeerID) {
            if (PEER_PUBLIC_KEY == messageData.PeerPubKey) {
                const ServerToClient = decryptEncryptedPacket(messageData.encrypted, privateKey);
                const ClientToClient = decryptEncryptedPacket(ServerToClient, privateKey);
                if (ClientToClient.PeerID !== messageData.PeerID || ClientToClient.PeerPubKey !== messageData.PeerPubKey) {
                    return;
                }
                if (ClientToClient.PacketType == "MESSAGE") {
                    const ReSendData = {
                        PeerID: config.C2CC_ID,
                        PeerPubKey: publicKey,
                        PacketType: "VERIF_ACKNOWLEDGEMENT",
                        PacketContents: ClientToClient.Acknowledgement,
                        Acknowledgement: ""
                    }
                    const ClientToClient2 = createEncryptedPacket(ReSendData, PEER_PUBLIC_KEY);
                    const ServerData = {
                        PeerID: PEER_SERVER_ID,
                        EncryptedClientData: ClientToClient2
                    }
                    const ServerList = getServerList();
                    const SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
                    const PUBKEY = ServerList[SERVER_ENTRY].PUBKEY;
                    const ClientToServer = createEncryptedPacket(ServerData, PUBKEY);
                    socket.emit("SendMessageToClient", ClientToServer);
                    var DateObject = new Date();
                    var Obj = DateObject.getHours() + ":" + DateObject.getMinutes();
                    Obj = Obj.replace(/\b(\d{1})\b/g, '0$1')
                    console.log("\n[" + Obj + "] " + chalk.magentaBright('['+PEER_SERVER_ID+']: ') + ClientToClient.PacketContents);
                    prompt("chat:" + PEER_SERVER_ID + "> ");
                } else if (ClientToClient.PacketType == "VERIF_ACKNOWLEDGEMENT") {
                    const ReturnedVerifString = ClientToClient.PacketContents;
                    if (ReturnedVerifString == flags.MSG_SENT_VERIF_STRING) {
                        clearTimeout(flags.MSG_SEND_TIMEOUT);
                    } else {
                        console.log(chalk.yellowBright("ReadSentPacketData: warning: " + "Inconsistent data - someone may have tampered with the data."))
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            return;
        }
    } else {
        return;
    }
});

function sendMessage(message) {
    if (PEER_SERVER_ID == null) {
        ProgramError("UNKNOWN_PEER_DATA", "You are trying to send a message without a destination")
    }
    if (SERVER_DETAILS.IP == null || SERVER_DETAILS.PORT == null) {
        ProgramError("UNKNOWN_SERVER_DATA", "Unknown server data -> server is required to route messages to peer")
    }
    const FriendsList = loadFriendList();
    if (!FriendsList.includes(PEER_SERVER_ID)) {
        console.log(chalk.redBright('SendMessage: error: ') + "You can't send a message to someone who is not in your friends list, or they cannot respond to you.\nDo: "+ chalk.magentaBright('add-friend ' + PeerServerID));
        return;
    }
    var DateObject = new Date();
    var Obj = DateObject.getHours() + ":" + DateObject.getMinutes();
    Obj = Obj.replace(/\b(\d{1})\b/g, '0$1')
    console.log(`[${Obj}] ${chalk.blueBright('[You]')}: ${message}`);
    const Ack = randomWords({min: 3, max: 10, join: ' '});
    flags.MSG_SENT_VERIF_STRING = Ack;
    const SendData = {
        PeerID: config.C2CC_ID,
        PeerPubKey: publicKey,
        PacketType: "MESSAGE",
        PacketContents: message,
        Acknowledgement: Ack
    }
    const ClientToClient = createEncryptedPacket(SendData, PEER_PUBLIC_KEY);
    const ServerData = {
        PeerID: PEER_SERVER_ID,
        EncryptedClientData: ClientToClient
    }
    const ServerList = getServerList();
    const SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
    const PUBKEY = ServerList[SERVER_ENTRY].PUBKEY;
    const ClientToServer = createEncryptedPacket(ServerData, PUBKEY);
    flags.MSG_SEND_TIMEOUT = setTimeout(function() {
        console.log(chalk.redBright("SendMessage: error: ") + "It seems like your message didn't go through");
        prompt();
    }, 8000)
    socket.emit("SendMessageToClient", ClientToServer);
}

function requestDisconnectFromMe() {
    if (TALKING_TO_PEER) {
        console.log("Disconnecting from " + PEER_SERVER_ID)
        const SendData = {
            MyID: config.C2CC_ID,
            PeerID: PEER_SERVER_ID
        };
        const ServerList = getServerList();
        const SERVER_ENTRY = cleanStr(SERVER_DETAILS.IP + SERVER_DETAILS.PORT)
        const PUBKEY = ServerList[SERVER_ENTRY].PUBKEY;
        socket.emit("req_discon_from_me", createEncryptedPacket(SendData, PUBKEY));
        PEER_SERVER_ID = null;
        PEER_PUBLIC_KEY = null;
        PEER = "none";
        TALKING_TO_PEER = false;
        console.log("Done.")
        prompt();
    } else {
        console.log(chalk.redBright('No-one to disconnect from!'))
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