var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var chalk = require('chalk');
var { v4 } = require('uuid');
var fs = require('fs');
const path = require('path');
const promptsync = require('prompt-sync')();
const SupportedVersionNumber = 0001;
console.clear();
var homedir = require('os').homedir();

if (!fs.existsSync(homedir + "/.c2cc/")) {
    fs.mkdirSync(homedir + "/.c2cc/");
}
if (!fs.existsSync(homedir + "/.c2cc/server/")) {
    fs.mkdirSync(homedir + "/.c2cc/server/");
}
var FileDir = homedir + "/.c2cc/server/";


var ConfigLocation = FileDir + "/c2cc_server_config.js";
var StockConfig = path.join(__dirname, '/stock_cfg.js') // get pkg to package this
if (!fs.existsSync(ConfigLocation)) {
    if (!fs.existsSync(StockConfig)) {
        console.log("Error: a critical component is missing");
        process.exit();
    } else {
        fs.writeFileSync(ConfigLocation, fs.readFileSync(StockConfig, 'utf-8'))
    }
}

var d1 = fs.readFileSync(ConfigLocation, 'UTF-8');
ConfigLines = d1.split(/\r?\n/)

var d2 = fs.readFileSync(StockConfig, 'UTF-8');
StockCfgLines = d2.split(/\r?\n/)

var StockValues = [];
var MatchingLines = 0;
var ShouldWriteConfig = false;

function matchTest() {
    for (i = 0; i < StockCfgLines.length; i++) {
        var Matched = false;
        if (StockCfgLines[i].startsWith("module.exports.")) {
            var CurrentLine = "";
            var CurrentAnswer = "";
            var LogAnswer = false;
            for (i2 = 0; i2 < StockCfgLines[i].length; i2++) {
                if (LogAnswer) {
                    CurrentAnswer += StockCfgLines[i][i2];
                    continue;
                }
                if (StockCfgLines[i][i2] == " ") {
                    LogAnswer = true;
                    continue;
                }
                CurrentLine += StockCfgLines[i][i2];
            }
            CurrentLine = CurrentLine.replace("module.exports.", "");
            CurrentAnswer = CurrentAnswer.trim().replace("=", "");
            StockValues.push(CurrentLine)
            for (i4 = 0; i4 < ConfigLines.length; i4++) {
                var CurrentConfigLine = "";
                for (i3 = 0; i3 < ConfigLines[i4].length; i3++) {
                    if (ConfigLines[i4][i3] == " ") {
                        break;
                    }
                    CurrentConfigLine += ConfigLines[i4][i3];
                }
                CurrentConfigLine = CurrentConfigLine.replace("module.exports.", "");
                if (CurrentConfigLine == CurrentLine) {
                    MatchingLines++;
                    Matched = true;
                    break;
                }
            }
            if (Matched == false) {
                console.log(chalk.yellowBright("Warning!") + " no matches for value '"+CurrentLine+"'")

                // get last value before this value
                var LastValue = "";
                for (i5 = 0; i5 < StockValues.length; i5++) {
                    if (StockValues[i5] == CurrentLine) {
                        LastValue = StockValues[i5-1];
                    }
                }

                // scan file and take in the comments, starting from the last value
                var StartScan = false;
                var ScanResults = [];
                for (i6 = 0; i6 < StockCfgLines.length; i6++) {
                    if (StockCfgLines[i6].startsWith("module.exports."+LastValue+" = ")) {
                        StartScan = true;
                        continue;
                    }
                    if (StockCfgLines[i6].startsWith("module.exports."+CurrentLine+" = ")) {
                        StartScan = false;
                        break;
                    }
                    if (StartScan) {
                        ScanResults.push(StockCfgLines[i6])
                    }
                }

                // write that value to the end of config
                for (i7 = 0; i7 < ScanResults.length; i7++) {
                    ConfigLines.push(ScanResults[i7]);
                }
                ConfigLines.push("module.exports."+CurrentLine+" = "+CurrentAnswer);
                ShouldWriteConfig = true;
            }
        }
    }
    if (ShouldWriteConfig) {
        console.log("\n"+chalk.blueBright("Note: ")+"For the program to work, your config must be updated, updating will NOT remove existing config data, it will only add new config values.");
        function internalPrompt() {
            var input = promptsync("Do you want to update your config? (y/n): ");
            if (input === undefined || input === null) {
                process.exit();
            }
            if (input.trim() == "") return internalPrompt();
            if (input.trim().toUpperCase() == "Y") {
                updateConfig();
            } else if (input.trim().toUpperCase() == "N") {
                process.exit();
            } else {
                console.log(`'${input}'?`);
                return internalPrompt()
            }
        }
        internalPrompt();
    } else {
        console.log(chalk.greenBright("Yay!") + " Your config should work fine with this application.\n")
    }
}

function updateConfig(array = null) {
    var linesWritten = 0
    var Written = "";

    if (array === null) {
        array = ConfigLines
    }

    console.log("Updating config... " + chalk.yellowBright("DO NOT INTERRUPT"))
    for (i8=0;i8<array.length;i8++) {
        linesWritten++;
        process.stdout.write(chalk.blueBright("Wrote " + linesWritten + " lines\r"))
        if (array[i8] === undefined) {
            Written += "\n";
        } else {
            Written += array[i8] + "\n";
        }
    }
    fs.writeFileSync(ConfigLocation, Written)
    process.stdout.write("\n\nPlease restart the application\n")
    process.exit()
}

const Config = require(ConfigLocation);

const MAX_CONNECTIONS = Config.MAX_CONNECTIONS;
const LISTENING_PORT = Config.LISTENING_PORT;

var sockets = [];
var socketNames = {};
var SocketInformation = {};
var ConnectionSockets = [];
var BadActions = {};
var Banlist = {};
if (fs.existsSync(FileDir+"/banlist.json")) {
    Banlist = JSON.parse(fs.readFileSync(FileDir+"/banlist.json", 'utf-8'));
}

try {
    function log(reason, message) {
        if (reason == "CONNECT") {
            console.log(chalk.greenBright('[Connect]') + " " + message)
        } else if (reason == "DISCONNECT") {
            console.log(chalk.redBright('[Disconnect]') + " " + message)
        } else if (reason == "INFO") {
            console.log(chalk.gray('[Info]') + " " + message)
        } else if (reason == "WARN") {
            console.log(chalk.yellowBright('[Warning]') + " " + message)
        } else if (reason == "ERROR") {
            console.log(chalk.redBright('[Error]') + " " + message)
        } else {
            console.log(chalk.whiteBright(reason) + " " + message)
        }
    }
    console.log(`Your config is at: ${ConfigLocation}`);
    log("INFO", "Server:PreStartup -> Running match test...")
    matchTest();
    console.log("Starting C2CC Server on port " + LISTENING_PORT)
    log("INFO", "Generating keypairs...")
    const crypto = require('crypto');

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
    log("INFO", "Generated keypairs")
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
        var StringObject = decrypt(encrypted_packet.packetdata)
        return JSON.parse(StringObject);
    }

    if (!fs.existsSync(FileDir+'/users.json')) {
        fs.writeFileSync(FileDir+'/users.json', "{}")
    }
    var CURRENT_CONNECTIONS = 0;

    function hashString(data) {
        return crypto.createHash("sha256").update(data, "binary").digest("base64");
    }

    function md5(data) {
        return crypto.createHash("sha512").update(data, "binary").digest("base64");
    }

    function isNullOrUndefined(value) {
        if (value === null || value === undefined) {
            return true;
        } else {
            return false;
        }
    }

    function ConstructUntilString(time_ms = 0) {
        var remainingTime = time_ms - new Date().getTime();
        var TimeObject = {
            days: "?",
            hours: "?",
            minutes: "?"
        }
        if (!isNaN(remainingTime)) {
            if (remainingTime <= 0) {
                TimeObject.days = 0;
                TimeObject.hours = 0;
                TimeObject.minutes = 0;
            } else {
                var Days = Math.floor(remainingTime / 86400000)
                var Hours = Math.floor((remainingTime - (Days * 86400000)) / 3600000);
                var Minutes = Math.floor((remainingTime - (Hours * 3600000) - (Days * 86400000)) / 60000)
                TimeObject.days = Days;
                TimeObject.hours = Hours;
                TimeObject.minutes = Minutes;
            }
        }
        return TimeObject.days + " day(s) " + TimeObject.hours + " hour(s) " + TimeObject.minutes + " minute(s)";
    }

    function banSocket(socket, reason = "Reason not specified", duration = new Date().getTime() + 315576000000000, clientBan = false) {
        if (Config.AUTO_BAN == false && clientBan == false) {
            return;
        }
        const ip = socket.request.connection.remoteAddress;
        const IPHash = hashString(ip);
        const BannedInformation = {
            Banned: true,
            BannedFor: reason,
            BannedUntil: Number(duration)
        }
        Banlist[IPHash] = BannedInformation;
        fs.writeFileSync(FileDir+"/banlist.json", JSON.stringify(Banlist, null, 2));
        const IsBannedObject = {
            reason: reason,
            until: Number(duration)
        }
        var UntilString = ConstructUntilString(IsBannedObject.until);
        UntilString = UntilString.replace(/\b(\d{1})\b/g, '0$1')
        socket.emit("server_warning", "You are banned from the server!{NEWLINE}Banned for: " + IsBannedObject.reason + "{NEWLINE}Banned until: " + UntilString);
        socket.disconnect();
    }

    function isBanned(socket) {
        var ReturnData = {
            banned: true,
            reason: "[Server Error] Unable to get banlist information",
            until: new Date().getTime() + 315576000000000
        }
        const ip = socket.request.connection.remoteAddress;
        const IPHash = hashString(ip);
        if (isNullOrUndefined(Banlist[IPHash]) || isNullOrUndefined(Banlist[IPHash].BannedUntil) == true || isNullOrUndefined(Banlist[IPHash].BannedFor) == true || isNullOrUndefined(Banlist[IPHash].Banned) == true) {
            ReturnData.banned = false;
            ReturnData.reason = "Not banned";
            ReturnData.until = 0;
        } else {
            var NowDate = new Date().getTime();
            if (Banlist[IPHash].BannedUntil <= NowDate) {
                ReturnData.banned = false;
                ReturnData.reason = "Not banned";
                ReturnData.until = 0;
            } else {
                ReturnData.reason = Banlist[IPHash].BannedFor;
                ReturnData.until = Banlist[IPHash].BannedUntil;
            }
        }
        return ReturnData;
    }

    function logBadAction(socket) {
        if (BadActions[socket] === undefined || BadActions[socket] === null) {
            const actions = {
                offences: 0,
                last_committed_offence: new Date().getTime()
            };
            BadActions[socket] = actions;
        } else {
            var OldOffences = BadActions[socket].offences;
            const actions = {
                offences: Number(OldOffences + 1),
                last_committed_offence: new Date().getTime()
            }
            BadActions[socket] = actions;
        }
        if (BadActions[socket].offences >= Config.MAL_REQ_THRESHOLD) {
            banSocket(socket, "[Autoban] Exceeded offences threshold", new Date().getTime() + Config.MAL_REQ_BAN_DURATION);
        }
    }
    function getOffences(socket) {
        if (BadActions[socket] === undefined || BadActions[socket] === null) {
            return 0;
        } else {
            return BadActions[socket].offences;
        }
    }
    function getLastCommittedOffenceTime(socket) {
        if (BadActions[socket] === undefined || BadActions[socket] === null) {
            return 0;
        } else {
            return BadActions[socket].last_committed_offence;
        }
    }


    function loadUserlist() {
        if (!fs.existsSync(FileDir+'/users.json')) {
            fs.writeFileSync(FileDir+'/users.json', "{}")
        }
        return JSON.parse(fs.readFileSync(FileDir+'/users.json', 'utf-8'))
    }

    function registerUser(socketID, uuid) {
        var list = loadUserlist();
        const obj = {
            UUID: uuid
        }
        list[socketID] = obj;
        fs.writeFileSync(FileDir+'/users.json', JSON.stringify(list, null, 2))
    }

    function userExists(socketID) {
        var list = loadUserlist();
        if (list[socketID] === undefined || list[socketID] === null || list[socketID].UUID === undefined || list[socketID].UUID === null) {
            return false;
        } else {
            return true;
        }
    }

    function getUUID(socketID) {
        var list = loadUserlist();
        try {
            return list[socketID].UUID;
        } catch {
            return null;
        }
    }

    function broadcastToAll(event_name, message) {
        for (i = 0; i < sockets.length; i++) {
            const currentSocket = sockets[i].socket_obj;
            currentSocket.emit(event_name, message);
        }
    }

    function UpdateStatusMessage() {
        var COMPLETE_CONNECTIONS = Math.floor(CURRENT_CONNECTIONS / 2);
        console.log(chalk.greenBright('Active connections: ') + CURRENT_CONNECTIONS + "/" + MAX_CONNECTIONS + ` | ${COMPLETE_CONNECTIONS} complete connection(s)\r`)
    }

    function UnregisterSocket(socket) {
        var SocketID = null;
        for (i = 0; i < sockets.length; i++) {
            const currentSocket = sockets[i];
            if (currentSocket.socket_obj == socket) {
                SocketID = currentSocket.socket_id
            }
        }
        for (i = 0; i < ConnectionSockets.length; i++) {
            if (ConnectionSockets[i].main_socket_object == socket) {
                try {
                    var Peer = ConnectionSockets[i].peer_socket_object;
                    var PeerID = ConnectionSockets[i].peer_socket_id;
                    const SendData = {
                        PeerID: ConnectionSockets[i].main_socket_id
                    }
                    Peer.emit("server_warning", "The peer you were talking to has disconnected from the server")
                    Peer.emit("disconnect_from_user", createEncryptedPacket(SendData, SocketInformation[PeerID].publicKey))
                } catch {}
            }
        }
        sockets = sockets.filter(data => data.socket_obj != socket);
        ConnectionSockets = ConnectionSockets.filter(data => data.main_socket_object != socket);
        SocketInformation[SocketID] = undefined;
    }

    function nullUndefinedCheck(value) {
        if (value === null || value === undefined) {
            return true;
        } else {
            return false;
        }
    }

    function isOnline(socketID) {
        if (nullUndefinedCheck(SocketInformation[socketID])) {
            return false;
        } else {
            return true;
        }
    }

    var DONT_UNREGISTER = false;
    var DONT_LOG = false;

    io.on('connection', function (socket){
        const IsBannedObject = isBanned(socket);
        if (IsBannedObject.banned == true) {
            var UntilString = ConstructUntilString(IsBannedObject.until);
            UntilString = UntilString.replace(/\b(\d{1})\b/g, '0$1')
            socket.emit("server_warning", "You are banned from the server!{NEWLINE}Reason: " + IsBannedObject.reason + "{NEWLINE}Banned for: " + UntilString);
            socket.disconnect();
            return;
        }

        log("CONNECT", `${socket.handshake.query['userid']} has connected.`)

        CURRENT_CONNECTIONS = CURRENT_CONNECTIONS + 1;
        UpdateStatusMessage();
        if (CURRENT_CONNECTIONS > MAX_CONNECTIONS) {
            socket.emit("server_warning", "The server you are accessing is currently full.");
            socket.disconnect()
            CURRENT_CONNECTIONS = CURRENT_CONNECTIONS - 1;
            UpdateStatusMessage();
        }
        socket.on('disconnect', function() {
            if (DONT_LOG == false) {
                if (nullUndefinedCheck(socketNames[socket.id])) {
                    log("DISCONNECT", `A user has disconnected.`)
                } else {
                    log("DISCONNECT", `${socketNames[socket.id].name} has disconnected.`)
                }
            }
            CURRENT_CONNECTIONS = CURRENT_CONNECTIONS - 1;
            // UNREGISTER THE SOCKET
            if (DONT_UNREGISTER == false) {
                UnregisterSocket(socket);
            }
            UpdateStatusMessage();
        });

        socket.on('req_discon_from_me', function(data) {
            try {
                var decryptedData = decryptEncryptedPacket(data, privateKey);
                const PeerID = decryptedData.PeerID;
                const SocketID = decryptedData.MyID;
                if (!isOnline(PeerID)) {
                    return;
                }
                const PeerSocket = SocketInformation[PeerID].socketObject;
                const SendData = {
                    PeerID: SocketID
                }
                log("INFO", "Recieved a DisconnectFromMe packet from " + SocketID + " wishing to disconnect from " + PeerID);
                PeerSocket.emit("disconnect_from_user", createEncryptedPacket(SendData, SocketInformation[PeerID].publicKey))
            } catch (e) {
                log("WARN", "Exception whilst running req_discon_from_me: " + e.message + ". Client has been warned")
                socket.emit("server_warning", "Malformed request sent to server! Event: req_discon_from_me. This will be logged");
                logBadAction(socket);
                return;
            }
        })

        socket.on('peer_conn_req', function(data) {
            try {
                //console.log('recv peer_conn_req')
            var decryptedData = decryptEncryptedPacket(data, privateKey);
            const VerificationString = decryptedData.AcceptVerifString;
            const SocketID = decryptedData.MyID;
            const PeerID = decryptedData.ConnectToID;
            const MainPubKey = SocketInformation[SocketID].publicKey;
            if (!isOnline(PeerID)) {
                const SendData = {
                    acc: false,
                    reason: "The user you are trying to contact is offline.",
                    vstring: VerificationString,
                    responseFrom: null,
                    peerPublicKey: null
                };
                socket.emit("peer_conn_res", createEncryptedPacket(SendData, MainPubKey))
                return;
            }
            const PeerPubKey = SocketInformation[PeerID].publicKey;
            const PeerSocket = SocketInformation[PeerID].socketObject;
            //log("INFO", "Recieved a ConnectionRequest packet from " + SocketID + " wishing to connect to " + PeerID);
            /*const sendData = {
                acc: false,
                reason: "Test",
                //vstring: decryptedData.AcceptVerifString
                vstring: "Test"
            }
            var encryptedData = createEncryptedPacket(sendData, SocketInformation[SocketID].publicKey);
            socket.emit("peer_conn_res", encryptedData)*/
            const ConnectionParameters = {
                pubKey: MainPubKey
            }

            const SendData = {
                userID: SocketID,
                encData: createEncryptedPacket(ConnectionParameters, PeerPubKey)
            }
            PeerSocket.emit("server_peerConn_req", SendData);
            var IgnoreResponse = false;
            const ResponseNotRecievedTimeout = setTimeout(function(){
                if (!isOnline(PeerID)) {
                    const SendData = {
                        acc: false,
                        reason: "The user you are trying to contact is offline.",
                        vstring: VerificationString,
                        responseFrom: null,
                        peerPublicKey: null
                    };
                    socket.emit("peer_conn_res", createEncryptedPacket(SendData, MainPubKey))
                    IgnoreResponse = true
                    return;
                } else {
                    const SendData = {
                        acc: false,
                        reason: "The connection packet could not be sent to peer.",
                        vstring: VerificationString,
                        responseFrom: null,
                        peerPublicKey: null
                    };
                    socket.emit("peer_conn_res", createEncryptedPacket(SendData, MainPubKey))
                    IgnoreResponse = true
                    return;
                }
            },9000);
            //log("INFO", `Sent a ConnectionRequestFromServer packet to ${PeerID}.`)
            PeerSocket.on('peerConn_res', function(data) {
                clearTimeout(ResponseNotRecievedTimeout);
                if (IgnoreResponse) {
                    return;
                }
                //log("INFO", `Got a ConnectionRequest_Response packet from ${PeerID}.`)
                const DecryptedAnswer = decryptEncryptedPacket(data, privateKey);
                const SendData = {
                    acc: false,
                    reason: "Unable to process request, try again later",
                    vstring: VerificationString,
                    responseFrom: PeerID,
                    peerPublicKey: PeerPubKey
                };
                if (DecryptedAnswer.response == "deny") {
                    SendData.acc = false;
                    SendData.reason = DecryptedAnswer.reason;
                } else {
                    SendData.acc = true;
                    SendData.reason = DecryptedAnswer.reason;
                    const pushData = {
                        main_socket_object: socket,
                        peer_socket_object: PeerSocket,
                        main_socket_id: SocketID,
                        peer_socket_id: PeerID
                    }
                    const pushDataReverse = {
                        main_socket_object: PeerSocket,
                        peer_socket_object: socket,
                        main_socket_id: PeerID,
                        peer_socket_id: SocketID
                    }
                    ConnectionSockets.push(pushData);
                    ConnectionSockets.push(pushDataReverse);
                }
                socket.emit("peer_conn_res", createEncryptedPacket(SendData, MainPubKey))
                //log("INFO", `Relayed ConnectionRequest_Response packet to ${SocketID}.`)
            })
            } catch (e) {
                log("WARN", "Exception whilst running peer_conn_req: " + e.message + ". Client has been warned")
                socket.emit("server_warning", "Malformed request sent to server! Event: peer_conn_req. This will be logged");
                logBadAction(socket);
                return;
            } 
            return;
        })

        socket.on('SendMessageToClient', function(data) {
            /*
                const SocketQuickAccessData = {
                    publicKey: SocketPublicKey,
                    id: SocketID,
                    uuid: ProvidedUUID,
                    socketObject: socket
                }
            */
           try {
                const Decrypted = decryptEncryptedPacket(data, privateKey);
                const ToSendToClient = Decrypted.EncryptedClientData;
                const PeerID = Decrypted.PeerID;
                const SocketID = Decrypted.MyID;
                const SockPubKey = SocketInformation[SocketID].publicKey;
                const PeerSocketObject = SocketInformation[PeerID].socketObject;
                const PeerSocketPubKey = SocketInformation[PeerID].publicKey;
                const mdata = {
                    encrypted: ToSendToClient,
                    PeerID: SocketID,
                    PeerPubKey: SockPubKey
                }
                PeerSocketObject.emit('_sentMessage_', createEncryptedPacket(mdata, PeerSocketPubKey));
            } catch (e) {
                log("WARN", "Exception whilst running SendMessageToClient: " + e.message + ". Client has been warned")
                socket.emit("server_warning", "Malformed request sent to server! Event: SendMessageToClient. This will be logged");
                logBadAction(socket);
                return;
            }
        })

        socket.on('socket_provide_data', function(data) {
            try {
                // REGISTER THE SOCKET
            const SocketID = data.SockID;
            const SocketPublicKey = data.SockPubKey;
            var ProvidedUUID = data.MyUUID;
            const ProvidedVersion = data.Version;

            if (nullUndefinedCheck(SocketID) || nullUndefinedCheck(SocketPublicKey) || nullUndefinedCheck(ProvidedVersion)) {
                socket.emit("server_warning", "The authentication information provided is invalid.");
                log("WARN", SocketID + " failed at nullUndefinedCheck():Authentication-1")
                socket.disconnect()
                return;
            }

            log("INFO", "Registering " + data.SockID + "...");

            if (ProvidedVersion !== SupportedVersionNumber) {
                if (ProvidedVersion < SupportedVersionNumber) {
                    socket.emit("server_warning", "Your client is too old for this server.");
                } else {
                    socket.emit("server_warning", "Your client is too new for this server.");
                }
                socket.disconnect()
                return;
            }

            if (SocketInformation[SocketID] !== undefined) {
                socket.emit("server_warning", "The C2CC ID you are using is already in use");
                socket.disconnect()
                return;
            }

            if (SocketPublicKey.trim() == "" || SocketID.trim() == "" || SocketPublicKey === null || SocketPublicKey === undefined || SocketID === undefined || SocketID === null) {
                socket.emit("server_warning", "The authentication information provided is invalid.");
                log("WARN", SocketID + " failed at credentialsValidateCheck():Authentication-2")
                socket.disconnect()
                return;
            }

            // AUTHENTICATE USER
            var GeneratedUUID = null;
            if (userExists(SocketID)) {
                if (!ProvidedUUID) {
                    socket.emit("server_warning", "The authentication information provided is invalid.");
                    log("WARN", SocketID + " failed at verifyProvidedUUID():Authentication-3");
                    socket.disconnect();
                    return;
                }
                var UUID = getUUID(SocketID)
                ProvidedUUID = ProvidedUUID.replace(/["]/g, "");
                if (md5(ProvidedUUID) !== UUID) {
                    socket.emit("server_warning", "The authentication information provided is invalid.");
                    log("WARN", SocketID + " failed at verifyProvidedUUID():Authentication-4");
                    socket.disconnect();
                    return;
                }
            }

            const randomWords = require('random-words')
            GeneratedUUID = hashString(randomWords({ min: 3, max: 10, join: ' ' }) + " " + v4());
            registerUser(SocketID, md5(GeneratedUUID.toString()));

            const SocketQuickAccessData = {
                publicKey: SocketPublicKey,
                id: SocketID,
                uuid: ProvidedUUID,
                socketObject: socket
            }
            SocketInformation[SocketID] = SocketQuickAccessData;
            sockets.push({socket_obj: socket, socket_id: SocketID});

            const SendData = {
                uuid: GeneratedUUID,
                pubkey: publicKey,
                servername: Config.HOSTNAME,
                motd: Config.MOTD
            };

            const Name = {
                name: SocketID
            }

            socketNames[socket.id] = Name;

            const EncryptedSendData = createEncryptedPacket(SendData, SocketInformation[SocketID].publicKey)
            socket.emit("server_connection_accepted", EncryptedSendData); // accept the connection
            log("INFO", "Finished registering " + data.SockID);
            } catch (e) {
                log("WARN", "Exception whilst running socket_provide_data: " + e.message + ". Client has been warned")
                socket.emit("server_warning", "Malformed request sent to server! Event: socket_provide_data. This will be logged");
                logBadAction(socket);
                return;
            }
        });
    });

    http.listen(LISTENING_PORT, function () {
    console.log('C2CC Server listening on port '+LISTENING_PORT);
    });
    var ON_DEATH = require('death'); 
    ON_DEATH(function(signal, err) {
        console.log(chalk.yellowBright("\nRECEIVED "+signal))
        console.log(chalk.magentaBright("--- RUNNING SHUTDOWN SEQUENCE ---"))
        var ShutdownClients = 0;
        process.stdout.write("Disconnected " + ShutdownClients + "/" + sockets.length + " clients\r");
        for (i = 0; i < sockets.length; i++) {
            ShutdownClients++;
            process.stdout.write("Disconnected " + ShutdownClients + "/" + sockets.length + " clients\r");
            //const sockID = sockets[i].socket_id;
            const currentSocket = sockets[i].socket_obj;
            //log("INFO", "Disconnecting " + sockID)
            //UnregisterSocket(currentSocket);
            currentSocket.emit("server_warning", "The server has shut down");
            DONT_UNREGISTER = true;
            DONT_LOG = true;
            currentSocket.disconnect()
        }
        console.log(chalk.magentaBright("\n--- Server safely shut down ---"));
        console.log("Bye!")
        process.exit()
    })
} catch (e) {
    console.log(chalk.redBright("SERVER CRASH DETECTED! ") + e.message)
    console.log("\nDoing a safe shutdown...")
    for (i = 0; i < sockets.length; i++) {
        const sockID = sockets[i].socket_id;
        const currentSocket = sockets[i].socket_obj;
        log("INFO", "Unregistering " + sockID)
        //UnregisterSocket(currentSocket);
        currentSocket.emit("server_warning", "The server has crashed");
        DONT_UNREGISTER = true;
        DONT_LOG = true;
        currentSocket.disconnect()
    }
    process.exit()
}