var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var chalk = require('chalk');
var { v4 } = require('uuid');
var fs = require('fs');
const SupportedVersion = "IndevTestBeta";
const SupportedVersionString = "1.0.0"
const Config = require('./config');

const MAX_CONNECTIONS = Config.MAX_CONNECTIONS;
const LISTENING_PORT = Config.LISTENING_PORT;

var sockets = [];
var socketNames = {};
var SocketInformation = {};

function log(reason, message) {
    if (reason == "CONNECT") {
        console.log(chalk.greenBright('[Connect]') + " " + message)
    } else if (reason == "DISCONNECT") {
        console.log(chalk.redBright('[Disconnect]') + " " + message)
    } else if (reason == "INFO") {
        console.log(chalk.whiteBright('[Info]') + " " + message)
    } else if (reason == "WARN") {
        console.log(chalk.yellowBright('[Warning]') + " " + message)
    } else if (reason == "ERROR") {
        console.log(chalk.redBright('[Error]') + " " + message)
    } else {
        console.log(chalk.whiteBright(reason) + " " + message)
    }
}
console.clear()
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

if (!fs.existsSync('./users.json')) {
    fs.writeFileSync('./users.json', "{}")
}

try {
    var CURRENT_CONNECTIONS = 0;

    function hashString(data) {
        return crypto.createHash("sha256").update(data, "binary").digest("base64");
    }

    function loadUserlist() {
        if (!fs.existsSync('./users.json')) {
            fs.writeFileSync('./users.json', "{}")
        }
        return JSON.parse(fs.readFileSync('./users.json', 'utf-8'))
    }

    function registerUser(socketID, uuid) {
        var list = loadUserlist();
        const obj = {
            UUID: uuid
        }
        list[socketID] = obj;
        fs.writeFileSync('./users.json', JSON.stringify(list))
    }

    function userExists(socketID) {
        var list = loadUserlist();
        if (list[socketID] === undefined || list[socketID] === null) {
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
        sockets = sockets.filter(data => data.socket_obj != socket);
        SocketInformation[SocketID] = undefined;
    }

    function nullUndefinedCheck(value) {
        if (value === null || value === undefined) {
            return true;
        } else {
            return false;
        }
    }

    io.on('connection', function (socket){
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
            if (nullUndefinedCheck(socketNames[socket.id])) {
                log("DISCONNECT", `A user has disconnected.`)
            } else {
                log("DISCONNECT", `${socketNames[socket.id].name} has disconnected.`)
            }
            CURRENT_CONNECTIONS = CURRENT_CONNECTIONS - 1;
            // UNREGISTER THE SOCKET
            UnregisterSocket(socket);
            UpdateStatusMessage();
        });

        socket.on('peer_conn_req', function(data) {
            //console.log('recv peer_conn_req')
            var decryptedData = decryptEncryptedPacket(data, privateKey);
            const SocketID = decryptedData.MyID;
            const sendData = {
                acc: false,
                reason: "Test",
                vstring: decryptedData.AcceptVerifString
            }
            var encryptedData = createEncryptedPacket(sendData, SocketInformation[SocketID].publicKey);
            socket.emit("peer_conn_res", encryptedData)
            return;
        })

        socket.on('socket_provide_data', function(data) {
            // REGISTER THE SOCKET
            const SocketID = data.SockID;
            const SocketPublicKey = data.SockPubKey;
            const ProvidedUUID = data.MyUUID;
            const ProvidedVersionHash = data.VersionHash;
            const ProvidedVersionNumber = data.VersionNumber;

            if (nullUndefinedCheck(SocketID) || nullUndefinedCheck(SocketPublicKey) || nullUndefinedCheck(ProvidedUUID) || nullUndefinedCheck(ProvidedVersionNumber) || nullUndefinedCheck(ProvidedVersionHash)) {
                socket.emit("server_warning", "The authentication information provided is invalid.");
                socket.disconnect()
                return;
            }

            log("INFO", "Registering " + data.SockID + "...");

            if (ProvidedVersionHash !== SupportedVersion) {
                if (ProvidedVersionNumber > SupportedVersionString) {
                    socket.emit("server_warning", "Your client is too new for this server.");
                } else if (ProvidedVersionNumber == SupportedVersionString) {
                    socket.emit("server_warning", "Your client has the same version number, yet it is not a version hash the server recognises.{NEWLINE}Most likely you have a patch which this server does not support");
                } else {
                    socket.emit("server_warning", "Your client is too old for this server.");
                }
                socket.emit("server_warning", "This server needs a client of version v" + SupportedVersionString + ", your version is v" + ProvidedVersionNumber)
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
                socket.disconnect()
                return;
            }

            // AUTHENTICATE USER
            var GeneratedUUID = null;
            if (userExists(SocketID)) {
                var UUID = getUUID(SocketID)
                if (hashString(ProvidedUUID) !== UUID) {
                    socket.emit("server_warning", "The authentication information provided is invalid.");
                    socket.disconnect();
                    return;
                }
            }

            GeneratedUUID = v4();
            registerUser(SocketID, hashString(GeneratedUUID));

            const SocketQuickAccessData = {
                publicKey: SocketPublicKey,
                id: SocketID,
                uuid: ProvidedUUID
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
        });
    });

    http.listen(LISTENING_PORT, function () {
    console.log('C2CC Server listening on port '+LISTENING_PORT);
    });
    process.on('SIGINT', function() {
        var COMPLETE_CONNECTIONS = Math.floor(CURRENT_CONNECTIONS / 2);
        process.stdout.write(chalk.greenBright('Active connections: ') + CURRENT_CONNECTIONS + "/" + MAX_CONNECTIONS + ` | ${COMPLETE_CONNECTIONS} complete connection(s)\r`)
        console.log("\nDoing a safe shutdown...")
        for (i = 0; i < sockets.length; i++) {
            const currentSocket = sockets[i].socket_obj;
            const SockName = sockets[i].socket_id;
            log("INFO", "Unregistering socket with ID of '"+SockName+"'")
            UnregisterSocket(currentSocket);
            currentSocket.emit("server_warning", "The server has shut down");
            currentSocket.disconnect()
            log("INFO", "Unregistered socket with ID of '"+SockName+"'")
        }
        console.log("Bye!")
        process.exit()
    });
} catch {
    process.stdout.write("\n");
    process.exit()
}