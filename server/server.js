var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var chalk = require('chalk');
var { v4 } = require('uuid');
var fs = require('fs');
const SupportedVersionNumber = 0001;
var Config = require('./config');

const MAX_CONNECTIONS = Config.MAX_CONNECTIONS;
const LISTENING_PORT = Config.LISTENING_PORT;

var sockets = [];
var socketNames = {};
var SocketInformation = {};
var ConnectionSockets = [];
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
    var CURRENT_CONNECTIONS = 0;

    function hashString(data) {
        return crypto.createHash("sha256").update(data, "binary").digest("base64");
    }

    function md5(data) {
        return crypto.createHash("sha512").update(data, "binary").digest("base64");
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
        fs.writeFileSync('./users.json', JSON.stringify(list, null, 2))
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
            if (DONT_UNREGISTER == false) {
                UnregisterSocket(socket);
            }
            UpdateStatusMessage();
        });

        socket.on('req_discon_from_me', function(data) {
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
        })

        socket.on('peer_conn_req', function(data) {
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
        })

        socket.on('socket_provide_data', function(data) {
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
                var UUID = getUUID(SocketID)
                ProvidedUUID = ProvidedUUID.replace(/["]/g, "");
                if (md5(ProvidedUUID) !== UUID) {
                    socket.emit("server_warning", "The authentication information provided is invalid.");
                    log("WARN", SocketID + " failed at verifyProvidedUUID():Authentication-3");
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
        });
    });

    http.listen(LISTENING_PORT, function () {
    console.log('C2CC Server listening on port '+LISTENING_PORT);
    });
    process.on('SIGINT', function() {
        var COMPLETE_CONNECTIONS = Math.floor(CURRENT_CONNECTIONS / 2);
        process.stdout.write(chalk.greenBright('Active connections: ') + CURRENT_CONNECTIONS + "/" + MAX_CONNECTIONS + ` | ${COMPLETE_CONNECTIONS} complete connection(s)\n`)
        console.log("\nDoing a safe shutdown...")
        for (i = 0; i < sockets.length; i++) {
            const sockID = sockets[i].socket_id;
            const currentSocket = sockets[i].socket_obj;
            log("INFO", "Unregistering " + sockID)
            //UnregisterSocket(currentSocket);
            currentSocket.emit("server_warning", "The server has shut down");
            DONT_UNREGISTER = true;
            currentSocket.disconnect()
        }
        console.log("Bye!")
        process.exit()
    });
} catch {
    var COMPLETE_CONNECTIONS = Math.floor(CURRENT_CONNECTIONS / 2);
    process.stdout.write(chalk.greenBright('Active connections: ') + CURRENT_CONNECTIONS + "/" + MAX_CONNECTIONS + ` | ${COMPLETE_CONNECTIONS} complete connection(s)\n`)
    console.log("\nDoing a safe shutdown...")
    for (i = 0; i < sockets.length; i++) {
        const sockID = sockets[i].socket_id;
        const currentSocket = sockets[i].socket_obj;
        log("INFO", "Unregistering " + sockID)
        //UnregisterSocket(currentSocket);
        currentSocket.emit("server_warning", "The server is restarting after a crash");
        DONT_UNREGISTER = true;
        currentSocket.disconnect()
    }
    console.log("Bye!")
    require("child_process").spawn(process.argv.shift(), process.argv, {
        cwd: process.cwd(),
        detached : true,
        stdio: "inherit"
    });
    process.exit()
}