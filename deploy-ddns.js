let logger = require('./sources/logger.js');
let FileSystem = require('fs');
let jwt = require('jsonwebtoken');
let rsa = require('rsa-compat').RSA;
let path = require('path');

let DNSStore = {};
let DNSStoreArray = {};
let DNSIndexStore = {};
let DNSFastForwardStore = {};

let DNSStorePath = path.join(process.cwd(), 'dns-data.json');
if (FileSystem.existsSync(DNSStorePath)) {
    DNSStore = require(DNSStorePath);
    DeployDDNS.refreshDNSStoreArray();
}

let externalIpFindService = 'https://api.ipify.org';

//TODO REST
class DeployDDNS {
    static load() {
        logger('LOAD THE DDNS REINHARDT DDNS SERVER...');
        logger(`CREATE CHECK 'pubkey.pem' 'privkey.pem'`);
        DeployDDNS.createPem(() => {
            DeployDDNS.createServer();
            logger('DDNS REINHARDT DDNS SERVER LOADED.');

            checkip.getExternalIp(externalIpFindService).then(function(ip) {
                logger(`DDNS SERVER EXTERNAL IP: '${ip}:53'`);
            });
        });
    }

    /**
     * @param {number} port
     * @param {string} address
     */
    static createServer(port, address, udpManagerPort) {
        if (port == undefined) port = 53;
        if (address == undefined) address = '0.0.0.0';

        let DDNS = require('./sources/ddns.js');
        let handler = require('./sources/handler.js');
        let servers = DDNS.createDDNSServer(handler.onRequest, handler.onError, handler.onSocketError);

        servers.udpServer.serve(port, address);
        servers.tcpServer.serve(port, address);

        let UDPManager = require('./sources/udp-manager.js');
        let udpManagerSocket = UDPManager.createServer(udpManagerPort, address);

        return [servers.udpServer, servers.tcpServer, udpManagerSocket];
    }

    /**
     * @description
     * Create 'privkey.pem' and 'pubkey.pem'
     */
    static createPem(callback) {
        let bitlen = 2048;
        let exp = 65537;
        let opts = {
            public: true,
            pem: true
        };
        let cwd = process.cwd();
        let privkeyPath = path.join(cwd, 'privkey.pem');
        let pubkeyPath = path.join(cwd, 'pubkey.pem');

        if (FileSystem.existsSync(privkeyPath)) {
            logger(`PEM DATA ALREADY EXIST.`);
            callback();
            return false;
        }

        rsa.generateKeypair(bitlen, exp, opts, (err, keypair) => {
            FileSystem.writeFileSync(privkeyPath, keypair.privateKeyPem, 'ascii');
            FileSystem.writeFileSync(pubkeyPath, keypair.publicKeyPem, 'ascii');
            logger('CREATED PRIVACY-ENHANCED ELECTRONIC MAIL DATA.');
            callback();
        });
        return true;
    }

    /**
     * @param {string}
     */
    static checkPrivkeyPem(privkeyPemData) {
        let privkeyPath = path.join(process.cwd(), 'privkey.pem');
        let secret = FileSystem.readFileSync(privkeyPath, 'ascii');
        return (secret == privkeyPemData);
    }

    /**
     * @description
     * Create Jwt token
     *
     * @param {string} domainName
     */
    static createJwt(domainName) {
        let jwtFolderPath = path.join(process.cwd(), 'jwts');
        try {
            if (!FileSystem.existsSync(jwtFolderPath)) FileSystem.mkdirSync(jwtFolderPath);
        } catch (e) {}

        let domainJwtFilePath = path.join(jwtFolderPath, `${domainName}.jwt`);
        let privkeyPath = path.join(process.cwd(), 'privkey.pem');
        let pem = FileSystem.readFileSync(privkeyPath, 'ascii');

        let tok = jwt.sign({
            approvedDomain: domainName
        }, pem, {
            algorithm: 'RS256'
        });
        FileSystem.writeFileSync(domainJwtFilePath, tok, 'utf-8');

        logger(`CREATED JWT FILE. '${domainName}.jwt'`);
    }

    /**
     * @param {string} domainName
     */
    static getJwtData(domainName) {
        let deviceJwtFilePath = path.join(process.cwd(), `jwts/${domainName}.jwt`);
        if (!FileSystem.existsSync(deviceJwtFilePath)) ReinHardt.createJwt(domainName);
        return FileSystem.readFileSync(deviceJwtFilePath, 'utf-8');
    }

    /**
     * @param {string} jwtData
     * @param {string} accessDomainName
     * @param {function} callback
     */
    static checkJwt(jwtData, accessDomainName, callback) {
        let verifyCallback = (error, decoded) => {
            if (error) {
                callback(false, error);
                return;
            }

            let token = jwt.decode(jwtData);
            if (typeof(token.approvedDomain) == 'undefined') {
                callback(false, `TOKEN DOESN'T EXIST`);
                return;
            }

            if (token.approvedDomain != accessDomainName) {
                callback(false, 'NOT ALLOWED');
                return;
            }

            callback(true, decoded);
        };

        let pubkeyPath = path.join(process.cwd(), 'pubkey.pem');
        let secret = FileSystem.readFileSync(pubkeyPath, 'ascii');
        jwt.verify(jwtData, secret, [], verifyCallback);
    }

    /**
     * @param {string} log
     */
    static requestLog(log) {
        if (logger != null) logger(log);
    }

    /**
     * @param {object} newLogger
     */
    static setLogger(newLogger) {
        logger = newLogger;
    }

    /**
     * @param {string} domainName
     * @param {string} serverIp
     */
    static addDNS(domainName, serverIp, serverName) {
        if (typeof(DNSStore[domainName]) == 'undefined') DNSStore[domainName] = {};
        DNSStore[domainName][serverIp] = serverName;
        DeployDDNS.refreshDNSStoreArray();
    }

    /**
     * @param {string} domainName
     * @param {string} serverIp
     */
    static deleteDNStoIP(domainName, serverIp) {
        if (typeof(DNSStore[domainName][serverIp]) == 'undefined')
            return false;
        delete(DNSStore[domainName][serverIp]);
        if (DNSStore[domainName].length == 0)
            delete(DNSStore[domainName]);
        DeployDDNS.refreshDNSStoreArray();
        return true;
    }

    /**
     * @param {string} domainName
     * @param {string} serverName
     */
    static deleteDNStoName(domainName, serverName) {
        if (typeof(DNSStore[domainName]) == 'undefined')
            return false;
        for (let serverIp in DNSStore[domainName]) {
            let storedServerName = DNSStore[domainName][serverIp];
            if (storedServerName == serverName) {
                delete(DNSStore[domainName][serverIp]);
                break;
            }
        }
        DeployDDNS.refreshDNSStoreArray();
        return true;
    }

    /**
     * @param {string} domainName
     */
    static getDNSOrderly(domainName) {
        let index = getDNSIndexOrderly(domainName);
        if (typeof(DNSStoreArray[domainName]) == 'undefined') return null;
        if (typeof(DNSStoreArray[domainName][index]) == 'undefined') return null;

        return DNSStoreArray[domainName][index];
    }

    /**
     * @param {string} domainName
     */
    static getDNSIndexOrderly(domainName) {
        if (typeof(DNSStoreArray[domainName]) == 'undefined') return 0;

        if (typeof(DNSIndexStore[domainName]) == 'undefined') {
            DNSIndexStore[domainName] = 0;
            return 0;
        } else {
            let currentIndex = ++DNSIndexStore[domainName];
            if (currentIndex >= DNSStoreArray[domainName].length)
                currentIndex = DNSIndexStore[domainName] = 0;
            return currentIndex;
        }
    }

    /**
     * @param {string} domainName
     */
    static getDomainDNSData(domainName){
        if (typeof(DNSStoreArray[domainName]) == 'undefined') return null;
        return DNSStoreArray[domainName];
    }

    /**
     * @param {boolean} async
     * @param {function} callback
     */
    static saveDNS(async, callback) {
        if (async == undefined || !async) {
            FileSystem.writeFileSync(DNSStorePath, JSON.stringify(DNSStore), 'utf-8');
        } else {
            FileSystem.writeFile(DNSStorePath, JSON.stringify(DNSStore), encoding = 'utf8', callback);
        }
    }

    static clearDNS() {
        DNSStore = {};
        DNSStoreArray = {};
        DNSIndexStore = {};
        FileSystem.stat(DNSStorePath, (error, stats) => {
            if (error) return;
            FileSystem.unlink(DNSStorePath);
        });
    }

    /**
     * @param {string} domainName
     * @param {string} clientIp
     * @param {string} serverIp
     */
    static addDNSFastForward(domainName, clientIp, serverIp) {
        if (typeof(DNSFastForwardStore[domainName]) == 'undefined') DNSFastForwardStore[domainName] = {};
        DNSFastForwardStore[domainName][clientIp] = serverIp;
    }

    /**
     * @param {string} domainName
     * @param {string} clientIp
     */
    static deleteDNSFastForwardToClientIp(domainName, clientIp) {
        if (typeof(DNSFastForwardStore[domainName]) == 'undefined') return false;
        if (typeof(DNSFastForwardStore[domainName][clientIp]) == 'undefined') return false;

        delete(DNSFastForwardStore[domainName][clientIp]);
        if (DNSFastForwardStore[domainName].length == 0)
            delete(DNSFastForwardStore[domainName]);
        return true;
    }

    /**
     * @param {string} domainName
     * @param {string} serverIp
     */
    static deleteDNSFastForwardToServerIp(domainName, serverIp) {
        if (typeof(DNSFastForwardStore[domainName]) == 'undefined') return;
        for (let clientIp in DNSFastForwardStore[domainName]) {
            let storedServerIp = DNSFastForwardStore[domainName][clientIp];
            if (storedServerIp == serverIp) delete(DNSFastForwardStore[domainName][clientIp]);
        }
    }

    /**
     * @param {string} domainName
     * @param {string} clientIp
     */
    static getDNSFastForward(domainName, clientIp) {
        if (typeof(DNSFastForwardStore[domainName]) == 'undefined') return null;
        if (typeof(DNSFastForwardStore[domainName][clientIp]) == 'undefined') return null;

        return DNSFastForwardStore[domainName][clientIp];
    }

    /**
     * @param {string} domainName
     */
    static getDomainDNSFastForwardData(domainName){
        if (typeof(DNSFastForwardStore[domainName]) == 'undefined') return null;
        return DNSFastForwardStore[domainName];
    }

    static clearDNSFastForward() {
        DNSFastForwardStore = {};
    }

    static refreshDNSStoreArray() {
        DNSStoreArray = {};

        for (let DomainName in DNSStore) {
            DNSStoreArray[DomainName] = [];
            for (let IpAddress in DNSStore[DomainName]) {
                DNSStoreArray[DomainName].push(IpAddress);
            }
        }
    }
}

module.exports = DeployDDNS;
