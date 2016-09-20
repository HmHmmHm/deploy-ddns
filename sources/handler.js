var DeployDDNS = require('../deploy-ddns.js');

var ddnsRequestHander = (request, response) => {
    let answers = [];
    for (let questionIndex in request.question) {
        let answer = {};

        let question = request.question[questionIndex];
        let domainName = question.name;
        let clientIp = request.address.address;
        let typeName = ndns.consts.QTYPE_TO_NAME[question && question.type];

        let domainIp = '';
        let dnsFastForward = DeployDDNS.getDNSFastForward(domainName, clientIp);
        if (dnsFastForward != null) domainIp = dnsFastForward;

        if (domainIp.length == 0) {
            let dnsOrderly = DeployDDNS.getDNSOrderly(domainName);
            if (dnsOrderly != null) domainIp = dnsOrderly;
        }

        if (domainIp.length == 0) {
            answers.push(answer);
            continue;
        }

        switch (typeName) {
            case 'A':
            case 'AAAA':
                answer = {
                    type: 1,
                    class: 1,
                    name: domainName,
                    address: domainIp,
                    data: [domainIp],
                    exchange: domainIp,
                    priority: 10,
                    ttl: 1
                }
                break;
        }

        answers.push(answer);
    }

    response.answer = answers;
}

function onRequestError(error, request, response) {
    DeployDDNS.requestLog('[ERROR] REQUEST ERROR OCCURS IN HANDLER.');
    DeployDDNS.requestLog(error && error.stack || error || "Unknown Error");

    if (request && request.question) {
        DeployDDNS.requestLog(request.question);
    } else {
        DeployDDNS.requestLog(request);
    }
    try {
        if (response && response.send) response.send();
    } catch (e) {
        return;
    }
}

function onRequest(request, response) {
    try {
        ddnsRequestHander(request, response);
    } catch (error) {
        onRequestError(error, request, response);
    }
}

function onError(error, message, response) {
    DeployDDNS.requestLog('[ERROR] UNPACK ERROR OCCURS IN HANDLER.');
    DeployDDNS.requestLog(message);
    DeployDDNS.requestLog(error && error.stack || error || "Unknown Error");
    if (response && response.send) response.send();
}

function onSocketError(error, socket) {
    DeployDDNS.requestLog('[ERROR] SOCKET ERROR OCCURS IN HANDLER.');
    DeployDDNS.requestLog(socket);
    DeployDDNS.requestLog(error && error.stack || error || "Unknown Error");
}

module.exports = {
    onRequest: onRequest,
    onError: onError,
    onSocketError: onSocketError
};
