define(["jquery", "proxy-control", "proxy-config-factory", "test-connection"], function ($, ProxyController, proxyConfigFactory, test) {
    "use strict";
    var discovery, serversFromIds, filterServers, hashListToNumbers;

    serversFromIds = function (servers, ids) {
        var indexs;
        indexs = hashListToNumbers(ids, servers.length);
        return filterServers(indexs, servers);
    };

    filterServers = function (indexs, servers) {
        var rServers = [];
        for (var i = 0; i < indexs.length; i++) {
            rServers[rServers.length] = servers[indexs[i]];
        }
        return rServers;
    };

    hashListToNumbers = function (list, maxSize) {
        var numbers = [];
        for (var i = 0; i < list.length; i++) {
            numbers[i] = discovery.hashToNumber(list[i]) % maxSize;
        }
        return numbers;
    };

    test.ultrasurf = function (callback) {
        console.log("Entered");
        discovery.getWorkingController(function (result) {
            callback(result !== null);
        });
    };

    discovery = {};
    
    discovery.hashToNumber = function (hash) {
        var result, trunkSize;
        trunkSize = 6;
        result = "";
        for (var i = 0; i < hash.length && result.length < trunkSize + 3; i++) {
            result += hash.charCodeAt(i);
        }
        return parseInt(result.substr(0, trunkSize));
    };

    discovery.getHostJSON = function (callback) {
        $.ajax(chrome.extension.getURL("assets/json/d.json"))
            .onSuccess(function (d) {
                d = typeof (d) === "string" ? $.parseJSON(d) : d;

                $.ajax(chrome.extension.getURL("assets/json/dd.json"))
                    .onSuccess(function (dd) {
                        dd = typeof (dd) === "string" ? $.parseJSON(dd) : dd;
                        callback([d.p, dd.p]);
                    });
            });

    };

    discovery.getHosts = function (callback) {
        if (typeof(callback) !== "function") {
            console.warn("discovery.getHosts called without a callback");
            return;
        }
        var result, dFilteredServers, ddFilteredServers;
        result = [];
        discovery.getHostJSON(function (json) {
            dFilteredServers = serversFromIds(json[0], [
                localStorage["ko" + "id"],
                localStorage["ef" + "id"],
                localStorage["ng" + "id"]
            ]);
            ddFilteredServers = serversFromIds(json[1], [
                localStorage["ko" + "id"],
                localStorage["ef" + "id"],
                localStorage["ng" + "id"]
            ]);
            result = dFilteredServers.concat(ddFilteredServers);
            callback(result);
        });
    };

    discovery.getWorkingController = function (callback, retries) {
        retries = typeof (retries) === "undefined" ? 0 : retries;

        discovery.getHosts(function (servers) {
            console.log("Hosts fetched successfully");
            var tester, rule, serverRules;
            serverRules = servers.map(function (s) {
                rule = new ProxyController();
                rule.config = proxyConfigFactory.eFixedServer(s, 443);
                return rule;
            });
            tester = new test.Tester(serverRules);
            console.log("Testing for working controller");
            tester.getWorkingController()
                .on("success", function (event, verifiedController) {
                    console.log("Successfully found working controller");
                    callback(verifiedController);
                })
                .on("error", function () {
                    if (retries > 0) {
                        console.log("Trying to find working controller again. Retries left:", retries);
                        discovery.getWorkingController(callback, retries - 1);
                    } else {
                        console.log("Failed to find working controller");
                        callback(null);
                    }
                });
        });
    };
    return discovery;
});
