define(["config-factory-helper"], function (HostDecryptor) {
    var configFactory = {};
    configFactory.fixedServer = function (host, port, scheme) {
        scheme = scheme || "https";
        return {
            value: {
                mode: "fixed_servers",
                rules: {
                    proxyForHttp: {scheme: scheme, host: host, port: port},
                    proxyForHttps: {scheme: scheme, host: host, port: port},
                    proxyForFtp: {scheme: scheme, host: host, port: port},
                    fallbackProxy: {scheme: scheme, host: host, port: port},
                    bypassList: ["<local>", "chrome-devtools://*.*"]
                }
            }
        };
    };
    //eFixedServer = encryptedFixedServer
    configFactory.eFixedServer = function (eHost, port, scheme) {
        var decryptor = new HostDecryptor(eHost);
        return configFactory.fixedServer(decryptor.host, port, scheme);
    };
    configFactory.system = function () {
        return {
            value: {mode: "system"}
        }
    };
    configFactory.direct = function () {
        return {
            value: {mode: "direct"}
        }
    };
    return configFactory;
});