define(["proxy-control", "proxy-config-factory", "discovery", "test-connection", "promise"],
    function (ProxyController, proxyConfigFactory, discovery, test, Promise) {
        "use strict";
        var connect, disconnect, promise;
        promise = new Promise([
            "error",
            "start",
            "success",
            "complete",
            "disconnect"
        ]);

        connect = function (callback, dontFirePromise) {
            console.log("Beginning Connection Process");
            if (!dontFirePromise) {
                promise.fireCallback("start");
            }
            discovery.getWorkingController(function (controller) {
                if (controller !== null) {
                    controller.safeEnable(function () {
                        console.log("Proxy Enabled");
                        if (typeof(callback) === "function" && localStorage["enable"] === "true") {
                            console.log("Proxy Enabled Callback Fired");
                            callback(true);
                        }
                        console.log("Connect callbacks fired: success, complete");
                        if (!dontFirePromise) {
                            promise
                                .fireCallback("success")
                                .fireCallback("complete");
                        }
                    });
                } else {
                    if (typeof (callback) === "function") {
                        callback(false);
                    }
                    if (!dontFirePromise) {
                        promise
                            .fireCallback("error")
                            .fireCallback("complete");
                    }
                }
            });
            return promise;
        };

        disconnect = function (callback) {
            console.log("Began Disconnect Process");
            ProxyController.disable(function () {
                console.log("Proxy Disabled");
                console.log("Firing disconnect promise: disconnect");
                promise.fireCallback("disconnect");
                if (typeof(callback) === "function") {
                    callback();
                }
            });
            return promise;
        };
        return {
            connect: connect,
            disconnect: disconnect,
            promise: promise
        };
    });
