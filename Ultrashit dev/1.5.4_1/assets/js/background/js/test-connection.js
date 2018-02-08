define(["jquery", "promise", "proxy-control"], function ($, Promise, proxyController) {
    "use strict";
    var test, Tester, testConnection, testInternetSingleCallback, testInternet;
    testInternet = function (obj) {
        var testURLs, doCallback, i, failCount;
        if (!obj.onSuccess) {
            obj.onSuccess = function () {
            };
        }
        if (!obj.onError) {
            obj.onError = function () {
            };
        }
        doCallback = true;
        failCount = 0;
        testURLs = [
            "http://a0.awsstatic.com/main/images/logos/footer-logo.gif",
            "http://s3.amazonaws.com/ultrasurfchrome/public/test",
            "https://s3.amazonaws.com/ultrasurfchrome/public/test",
            "http://clients5.google.com/pagead/drt/dn/dn.js",
            "http://www.google.com/",
            "https://www.google.com/"
        ];
        for (i = 0; i < testURLs.length; i++) {
            testConnection(testURLs[i], function (success) {
                if (success && doCallback) {
                    console.log("Successful connection");
                    doCallback = false;
                    obj.onSuccess();
                } else {
                    failCount += 1;
                    if (failCount === testURLs.length) {
                        obj.onError();
                    }
                }
            });
        }
    };

    testInternetSingleCallback = function (callback) {
        testInternet({
            onSuccess: function () {
                callback(true);
            },
            onError: function () {
                callback(false);
            }
        });
    };

    testConnection = function (url, callback) {
        $.ajax({
            url: url,
            timeout: 5000,
            cache: false,
            dataType: 'text',
            onSuccess: function () {
                callback(true);
            },
            onError: function () {
                callback(false);
            }
        });
    };
    test = {};
    test.current = function (callback) {
        testInternetSingleCallback(callback);
    };
    var controllerLock = false;
    var que = [];
    var safeLock = function (callback) {
        controllerLock = true;
        return function (result) {
            try {
                callback(result);
            } catch (e) {
                console.error("Error during callback. Proceeding with unlock.", e);
            }
            safeLock.unlock();

        };
    };
    safeLock.unlock = function () {
        var args;
        controllerLock = false;
        if (que.length > 0) {
            console.log("Executing next test in que.", que.length, "tests waiting.");
            args = que.shift();
            test.controller(args[0], args[1]);
        }
    };
    test.controller = function (controller, callback) {
        if (controllerLock) {
            console.log("Locked. Adding to test Que");
            que.push([controller, callback]);
            return;
        }
        callback = safeLock(callback);
        var previouslyEnabled;
        if (typeof (controller) !== "object") {
            callback(false);
            return;
        }
        previouslyEnabled = proxyController.currentlyEnabled;
        controller.enable(function () {
            testInternetSingleCallback(function (result) {
                previouslyEnabled.enable(function () {
                    callback(result);
                });
            });
        });
    };
    test.controllers = function (controllers, callback) {
        if (controllers.length === 0) {
            callback(false);
            return;
        }
        var rule;
        rule = controllers.pop();
        test.controller(rule, function (result) {
            if (result) {
                callback(rule);
            } else {
                test.controllers(controllers, callback);
            }
        });
    };
    test.internet = function (callback, retries) {
        if (retries === undefined) {
            retries = 0;
        }
        var noProxyTest = new Tester([proxyController.noProxy]);
        noProxyTest.getWorkingController()
            .on("success", function (result) {
                callback(true);
            })
            .on("error", function () {
                if (retries > 0) {
                    test.internet(callback, retries - 1);
                } else {
                    callback(false);
                }
            });
    };

    Tester = (function (controllerList) {
        this.controllerList = controllerList;
    });
    Tester.prototype.getWorkingController = function () {
        var promise;
        promise = new Promise([
            "success",
            "error",
            "complete"
        ]);
        test.controllers(this.controllerList, function (result) {
            if (result === false) {
                promise.fireCallback("error", result);
            } else {
                promise.fireCallback("success", result);
            }
            promise.fireCallback("complete", result);
        });
        return promise;
    };

    test.Tester = Tester;
    uDev.test = test;

    return test;
});