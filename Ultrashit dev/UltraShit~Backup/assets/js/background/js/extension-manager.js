var user_connect, user_disconnect, startTime;
startTime = new Date().getTime();
define(["connection-manager", "state-manager", "error-handler"],
    function (connectionManager, stateManager, errorHandler) {
        "use strict";
        uDev.cleanRestart = function () {
            localStorage.clear();
            chrome.storage.local.clear();
            chrome.runtime.reload();
        };
        user_connect = function () {
            console.log("User Enabled Extension");
            startTime = new Date().getTime();
            localStorage["enabled"] = true;
            if (localStorage["returnUser"] !== "true") {
                localStorage["returnUser"] = true;
            }
            connectionManager.connect();
        };
        user_disconnect = function () {
            console.log("User Disabled Extension");
            var timeSpent = ((new Date().getTime() - startTime) / 1000) / 60;
            //_gaq.push(['_trackTiming', 'Time Enabled', 'Time Enabled', timeSpent]);
            localStorage["enabled"] = false;
            connectionManager.disconnect();
        };
        var extensionManager, shouldSetState;
        extensionManager = {};
        shouldSetState = false;
        extensionManager.startConnectionManager = function () {
            connectionManager.promise
                .on("start", function (event) {
                    if (shouldSetState) {
                        stateManager.set(event);
                    }
                })
                .on("error", function (event) {
                    if (shouldSetState) {
                        stateManager.set(event);
                    }
                    errorHandler.fireErrorModeCallbacks();
                })
                .on("success", function (event) {
                    errorHandler.fireCallbackOnError();
                    if (localStorage["error"] === "true") {
                        errorHandler.fireErrorModeCallbacks();
                    }
                    if (shouldSetState) {
                        stateManager.set(event);
                    }
                    errorHandler.checkForProxyConflicts();
                })
                .on("disconnect", function (event) {
                    localStorage["error"] = false;
                    errorHandler.disableCallbacks();
                    if (shouldSetState) {
                        stateManager.set(event);
                    }
                });
            return extensionManager;
        };
        extensionManager.startErrorHandling = function () {
            errorHandler
                .listenForErrors()
                .on("reconnectSuggestion", function () {
                    console.log("Reconnect Suggestion Accepted");
                    errorHandler.disableCallbacks();
                    connectionManager.connect(function (result) {
                        if (!result) {
                            errorHandler.fireErrorModeCallbacks();
                        }
                    });
                });
            errorHandler
                .listenForProxyConflicts()
                .on("otherProxyExtension", function () {
                    console.log("Proxy Extension Conflict Detected");
                    errorHandler.fireConflictModeCallbacks();
                    stateManager.set("conflict");
                })
                .on("conflictResolved", function () {
                    console.log("Proxy Extension Conflict Resolved");
                    if (localStorage["enabled"] === "false") {
                        stateManager.set("disconnect");
                    }
                });
            return extensionManager;
        };
        extensionManager.startStateManager = function () {
            console.log("State Manager Enabled.");
            shouldSetState = true;
            return extensionManager;
        };
        extensionManager.stopStateManager = function () {
            console.log("State Manager Disabled.");
            shouldSetState = false;
            return extensionManager;
        };
        return extensionManager;
    });