define(["connection-manager", "promise"], function (connectionManager, Promise) {
    "use strict";
    var errorHandler, retrySuggestionsIsEnabled, errorHandlingIsEnabled,
        promise, proxyErrorFired, conflictModeEnabled, fireReconnectSuggestion,
        controlledFireProxyError;
    conflictModeEnabled = false;
    errorHandlingIsEnabled = false;
    retrySuggestionsIsEnabled = false;
    proxyErrorFired = false;
    errorHandler = {};
    promise = new Promise([
        "reconnectSuggestion",
        "otherProxyExtension",
        "conflictResolved"
    ]);
    fireReconnectSuggestion = function () {
        if (localStorage["enabled"] !== "false") {
            promise.fireCallback("reconnectSuggestion");
        } else {
            console.warn("reconnectSuggestions can not be fired while extension is disabled");
        }
    };

    controlledFireProxyError = function () {
        if (proxyErrorFired) {
            return;
        }
        proxyErrorFired = true;
        setTimeout(function () {
            proxyErrorFired = false;
        }, 5000);
        fireReconnectSuggestion();
    };


    errorHandler.listenForErrors = function () {
        setInterval(function () {
            if (errorHandlingIsEnabled && retrySuggestionsIsEnabled) {
                fireReconnectSuggestion();
            }
        }, 15000);
        chrome.webRequest.onBeforeRequest.addListener(function () {
            if (errorHandlingIsEnabled && retrySuggestionsIsEnabled) {
                fireReconnectSuggestion();
            }
        }, {
            urls: ["<all_urls>"]
        });
        chrome.proxy.onProxyError.addListener(function () {
            if (errorHandlingIsEnabled) {
                controlledFireProxyError();
            } else {
                console.log("Proxy Error Reconnect Suggestion Rejected");
            }
        });
        return promise;
    };
    errorHandler.fireCallbackOnError = function () {
        if (localStorage["enabled"] === "false") {
            console.warn("Can't set error callback level while disabled");
            return;
        }
        console.log("Error Callback Mode Set: Proxy Error Only");
        errorHandlingIsEnabled = true;
        retrySuggestionsIsEnabled = false;
        conflictModeEnabled = false;
    };
    errorHandler.disableCallbacks = function () {
        console.log("Error Callback Mode Set: Callbacks Disabled");
        errorHandlingIsEnabled = false;
        retrySuggestionsIsEnabled = false;
        conflictModeEnabled = false;
    };
    errorHandler.fireErrorModeCallbacks = function () {
        if (localStorage["enabled"] === "false") {
            console.warn("Can't set error callback level while disabled");
            return;
        }
        console.log("Error Callback Mode Set: Error Mode Callbacks");
        retrySuggestionsIsEnabled = true;
        errorHandlingIsEnabled = true;
        conflictModeEnabled = false;
    };
    errorHandler.fireConflictModeCallbacks = function () {
        if (localStorage["enabled"] === "false") {
            console.warn("Can't set error callback level while disabled");
            return;
        }
        console.log("Error Callback Mode Set: Conflict Resolution Callbacks Only");
        conflictModeEnabled = true;
        retrySuggestionsIsEnabled = false;
        errorHandlingIsEnabled = false;
    };
    errorHandler.checkForProxyConflicts = function () {
        chrome.proxy.settings.get({}, function (data) {
            if (!(data.levelOfControl === "controllable_by_this_extension" || data.levelOfControl === "controlled_by_this_extension")) {
                if (!conflictModeEnabled) {
                    promise.fireCallback("otherProxyExtension");
                    ga('send', 'event', 'Proxy Conflict', 'Proxy Extension Conflict Detected');
                }
            } else if (conflictModeEnabled) {
                fireReconnectSuggestion();
                promise.fireCallback("conflictResolved");
                ga('send', 'event', 'Proxy Conflict', 'Proxy Extension Conflict Resolved');
            }
        });
    };
    errorHandler.listenForProxyConflicts = function () {
        console.log("Listening for proxy conflicts");
        errorHandler.checkForProxyConflicts();
        setInterval(function () {
            errorHandler.checkForProxyConflicts();
        }, 10000);
        return promise;
    };
    return errorHandler;
});