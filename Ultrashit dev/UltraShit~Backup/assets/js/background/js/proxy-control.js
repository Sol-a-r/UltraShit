define(function () {
    "use strict";
    var ProxyController, noProxy;
    ProxyController = (function () {

    });
    ProxyController.prototype.config = undefined;
    ProxyController.prototype.enable = function (callback) {
        if (typeof(callback) !== "function") {
            callback = function () {
            };
        }
        if (this.config === undefined) {
            callback(false);
            return;
        }
        ProxyController.currentlyEnabled = this;

        chrome.proxy.settings.set(this.config, function () {
            callback(true);
        });
    };
    ProxyController.prototype.safeEnable = function (callback) {
        if (localStorage["enabled"] === "true") {
            this.enable(callback);
        } else {
            callback(false);
        }
    };
    ProxyController.disable = function (callback) {
        chrome.proxy.settings.clear({}, function () {
            ProxyController.currentlyEnabled = noProxy;
            if (typeof(callback) === "function") {
                callback(true);
            }
        });
    };
    ProxyController.prototype.disable = ProxyController.disable;

    noProxy = new ProxyController();
    noProxy.enable = ProxyController.disable;

    ProxyController.noProxy = noProxy;
    ProxyController.currentlyEnabled = noProxy;

    return ProxyController
});