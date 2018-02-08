
define(function () {
    "use strict";
    var Listener, Promise;
    Listener = function (name) {
        this.setName(name);
        this.callbacks = [];
    };
    Listener.prototype.addListener = function (callback) {
        if (typeof (callback) === "function") {
            this.callbacks.push(callback);
        }
    };
    Listener.prototype.fireListenerCallback = function (name, transport) {
        for (var i = 0; i < this.callbacks.length; i++) {
            this.callbacks[i](name, transport);
        }
    };
    Listener.prototype.setName = function (name) {
        if (typeof (name) === "string") {
            this.name = name;
        } else {
            console.error("Invalid setName in Listener");
        }
    };
    Listener.prototype.callbacks = undefined;
    Listener.prototype.name = undefined;

    Promise = function (registerList) {
        this.listeners = {};
        if (!(registerList instanceof Array)) {
            return;
        }
        for (var i = 0; i < registerList.length; i++) {
            this.register(registerList[i]);
        }
    };
    Promise.prototype.register = function (name) {
        name = name.toLowerCase();
        if (typeof (name) === "string") {
            this.listeners[name] = new Listener(name);
        }
        return this;
    };
    Promise.prototype.fireCallback = function (name, transport) {
        name = name.toLowerCase();
        var listener;
        listener = this.getListener(name);
        if (typeof (listener) === "object") {
            listener.fireListenerCallback(name, transport);
        }
        return this;
    };
    Promise.prototype.getListener = function (name) {
        name = name.toLowerCase();
        if (this.listeners.hasOwnProperty(name)) {
            return this.listeners[name];
        } else {
            console.warn("Listener requested was not found: " + name);
        }
    };
    Promise.prototype.addListener = function (name, callback) {
        name = name.toLowerCase();
        var listener;
        listener = this.getListener(name);
        listener.addListener(callback);
        return this;
    };
    Promise.prototype.on = function (name, callback) {
        return this.addListener(name, callback);
    };
    Promise.prototype.listeners = undefined;

    return Promise;
});