define(function () {
    "use strict";
    var level, log, logFunction, toConsole;
    level = {
        verbose: true,
        error: true,
        info: true,
        warning: true
    };

    logFunction = {
        log: console.log.bind(console),
        error: console.error.bind(console),
        warning: console.warning.bind(console),
        info: console.info.bind(console)
    };

    toConsole = function(inp, fun) {
        logFunction[fun].call(logFunction, inp);
    };

    log = function (inp) {
        toConsole(inp, "log");
    };
    log.error = function (inp) {
        toConsole(inp, "error");
    };
    log.warning = function (inp) {
        toConsole(inp, "warning");
    };
    log.info = function (inp) {
        toConsole(inp, "info");
    };

});