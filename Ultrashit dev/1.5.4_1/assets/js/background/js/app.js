var uDev, translationHelper;
uDev = {};
translationHelper = {};
var getTranslationHelper = function () {
    return translationHelper;
};
var setTranslationHelper = function (value) {
    translationHelper = value;
};
requirejs.config({
    baseUrl: 'assets/js/background/js',
    paths: {
        app: 'js'
    }
});

(function (i, s, o, g, r, a, m) {
    i['GoogleAnalyticsObject'] = r;
    i[r] = i[r] || function () {
            (i[r].q = i[r].q || []).push(arguments)
        }, i[r].l = 1 * new Date();
    a = s.createElement(o),
        m = s.getElementsByTagName(o)[0];
    a.async = 1;
    a.src = g;
    m.parentNode.insertBefore(a, m)
})(window, document, 'script', 'https://ssl.google-analytics.com/analytics.js', 'ga');

ga('create', 'UA-62592345-1', 'auto');
ga('set', 'checkProtocolTask', function () {
});
ga('require', 'displayfeatures');

requirejs(["init", "extension-manager", "connection-manager"],
    function (init, extensionManager, connectionManager) {
        "use strict";
        console.log("App loaded");
        console.log("Beginning App initialization");
        init();
        console.log("App initialized");
        extensionManager
            .startStateManager()
            .startConnectionManager()
            .startErrorHandling();

        if (localStorage["enabled"] !== "false") {
            connectionManager.connect();
        } else {
            connectionManager.disconnect();
        }

    });

require([
    "config-factory-helper",
    "connection-manager",
    "discovery",
    "error-handler",
    "icon-manager",
    "init",
    "promise",
    "proxy-config-factory",
    "proxy-control",
    "state-manager",
    "test-connection"
], function (configFactoryHelper,
             connectionManager,
             discovery,
             errorHandler,
             iconManager,
             init,
             promise,
             proxyConfigFactory,
             proxyControl,
             stateManager,
             testConnection) {
    var test = {};
    test.configFactoryHelper = configFactoryHelper;
    test.connectionManager = connectionManager;
    test.discovery = discovery;
    test.errorHandler = errorHandler;
    test.iconManager = iconManager;
    test.init = init;
    test.promise = promise;
    test.proxyConfigFactory = proxyConfigFactory;
    test.proxyControl = proxyControl;
    test.stateManager = stateManager;
    test.testConnection = testConnection;
    test.background = chrome.extension.getBackgroundPage;
    test.openTestRunner = function () {
        chrome.tabs.create({
            url: "karma-test-runner.html"
        });
    };
    window.jasTest = test;
});