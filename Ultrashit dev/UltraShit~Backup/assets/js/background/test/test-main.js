var allTestFiles = [];
var TEST_REGEXP = /(spec|test)\.js$/i;

var pathToModule = function (path) {
    return path.replace(/^\/base\//, '').replace(/\.js$/, '');
};

Object.keys(window.__karma__.files).forEach(function (file) {
    if (TEST_REGEXP.test(file)) {
        // Normalize paths to RequireJS module names.
        allTestFiles.push(pathToModule(file));
    }
});
var base = "/base/";
var testPath = base + "test";
var jsPath = base + "js";

require.config({
    // Karma serves files under /base, which is the basePath from your config file
    baseUrl: jsPath,
    paths: {
        test: testPath
    },

    // dynamically load all test files
    deps: allTestFiles,

    // we have to kickoff jasmine, as it is asynchronous
    callback: window.__karma__.start
});

window.jasTest = chrome.extension.getBackgroundPage().jasTest;
window.jasTest.localstorage = chrome.extension.getBackgroundPage().localStorage;
window.jasTest.sessionStorage = chrome.extension.getBackgroundPage().sessionStorage;
window.jasTest.background = chrome.extension.getBackgroundPage;
window.jasTest.resetExtension = function () {
    var bg = chrome.extension.getBackgroundPage();
    bg.localStorage["enabled"] = false;
    window.jasTest.connectionManager.disconnect(function () {
        bg.localStorage["enabled"] = true;
        window.jasTest.connectionManager.connect();
    });
    return jasTest.connectionManager.promise;
};