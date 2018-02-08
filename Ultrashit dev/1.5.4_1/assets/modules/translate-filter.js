//DELETE_ON_BUILD
var failedToTranslate = false;
var translationHelper = {};
var generateTranslations = function () {
    var st = localStorage["state"];
    var states = [st, "success", "error", "conflict", "start", "disconnect"];
    var iid = window.setInterval(function () {
        console.log("Hello");
        if (states.length === 0) {
            window.clearInterval(iid);
            console.log(JSON.stringify(translationHelper));
        } else {
            localStorage["state"] = states.pop();
        }
    }, 2000);
};
//END_DELETE_ON_BUILD

angular.module('translateFilter', [])
    .filter('translate', function () {
        return function (input) {
            console.log("input", input);
            var key, message;
            try {
                key = "";
                for (var i = 0; i < input.length; i++) {
                    key += "" + input.charCodeAt(i);
                }
                key = input.length + key;
                key = key.replace(/\D/g, '').substr(0, 25);
                message = chrome.i18n.getMessage(key);
                if (message.length > 0) {
                    input = message;
                }

            } catch (e) {

            }
            if (input !== message) {
                console.warn('No translation available:', input);
                failedToTranslate = true;
            }
            //DELETE_ON_BUILD
            if (typeof(key) !== "undefined") {
                translationHelper[key] = {
                    message: input
                };
            }
            //END_DELETE_ON_BUILD
            console.log("output", input);
            return input;
        };
    });