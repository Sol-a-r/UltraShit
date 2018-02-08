var extensionInterface = angular.module('extensionInterface', []);

extensionInterface.factory('extensionInfo', function () {
    var getReviewPage, getExtensionPage;
    getExtensionPage = function (id) {
        id = typeof id === 'string' ? id : chrome.runtime.id;
        return "https://chrome.google.com/webstore/detail/" + id;
    };
    getReviewPage = function (id) {
        return getExtensionPage(id) + "/reviews"
    };
    return {
        getExtensionPage: getExtensionPage,
        getReviewPage: getReviewPage
    };
});

extensionInterface.factory('changeTracker', ['$interval', function ($interval) {
    var result;
    result = {
        onStatusChange: function () {
        },
        onStateChange: function () {
        },
        status: localStorage['enabled'],
        state: localStorage['state']
    };
    $interval(function () {
        if (localStorage["state"] !== result.state) {
            result.state = localStorage["state"];
            try {
                result.onStateChange(result.state);
            } catch (e) {
            }
        }
        if (localStorage["enabled"] !== result.status) {
            result.status = localStorage["enabled"];
            try {
                result.onStatusChange(result.status);
            } catch (e) {
            }
        }
    }, 200);
    return result;
}]);

extensionInterface.factory('extensionState', ['changeTracker', function (changeTracker) {
    var result, callbackList;
    callbackList = [];
    result = {
        state: localStorage["state"],
        onChange: function (callback) {
            callbackList.push(callback);
        }
    };
    changeTracker.onStateChange = function (state) {
        result.state = state;
        for (var i = 0; i < callbackList.length; i++) {
            try {
                callbackList[i](result.state);
            } catch (e) {
            }

        }
    };
    return result;
}]);

extensionInterface.factory('extensionStatus', ['changeTracker', function (changeTracker) {
    var result, callbackList;
    callbackList = [];
    result = {
        status: localStorage["enabled"],
        onChange: function (callback) {
            callbackList.push(callback);
        }
    };
    changeTracker.onStatusChange = function (status) {
        result.status = status;
        for (var i = 0; i < callbackList.length; i++) {
            try {
                callbackList[i](result.status);
            } catch (e) {
            }

        }
    };
    return result;
}]);

extensionInterface.factory('controlExtension', [function () {
    return {
        enable: function () {
            ga('send', 'event', 'Switch', 'Enabled', 'enable-disable');
            localStorage["userRequest"] = true;
            chrome.extension.getBackgroundPage().user_connect();
            var value = parseInt(localStorage['enableCount']);
            localStorage['enableCount'] = (value && value > 0 ? value : 0) + 1;
        },
        disable: function () {
            ga('send', 'event', 'Switch', 'Disabled', 'enable-disable');
            localStorage["userRequest"] = false;
            chrome.extension.getBackgroundPage().user_disconnect();
        }
    };
}]);