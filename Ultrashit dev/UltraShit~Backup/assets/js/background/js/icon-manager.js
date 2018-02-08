define(function () {
    var iconManager, intervalID, iconState, stopConnecting;
    iconManager = {};
    iconManager.disconnected = function () {
        stopConnecting();
        chrome.browserAction.setIcon({
            path: "assets/img/icon/icon_BW_48.png"
        });
    };

    iconManager.error = function () {
        stopConnecting();
        chrome.browserAction.setIcon({
            path: "assets/img/icon/icon_error_48.png"
        });
    };

    iconManager.connected = function () {
        stopConnecting();
        chrome.browserAction.setIcon({
            path: "assets/img/icon/icon_48.png"
        });
    };

    iconManager.connecting = function () {
        stopConnecting();
        iconState = 1;
        chrome.browserAction.setIcon({
            path: "assets/img/icon/signal/0.png"
        });
        intervalID = setInterval(function () {
            if (iconState === 0) {
                chrome.browserAction.setIcon({
                    path: "assets/img/icon/signal/0.png"
                });
                iconState = 1;
            } else if (iconState === 1) {
                chrome.browserAction.setIcon({
                    path: "assets/img/icon/signal/1.png"
                });
                iconState = 2;
            } else if (iconState === 2) {
                chrome.browserAction.setIcon({
                    path: "assets/img/icon/signal/2.png"
                });
                iconState = 3;
            } else if (iconState === 3) {
                chrome.browserAction.setIcon({
                    path: "assets/img/icon/signal/3.png"
                });
                iconState = 0;
            }

        }, 400);
    };
    stopConnecting = function () {
        clearInterval(intervalID);
        intervalID = undefined;
    };
    return iconManager;
});
