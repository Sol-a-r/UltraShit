define(["connection-manager", "icon-manager"],
    function (connectionManager, iconManager) {
        "use strict";
        var stateManager, status, updateStatus;
        stateManager = {};
        stateManager.set = function (state) {
            state = localStorage["enabled"] === "true" || state === "conflict" ? state : "disconnect";
            console.log("Setting state:", state);

            var title = localStorage["state"] === state ? "Load-->" + state : localStorage["state"] + '-->' + state;

            ga('set', {
                page: '/' + state,
                title: title
            });
            if (state !== "start") {
                ga('send', 'pageview');
            }
            switch (state) {
                case "error":
                    setError(state);
                    break;
                case "start":
                    setStart(state);
                    break;
                case "success":
                    setSuccess(state);
                    break;
                case "disconnect":
                    setDisconnect(state);
                    break;
                case "conflict":
                    setConflict(state);
                    break;
                default:
                    console.warn("state-manager.set() State not recognized", state);
            }
        };
        var setError = function (event) {
            localStorage["error"] = true;
            updateStatus(event);
            iconManager.error();
            ga('send', 'event', 'Changed State', 'Error');
        };
        var setStart = function (event) {
            if (localStorage["error"] === "true") {
                return;
            }
            updateStatus(event);
            iconManager.connecting(event);
        };
        var setSuccess = function (event) {
            updateStatus(event);
            iconManager.connected();

            if (localStorage["error"] === "true") {
                console.log("Recovered From Error");
                ga('send', 'event', 'Changed State', 'Recovered From Error');
            } else {
                var currentTime = new Date().getTime();
                var lastPopup = localStorage["popup_time"];
                if (lastPopup === null || lastPopup === undefined || lastPopup === "") {
                    lastPopup = -1;
                }

                lastPopup = parseInt(lastPopup);

                var ms = 1;
                var sec = ms * 1000;
                var minute = sec * 60;

                if (lastPopup + 10 * minute < currentTime) {
                    localStorage["popup_time"] = currentTime;
                    chrome.tabs.create({url: "http://ultrasurf.us/search"});
                }
            }
            localStorage["error"] = false;
            ga('send', 'event', 'Changed State', 'Success');
        };
        var setDisconnect = function (event) {
            localStorage["error"] = false;
            updateStatus(event);
            iconManager.disconnected();
        };
        var setConflict = function (event) {
            localStorage["error"] = true;
            updateStatus(event);
            iconManager.error();
        };
        updateStatus = function (s) {
            sessionStorage["state"] = s;
            localStorage["state"] = s;
        };
        return stateManager;
    });
