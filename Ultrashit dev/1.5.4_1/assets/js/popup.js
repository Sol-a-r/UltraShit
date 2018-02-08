var backgroundPage = chrome.extension.getBackgroundPage();
var require = backgroundPage.require;
var ga = backgroundPage.ga;
ga = ga ? ga : function () {
};
ga('send', 'event', 'DEV', 'New Popup GA Working');
var app = angular.module('app', ['frapontillo.bootstrap-switch', 'ui.bootstrap'])
    .config([
        '$compileProvider',
        function ($compileProvider) {
            $compileProvider.aHrefSanitizationWhitelist(/^\s*(chrome-extension):/);
            $compileProvider.imgSrcSanitizationWhitelist(/^\s*(chrome-extension):/);
        }
    ]);

var enableSwitch = {};
enableSwitch.set = function (option, dontTriggerListener) {
    if (enableSwitch.getState !== option) {
        $('input[name="my-checkbox"]').bootstrapSwitch('state', option, dontTriggerListener);
    }
};
enableSwitch.getState = function () {
    return $('input[name="my-checkbox"]').bootstrapSwitch('state');
};

app.controller('HeaderCtrl', ['$scope', function ($scope) {
    $scope.feedbackTitle = "Feedback";
    $scope.feedbackMessage = chrome.i18n.getMessage("headerFeedbackMessage") + " info89@ultrasurf.us";
    $scope.infoPageName = chrome.i18n.getMessage("infoPageName");
    $scope.infoPageOpen = function () {
        ga('send', 'event', 'Information Page', 'Opened From Browser Action');
    }
}]);

app.controller('StateCtrl', ['$scope', function ($scope) {
    $scope.onText = 'On';
    $scope.offText = 'Off';
    $scope.onColor = "primary";
    $scope.offColor = "default";
    $scope.size = 'mini';
    var iid = setInterval(function () {
        clearInterval(iid);
        enableSwitch.set(!(localStorage["enabled"] === "false"), true);
        $scope.state = enableSwitch.getState();
        $scope.stateString = $scope.state ? enableString : disableString;
        $scope.imageUrl = $scope.state ? enableImg : disableImg;
        $scope.statusMessage = $scope.state ? enableMessage : disableMessage;
        $scope.$apply();
    }, 200);
    var enableString = chrome.i18n.getMessage("enableString");
    var disableString = chrome.i18n.getMessage("disableString");
    var enableImg = "../icon/icon_48.png";
    var disableImg = "../icon/icon_BW_48.png";
    var enableMessage = chrome.i18n.getMessage("enableMessage");
    var disableMessage = chrome.i18n.getMessage("disableMessage");

    $('input[name="my-checkbox"]').on('switchChange.bootstrapSwitch', function (event, state) {
        $scope.state = state;
        if (state) {
            ga('send', 'event', 'Switch', 'Enabled', 'enable-disable');
            $scope.stateString = enableString;
            $scope.statusMessage = enableMessage;
            $scope.imageUrl = enableImg;
            localStorage["userRequest"] = true;
            chrome.extension.getBackgroundPage().user_connect();

        } else {
            ga('send', 'event', 'Switch', 'Disabled', 'enable-disable');
            $scope.stateString = disableString;
            $scope.statusMessage = disableMessage;
            $scope.imageUrl = disableImg;
            localStorage["userRequest"] = false;
            chrome.extension.getBackgroundPage().user_disconnect();
        }
        $scope.$apply();
    });
}]);

app.controller('StatusControl', ['$scope', function ($scope) {
    $scope.showConnecting = false;
    $scope.showConnected = false;
    $scope.showDisconnected = false;
    $scope.showError = false;
    $scope.showConflict = false;
    $scope.troubleConnectingMessage = chrome.i18n.getMessage("openDiagnosticsMessage");
    $scope.connectingTitle = chrome.i18n.getMessage("connectingMessage"); //Connecting
    $scope.connectedTitle = chrome.i18n.getMessage("connectedTitle"); // connected
    $scope.disconnectedTitle = chrome.i18n.getMessage("disconnectedTitle"); //Disconnected
    $scope.conflictTitle = chrome.i18n.getMessage("conflictTitle"); // Extension Conflict
    $scope.thankYouMessage = chrome.i18n.getMessage("thankYouMessage");
    $scope.feedbackRequestMessage = chrome.i18n.getMessage("feedbackRequestMessage");
    $scope.submitButtonText = chrome.i18n.getMessage("submitButtonText");
    $scope.thankYouForFeedbackMessage = chrome.i18n.getMessage("thankYouForFeedbackMessage");
    $scope.rateExtensionButtonText = chrome.i18n.getMessage("rateExtensionButtonText");
    $scope.conflictMessage = chrome.i18n.getMessage("conflictMessage");


    var previous = undefined;
    setInterval(function () {
        if (localStorage["status"] !== previous) {
            previous = localStorage["status"];
            console.log(previous);
            switch (localStorage["status"]) {
                case "start":
                    $scope.showConnecting = true;
                    $scope.showConnected = false;
                    $scope.showDisconnected = false;
                    $scope.showError = false;
                    $scope.showConflict = false;
                    break;
                case "error":
                    $scope.showError = true;
                    $scope.showConnecting = false;
                    $scope.showConnected = false;
                    $scope.showDisconnected = false;
                    $scope.showConflict = false;
                    break;
                case "success":
                    $scope.showConnected = true;
                    $scope.showConnecting = false;
                    $scope.showDisconnected = false;
                    $scope.showError = false;
                    $scope.showConflict = false;
                    break;
                case "disconnect":
                    $scope.showDisconnected = true;
                    $scope.showConnecting = false;
                    $scope.showConnected = false;
                    $scope.showError = false;
                    $scope.showConflict = false;
                    break;
                case "conflict":
                    $scope.showConflict = true;
                    $scope.showConnecting = false;
                    $scope.showConnected = false;
                    $scope.showDisconnected = false;
                    $scope.showError = false;
            }
            $scope.$apply();
            console.log(
                $scope.showConnecting,
                $scope.showConnected,
                $scope.showDisconnected,
                $scope.showError,
                $scope.showConflict
            );
        }
    }, 200);

}]);

angular.module('app').controller('RatingCtrl', ["$scope", function ($scope) {
    $scope.isCollapsed = true;
    $scope.askForStoreRating = localStorage["ratingGiven"] === "5" && localStorage["ratingsPageOpened"] !== "true";
    $scope.askForRating = localStorage["returnUser"] === "true" && localStorage["ratingReceived"] !== "true";
    $scope.rate = 0;
    $scope.max = 5;
    $scope.isReadonly = false;

    $scope.hoveringOver = function (value) {
        $scope.overStar = value;
        switch (value) {
            case 1:
                $scope.message = "Terrible";
                break;
            case 2:
                $scope.message = "Not Good";
                break;
            case 3:
                $scope.message = "It Could Be Better";
                break;
            case 4:
                $scope.message = "Good";
                break;
            case 5:
                $scope.message = "I Love It";
                break;
        }
        if ($scope.rate > 0) {
            $scope.isCollapsed = false;
        }
    };
    $scope.ratingReceived = function () {
        localStorage["ratingReceived"] = true;
        localStorage["ratingGiven"] = $scope.rate;
        $scope.askForStoreRating = localStorage["ratingGiven"] === "5";
        ga('send', 'event', 'Rating-Given', "Rating Given: " + localStorage["ratingGiven"]);
    };
    $scope.openRatingsPage = function () {
        ga('send', 'event', 'Rating-Given', "Chrome Store Rating Page Opened");
        localStorage["ratingsPageOpened"] = true;
        chrome.tabs.create({url: "https://chrome.google.com/webstore/detail/ultrasurf/mjnbclmflcpookeapghfhapeffmpodij/reviews"})
    };
    var iid;
    $scope.waitForSelection = function () {
        console.log("called");
        if (iid === undefined) {
            iid = setInterval(function () {
                if ($scope.rate > 0) {
                    $scope.isCollapsed = false;
                    clearInterval(iid);
                }
            }, 25);
        }
    };
    $scope.$watch("rate", function () {
        console.log("called", $scope.rate);
        if ($scope.rate > 0) {
            $scope.isCollapsed = false;
        }
    });
    $scope.stopWaiting = function () {
        clearInterval(iid);
    };
    $scope.ratingStates = [
        {stateOn: 'glyphicon-ok-sign', stateOff: 'glyphicon-ok-circle'},
        {stateOn: 'glyphicon-star', stateOff: 'glyphicon-star-empty'},
        {stateOn: 'glyphicon-heart', stateOff: 'glyphicon-ban-circle'},
        {stateOn: 'glyphicon-heart'},
        {stateOff: 'glyphicon-off'}
    ];
}]);