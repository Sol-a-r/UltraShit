var testConnection, app;
testConnection = chrome.extension.getBackgroundPage().jasTest.testConnection;
app = angular.module('app', ['ui.bootstrap'])
    .config([
        '$compileProvider',
        function ($compileProvider) {
            $compileProvider.aHrefSanitizationWhitelist(/^\s*(chrome-extension):/);
            $compileProvider.imgSrcSanitizationWhitelist(/^\s*(chrome-extension):/);
        }
    ]);

app.controller("MainTestCtrl", ["$scope", function ($scope) {
    "use strict";
    var testing = "info";
    var success = "success";
    var failure = "danger";

    $scope.internetConnection = testing;
    $scope.ultrasurfConnection = testing;
    $scope.troubleConnectingMessage = false;
    $scope.showTroubleConnectingMessage = false;
    $scope.diagComplete = false;
    $scope.chrome = chrome;

    testConnection.internet(function (result) {
        console.log(result);
        if (result) {
            $scope.internetConnection = success;
        } else {
            $scope.internetConnection = failure;
        }
        updateTroubleConnectingMessage();
        $scope.$apply();
    }, 3);

    testConnection.ultrasurf(function (result) {
        console.log(result);
        if (result) {
            $scope.ultrasurfConnection = success;
        } else {
            $scope.ultrasurfConnection = failure;
        }
        updateTroubleConnectingMessage();
        $scope.$apply();
    }, 3);

    var updateTroubleConnectingMessage = function () {
        var currentlyTesting = $scope.internetConnection === testing || $scope.ultrasurfConnection === testing;
        if (currentlyTesting) {
            $scope.troubleConnectingMessage = false;
            $scope.showTroubleConnectingMessage = false;
        } else if ($scope.internetConnection === failure) {
            $scope.troubleConnectingMessage = chrome.i18n.getMessage("Please check your internet connection.");
            $scope.showTroubleConnectingMessage = true;
        } else if ($scope.ultrasurfConnection === failure) {
            $scope.troubleConnectingMessage = chrome.i18n.getMessage("Can't connect to UltraSurfs servers. Please try back later.");
            $scope.showTroubleConnectingMessage = true;
        } else {
            $scope.showTroubleConnectingMessage = false;
        }
        if (!currentlyTesting) {
            $scope.diagComplete = true;
        }
    };

}]);
