var stateMonitor = angular.module('stateMonitor', ['extensionInterface', 'translateFilter', 'reviewBox']);

stateMonitor.directive('stateProgressBar', function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/state-progress-bar.html',
        controller: ['$scope', 'extensionState', function ($scope, extensionState) {
            var valueSets, currentSet, setPage, prevousColor;
            prevousColor = 'success';
            valueSets = {
                "start": {
                    progressValue: 75,
                    progressColorSetting: 'success',
                    class: 'progress-striped active'
                },
                "error": {
                    progressValue: 25,
                    progressColorSetting: 'success',
                    class: 'progress-striped active'
                },
                "success": {
                    progressValue: 100,
                    progressColorSetting: 'default',
                    class: 'progress-striped active'
                },
                "disconnect": {
                    progressValue: 0,
                    class: 'progress-striped active'
                },
                "conflict": {
                    progressValue: 100,
                    progressColorSetting: 'danger',
                    class: ''
                }
            };
            currentSet = valueSets[extensionState.state];
            setPage = function (valueSet) {
                if (typeof valueSet === "undefined") {
                    console.error("Invalid valueSet", valueSet);
                    return;
                }
                $scope.progressValue = valueSet.progressValue;
                $scope.progressColorSetting = extensionState.state === 'disconnect' ? prevousColor : valueSet.progressColorSetting;
                $scope.class = valueSet.class;
                prevousColor = $scope.progressColorSetting;

            };
            setPage(currentSet);
            extensionState.onChange(function () {
                currentSet = valueSets[extensionState.state];
                setPage(currentSet);
            });
        }]
    };
});

stateMonitor.directive('stateMessage', function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/state-message.html',
        controller: ['$scope', 'extensionState', function ($scope, extensionState) {
            var valueSets, currentSet, setPage;
            valueSets = {
                "start": {
                    stateMessage: 'Connecting',
                    class: ''
                },
                "error": {
                    stateMessage: 'Connecting',
                    class: ''
                },
                "success": {
                    stateMessage: 'Connected',
                    class: 'text-success'
                },
                "disconnect": {
                    stateMessage: 'Disconnected',
                    class: ''
                },
                "conflict": {
                    stateMessage: 'Extension Conflict',
                    class: ''
                }
            };
            currentSet = valueSets[extensionState.state];
            setPage = function (currentSet) {
                if (typeof currentSet === "undefined") {
                    console.error("Invalid valueSet");
                    return;
                }
                $scope.stateMessage = currentSet.stateMessage;
                $scope.class = currentSet.class;

            };
            setPage(currentSet);
            extensionState.onChange(function () {
                currentSet = valueSets[extensionState.state];
                setPage(currentSet);
            });
        }]
    };
});

stateMonitor.directive('stateInformationBox', [function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/state-information-box.html',
        controller: ['$scope', 'extensionState', function ($scope, extensionState) {
            $scope.extensionState = extensionState;
            extensionState.onChange(function () {

            });
        }]
    };
}]);

stateMonitor.directive('stateConnected', function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/state-connected.html',
        controller: ['$scope', 'ratingStore', function ($scope, ratingStore) {
            $scope.dontRequestRating = (parseInt(localStorage['runCount']) < 3 &&
                parseInt(localStorage['enableCount']) < 10) ||
                localStorage['enabled'] === 'false';
            $scope.ratingStore = ratingStore;
        }]
    };
});

stateMonitor.directive('stateError', function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/state-error.html'
    };
});

stateMonitor.directive('stateConflict', function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/state-conflict.html'
    };
});