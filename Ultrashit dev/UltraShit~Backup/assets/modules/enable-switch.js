var enableDisableSwitch = angular.module('enableDisableSwitch', ['frapontillo.bootstrap-switch', 'extensionInterface']);

enableDisableSwitch.directive('enableSwitch', [function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/switch.html',
        controller: ['$scope', 'controlExtension', function ($scope, controlExtension) {
            $scope.onText = 'On';
            $scope.offText = 'Off';
            $scope.onColor = "primary";
            $scope.offColor = "default";
            $scope.size = 'mini';
            $scope.isSelected = localStorage['enabled'] === 'true';
            var initialized = false;
            $scope.$watch('isSelected', function () {
                if (!initialized) {
                    initialized = true;
                    return;
                }
                if ($scope.isSelected) {
                    controlExtension.enable();
                } else {
                    controlExtension.disable();
                }
            });
        }]
    };
}]);