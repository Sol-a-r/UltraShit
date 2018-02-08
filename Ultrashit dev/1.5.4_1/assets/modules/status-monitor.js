var statusMonitor = angular.module('statusMonitor', ['extensionInterface', 'translateFilter']);

statusMonitor.directive("statusMonitorArea", function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/status-monitor.html',
        controller: ['$scope', 'extensionStatus', function ($scope, extensionStatus) {
            var messages, setValues;
            messages = {
                'true': {
                    statusMessage: "You're anonymous. All web activity is encrypted and tunneled through UltraSurf's advanced proxy network.",
                    statusMediaMessage: "Privacy Protected",
                    icon: "assets/img/icon/icon_48.png"
                },
                'false': {
                    statusMessage: "UltraSurf is disabled. Your privacy is not being protected. Turn UltraSurf on to enable privacy protection.",
                    statusMediaMessage: "Protection Disabled",
                    icon: "assets/img/icon/icon_BW_48.png"
                }
            };
            setValues = function (values) {
                $scope.statusMediaMessage = values.statusMediaMessage;
                $scope.statusMessage = values.statusMessage;
                $scope.imageUrl = values.icon;
            };
            setValues(messages[extensionStatus.status]);

            extensionStatus.onChange(function (status) {
                setValues(messages[status]);
            });
        }]
    }
});