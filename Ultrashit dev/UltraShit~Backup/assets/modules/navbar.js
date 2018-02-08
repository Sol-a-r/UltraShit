var navbar = angular.module('ultrasurfNavbar', []);

navbar.directive('ultrasurfExtensionNavbar', function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/navbar.html'
    };
});