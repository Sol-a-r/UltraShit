var reviewBox;
reviewBox = angular.module("reviewBox", ['ui.bootstrap', 'translateFilter']);

reviewBox.filter('starValue', function () {
    return function (value) {
        var result;
        switch (value) {
            case 1:
                result = "Terrible";
                break;
            case 2:
                result = "Not Good";
                break;
            case 3:
                result = "It Could Be Better";
                break;
            case 4:
                result = "Good";
                break;
            case 5:
                result = "I Love It";
                break;
            default:
                result = "";
        }
        return result;
    };
});

reviewBox.factory('ratingStore', ['$interval', function ($interval) {
    var store, callbackList, iid;
    callbackList = [];
    store = {
        ratingSubmitted: localStorage['REVIEW: ratingSubmitted'] === 'true',
        storeRatingSubmitted: localStorage['REVIEW: storeRatingSubmitted'] === 'true',
        starsGiven: localStorage['REVIEW: ratingStars'],
        onChange: function (callback) {
            callbackList.push(callback);
        }
    };
    iid = $interval(function () {
        var changed = false;
        if (store.ratingSubmitted + '' !== localStorage['REVIEW: ratingSubmitted']) {
            localStorage['REVIEW: ratingSubmitted'] = store.ratingSubmitted;
            changed = true;
        }
        if (store.storeRatingSubmitted + '' !== localStorage['REVIEW: storeRatingSubmitted']) {
            localStorage['REVIEW: storeRatingSubmitted'] = store.storeRatingSubmitted;
            changed = true;
        }
        if (store.starsGiven + '' !== localStorage['REVIEW: ratingStars']) {
            localStorage['REVIEW: ratingStars'] = store.starsGiven;
            changed = true;
        }
        if (changed) {
            console.log(store, localStorage['REVIEW: ratingSubmitted'] === 'false');
            for (var i = 0; i < callbackList.length; i++) {
                try {
                    callbackList[i](store);
                } catch (e) {

                }
            }
        }
        if (store.storeRatingSubmitted || (store.ratingSubmitted && store.starsGiven !== '5')) {
            $interval.cancel(iid);
        }
    }, 200);

    return store
}]);

reviewBox.factory('reviewDataManager', [function () {
    var storage;
    storage = {
        rate: 0
    };
    return storage;
}]);

reviewBox.directive("stars", function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/stars.html',
        controller: ['$scope', 'reviewDataManager', function ($scope, reviewDataManager) {
            $scope.progress = reviewDataManager;
            $scope.stars = 0;
            $scope.hoveringOver = function (stars) {
                $scope.stars = stars;
            };
        }]
    };
});

reviewBox.directive("reviewRequest", function () {
    return {
        restrict: 'E',
        templateUrl: 'templates/review-request.html',
        controller: ['$scope', 'reviewDataManager', 'ratingStore', function ($scope, reviewDataManager, ratingStore) {
            var reviewUrl, id;
            $scope.ratingStore = ratingStore;
            $scope.askForStoreRating =
                ratingStore.ratingSubmitted
                && ratingStore.starsGiven === '5'
                && ratingStore.storeRatingSubmitted !== 'true';
            $scope.ratingReceived = function () {
                ratingStore.ratingSubmitted = true;
                ratingStore.starsGiven = reviewDataManager.rate + '';
                $scope.askForStoreRating = ratingStore.starsGiven === '5';
            };
            //id = chrome.runtime.id;
            id = 'mjnbclmflcpookeapghfhapeffmpodij'
            reviewUrl = "https://chrome.google.com/webstore/detail/" + id + "/reviews";
            $scope.openRatingsPage = function () {
                ratingStore.storeRatingSubmitted = true;
                try {
                    chrome.tabs.create({url: reviewUrl});
                } catch (e) {

                }
            };
        }]
    };
});
