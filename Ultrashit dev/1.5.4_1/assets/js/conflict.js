var findProxyPermissionConflicts = (function () {
    "use strict";
    var isInConflict, findProxyPermissionConflicts, getIconAndName;

    findProxyPermissionConflicts = function (callback) {
        chrome.management.getAll(function (data) {
            data = data
                .filter(function (x) {
                    return isInConflict(x);
                }).map(function (x) {
                    return getIconAndName(x);
                });
            callback(data);
        });
    };

    isInConflict = function (extensionData) {
        var p = extensionData.permissions;
        if (!extensionData.enabled) {
            return false;
        }
        if (chrome.i18n.getMessage("@@extension_id") === extensionData.id) {
            return false;
        }
        for (var i = 0; i < p.length; i++) {
            if (p[i] === "proxy") {
                return true;
            }
        }
        return false;
    };

    getIconAndName = function (extensionData) {
        var iconAndName, icon;
        iconAndName = {
            name: extensionData.shortName
        };
        icon = extensionData.icons.reduce(function (a, b) {
            if (a.size > b.size) {
                return a;
            }
            return b;
        });
        iconAndName.icon = icon.url;
        iconAndName.id = extensionData.id;
        return iconAndName;
    };

    return findProxyPermissionConflicts;
})();

var uninstallConflictExtensions = (function (done) {
    findProxyPermissionConflicts(function (exts) {
        for (var i = 0; i < exts.length; i++) {
            chrome.management.uninstall(exts[i].id);
        }
        callback(done);
    });
})();