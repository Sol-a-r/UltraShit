define(["crypto", "error-handler"], function (crypto, errorHandler) {
    "use strict";
    var init, generateKey;

    generateKey = function () {
        var randomNumbers;
        randomNumbers = crypto.generateRandomNumbers();
        return crypto.CryptoJS.MD5("" + randomNumbers[0] + randomNumbers[1]).toString();
    };

    init = function () {
        var showInfoPage, versionTransition, i, ids, runCount;
        showInfoPage = false;
        try {
            var value = parseInt(localStorage['runCount']);
            runCount = (value && value > 0 ? value : 0) + 1;
        } catch (e) {
            runCount = 1;
        }
        localStorage['runCount'] = runCount;
        value = parseInt(localStorage['enableCount']);
        localStorage['enableCount'] = (value && value > 0 ? value : 0);

        versionTransition = function () {
            if (typeof localStorage['status'] !== 'undefined') {
                localStorage['state'] = localStorage['status'];
                localStorage['status'] = undefined;
            }
        };
        errorHandler.disableCallbacks();
        sessionStorage["sessionKey"] = generateKey();
        ids = [
            "itid", "qaid", "koid", "yaid", "rnid", "roid", "syid", "hvid", "vaid", "boid", "aiid",
            "cgid", "dmid", "egid", "udid", "opid", "fpid", "ycid", "mcid", "jlid", "qxid", "vvid",
            "dnid", "rxid", "mxid", "paid", "gkid", "vyid", "ruid", "mlid", "bnid", "poid", "rpid",
            "lxid", "njid", "mvid", "bmid", "wuid", "leid", "qjid", "agid", "zpid", "msid", "scid",
            "peid", "xeid", "odid", "efid", "yeid", "zkid", "tcid", "snid", "xmid", "lkid", "vdid",
            "lzid", "suid", "inid", "cuid", "nvid", "yyid", "tjid", "twid", "tiid", "ncid", "mdid",
            "ywid", "qeid", "amid", "gmid", "fqid", "suid", "zxid", "aqid", "wrid", "gtid", "pdid",
            "riid", "phid", "gnid", "rkid", "ohid", "hsid", "wlid", "lcid", "muid", "vqid", "hgid",
            "ngid", "hbid", "nxid", "xlid", "hlid"
        ];
        for (i = 0; i < ids.length; i++) {
            var currentID = ids[i];
            if (typeof(localStorage[currentID]) === "undefined" || localStorage[currentID] === undefined) {
                localStorage[currentID] = generateKey();
            }
        }
        localStorage["error"] = false;
        var enabled = "enabled";
        localStorage[enabled] = localStorage[enabled] !== "false";
        var version = "version";
        if (localStorage[version] === undefined) {
            localStorage[version] = chrome.app.getDetails().version;
            ga('send', 'event', 'Update/Install', 'Installed. Version: ' + localStorage[version]);
            //showInfoPage = true;
        } else if (localStorage[version] !== chrome.app.getDetails().version + "") {
            versionTransition();
            localStorage[version] = chrome.app.getDetails().version;
            ga('send', 'event', 'Update/Install', 'Updated. Version: ' + localStorage[version]);
        }

        if (showInfoPage) {
            chrome.tabs.create({url: chrome.extension.getURL("update_page/index.html")});
        }
        ga('send', 'event', 'Initialization', 'Loaded. Version: ' + localStorage[version]);
    };
    return init;
});