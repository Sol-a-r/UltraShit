define(["crypto"], function (crypto) {
    "use strict";
    var HostDecryptor, CryptoJS, X509;
    CryptoJS = crypto.CryptoJS;
    X509 = crypto.X509;

    HostDecryptor = (function (encryptedHost) {
        var sigHash, certHash, key, eHSplit, sig, host, exp, hasExpDate;
        if (typeof encryptedHost !== "string") {
            this.invalidInput = true;
            console.onError("HostDecryptor input must be a string.");
            return;
        }
        eHSplit = encryptedHost.split(",58,");
        sig = eHSplit[1].split(",").map(function (character) {
            return String.fromCharCode(character);
        }).join("");
        sigHash = CryptoJS.SHA512(sig).toString();
        certHash = CryptoJS.SHA512(HostDecryptor.cert).toString();
        key = CryptoJS.SHA512(sigHash + certHash).toString();

        host = eHSplit[0].split(",").map(function (value, i) {
            var charCode;
            charCode = value ^ key.charCodeAt(i % key.length);
            return String.fromCharCode(charCode);
        }).join("");

        hasExpDate = eHSplit.length >= 3;
        if (hasExpDate) {
            exp = eHSplit[2].split(",").map(function (character) {
                return String.fromCharCode(character)
            }).join("");
        }
        this.hasExpDate = hasExpDate;
        this.host = host;
        this.sig = sig;
        this.exp = exp;
    });

    HostDecryptor.prototype.verifyHost = function () {
        if (this.invalidInput) {
            return false
        }
        var x509, verified, cert;
        x509 = new X509();
        x509.readCertPEM(HostDecryptor.cert);
        verified = true === x509.subjectPublicKeyRSA.verifyString(this.host, this.sig);
        return verified;
    };

    HostDecryptor.prototype.verifyExp = function () {
        var currentDate, expDate;
        if (this.invalidInput || (!this.hasExpDate)) {
            return false;
        }
        currentDate = new Date();
        expDate = new Date(parseInt(this.exp));
        return currentDate.valueOf() < expDate.valueOf()
    };

    HostDecryptor.prototype.invalidInput = false;
    HostDecryptor.cert =
        "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" +
        "BKIRt5KbUSqGSrMZKli78w==";

    return HostDecryptor;
});