describe("state-manager.js test suite", function () {
    "use strict";
    beforeEach(function (done) {
        jasTest.resetExtension()
            .on("success", function () {
                setTimeout(function () {
                    done();
                }, 2000);
            });
    });
    var stateManager = jasTest.stateManager;
    it("should be defined", function (done) {
        expect(stateManager).toBeDefined();
        done();
    });
    it("should set the icon", function (done) {
        var iconManager = jasTest.iconManager;
        spyOn(iconManager, "connecting");
        stateManager.set("start");
        expect(iconManager.connecting).toHaveBeenCalled();
        expect(jasTest.background().localStorage["state"]).toEqual("start");

        spyOn(iconManager, "connected");
        stateManager.set("success");
        expect(iconManager.connected).toHaveBeenCalled();
        expect(jasTest.background().localStorage["state"]).toEqual("success");

        spyOn(iconManager, "disconnected");
        stateManager.set("disconnect");
        expect(iconManager.disconnected).toHaveBeenCalled();
        expect(jasTest.background().localStorage["state"]).toEqual("disconnect");
        expect(jasTest.background().sessionStorage["state"]).toEqual("disconnect");
        expect(jasTest.background().localStorage["error"]).toEqual("false");
        spyOn(iconManager, "error");
        stateManager.set("error");
        expect(iconManager.error).toHaveBeenCalled();
        expect(jasTest.background().localStorage["state"]).toEqual("error");
        expect(jasTest.background().sessionStorage["state"]).toEqual("error");
        expect(jasTest.background().localStorage["error"]).toEqual("true");
        done();
    });

});