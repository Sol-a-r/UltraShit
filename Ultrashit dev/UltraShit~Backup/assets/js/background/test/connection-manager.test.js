describe("test of connection-manager.js", function () {
    var connectionManager;
    connectionManager = jasTest.connectionManager;
    beforeEach(function (done) {
        jasTest.resetExtension()
            .on("success", function () {
                setTimeout(function () {
                    done();
                }, 2000);
            });
    });

    describe("connect", function () {
        var config;
        beforeEach(function (done) {
            chrome.proxy.settings.get({}, function (c) {
                config = c;
                done();
            });
        });
        it("should be the correct proxy settings", function (done) {
            expect(config.value.mode).toEqual("fixed_servers");
            expect(config.levelOfControl).toEqual("controlled_by_this_extension");
            done();
        });
    });
    describe("disconnect", function () {
        var f1 = {
            f2: function () {
            }
        };
        var config;
        beforeEach(function (done) {
            spyOn(f1, "f2");
            jasTest.resetExtension()
                .on("success", function () {
                    localStorage["enabled"] = false;
                    connectionManager.disconnect(function () {
                        f1.f2();
                        chrome.proxy.settings.get({}, function (c) {
                            config = c;
                            setTimeout(function () {
                                done();
                            }, 2000);
                        });
                    });
                });
        });

        it("Should disconnect", function () {
            expect(config.levelOfControl).toEqual("controllable_by_this_extension");
        });
    });
});