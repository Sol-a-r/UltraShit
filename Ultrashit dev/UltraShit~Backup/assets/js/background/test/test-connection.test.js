describe("test-connection test suite", function () {
    "use strict";
    var test = jasTest.testConnection;
    var ProxyController = jasTest.proxyControl;
    var proxyConfigFactory = jasTest.proxyConfigFactory;

    describe("Check for general internet access", function () {
        var temp;
        beforeEach(function (done) {
            temp = {
                success: function () {
                }
            };
            spyOn(temp, "success");
            jasTest.resetExtension()
                .on("success", function () {
                    jasTest.connectionManager.disconnect()
                        .on("disconnect", function () {
                            test.current(function (result) {
                                temp.success(result);
                                setTimeout(function () {
                                    done();
                                }, 2000);
                            });
                        });
                });
        });
        it("should be connected to the internet", function (done) {
            expect(temp.success).toHaveBeenCalledWith(true);
            done();
        });
    });

    describe("test broken controller", function () {
        var brokenController;
        brokenController = new ProxyController();
        brokenController.config = proxyConfigFactory.fixedServer("127.0.0.1");
        var result = undefined;
        beforeEach(function (done) {
            jasTest.resetExtension()
                .on("success", function () {
                    test.controller(brokenController, function (r) {
                        result = r;
                        setTimeout(function () {
                            done();
                        }, 2000);
                    });
                });
        });
        it("should not be working", function (done) {
            expect(result).toBe(false);
            done();
        });
    });
});