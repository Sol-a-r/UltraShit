describe("discovery.js test suite", function () {
    var discovery = jasTest.discovery;
    var HostDecryptor = jasTest.configFactoryHelper;
    it("discovery is defined", function () {
        expect(discovery).toBeDefined();
    });
    it("HostDecryptor is defined", function () {
        expect(HostDecryptor).toBeDefined();
    });
    it("changes hash to number", function () {
        var result = discovery.hashToNumber("The Quick Brown Fox");
        expect(result).toBe(841041);
    });
    describe("test getHostJSON", function () {
        var fetchedHostJSON;
        beforeEach(function (done) {
            jasTest.resetExtension()
                .on("success", function () {
                    discovery.getHostJSON(function (result) {
                        fetchedHostJSON = result[0];
                        setTimeout(function () {
                            jasTest.background().console.log(fetchedHostJSON);
                            done();
                        }, 2000);

                    });
                });
        });
        it("makes sure the correct number of servers were returned", function (done) {
            expect(fetchedHostJSON).toBeDefined();
            expect(fetchedHostJSON.length).toBe(312);
            done();
        });
        it("makes sure the servers are defined", function (done) {
            expect(fetchedHostJSON).toBeDefined();
            done();
        });
        it("makes sure the first option is defined", function (done) {
            expect(fetchedHostJSON[0].toBeDefined);
            done();
        });
        it("makes sure the first option is a string", function (done) {
            expect(typeof(fetchedHostJSON[0])).toEqual("string");
            done();
        });
        xit("the correct data was fetched", function (done) {
            expect(fetchedHostJSON[0]).toContain("21,93,13,5,95,70,87,4,22,8,87,15,4,85,90,2,75,89,90,7,10");
            done();
        });
    });
    describe("test getHosts", function () {
        var fetchedHosts;
        beforeEach(function (done) {
            jasTest.resetExtension()
                .on("success", function () {
                    discovery.getHosts(function (json) {
                        fetchedHosts = json;
                        setTimeout(function () {
                            done();
                        }, 2000);
                    });
                });
        });
        it("fetchedHosts is valid", function (done) {
            expect(fetchedHosts).toBeDefined();
            expect(fetchedHosts.length).toEqual(6);
            done();
        });
        it("the data can be decoded", function (done) {
            var hostDecryptor;
            hostDecryptor = new HostDecryptor(fetchedHosts[0]);
            expect(hostDecryptor.verifyHost()).toEqual(true);
            done();
        });
    });
});