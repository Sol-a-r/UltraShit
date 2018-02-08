define(function () {


    /*! asn1hex-1.1.4.js (c) 2012-2013 Kenji Urushima | kjur.github.com/jsrsasign/license
     */
    /*
     * asn1hex.js - Hexadecimal represented ASN.1 string library
     *
     * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
     *
     * This software is licensed under the terms of the MIT License.
     * http://kjur.github.com/jsrsasign/license/
     *
     * The above copyright and license notice shall be
     * included in all copies or substantial portions of the Software.
     */

    /**
     * @fileOverview
     * @name asn1hex-1.1.js
     * @author Kenji Urushima kenji.urushima@gmail.com
     * @version asn1hex 1.1.4 (2013-Oct-02)
     * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
     */

    /*
     * MEMO:
     *   f('3082025b02...', 2) ... 82025b ... 3bytes
     *   f('020100', 2) ... 01 ... 1byte
     *   f('0203001...', 2) ... 03 ... 1byte
     *   f('02818003...', 2) ... 8180 ... 2bytes
     *   f('3080....0000', 2) ... 80 ... -1
     *
     *   Requirements:
     *   - ASN.1 type octet length MUST be 1.
     *     (i.e. ASN.1 primitives like SET, SEQUENCE, INTEGER, OCTETSTRING ...)
     */

    /**
     * ASN.1 DER encoded hexadecimal string utility class
     * @name ASN1HEX
     * @class ASN.1 DER encoded hexadecimal string utility class
     * @since jsrsasign 1.1
     */
    var ASN1HEX = new function () {
        /**
         * get byte length for ASN.1 L(length) bytes
         * @name getByteLengthOfL_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         * @return byte length for ASN.1 L(length) bytes
         */
        this.getByteLengthOfL_AtObj = function (s, pos) {
            if (s.substring(pos + 2, pos + 3) != '8') return 1;
            var i = parseInt(s.substring(pos + 3, pos + 4));
            if (i == 0) return -1; 		// length octet '80' indefinite length
            if (0 < i && i < 10) return i + 1;	// including '8?' octet;
            return -2;				// malformed format
        };

        /**
         * get hexadecimal string for ASN.1 L(length) bytes
         * @name getHexOfL_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         * @return {String} hexadecimal string for ASN.1 L(length) bytes
         */
        this.getHexOfL_AtObj = function (s, pos) {
            var len = this.getByteLengthOfL_AtObj(s, pos);
            if (len < 1) return '';
            return s.substring(pos + 2, pos + 2 + len * 2);
        };

        //   getting ASN.1 length value at the position 'idx' of
        //   hexa decimal string 's'.
        //
        //   f('3082025b02...', 0) ... 82025b ... ???
        //   f('020100', 0) ... 01 ... 1
        //   f('0203001...', 0) ... 03 ... 3
        //   f('02818003...', 0) ... 8180 ... 128
        /**
         * get integer value of ASN.1 length for ASN.1 data
         * @name getIntOfL_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         * @return ASN.1 L(length) integer value
         */
        this.getIntOfL_AtObj = function (s, pos) {
            var hLength = this.getHexOfL_AtObj(s, pos);
            if (hLength == '') return -1;
            var bi;
            if (parseInt(hLength.substring(0, 1)) < 8) {
                bi = new BigInteger(hLength, 16);
            } else {
                bi = new BigInteger(hLength.substring(2), 16);
            }
            return bi.intValue();
        };

        /**
         * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
         * @name getStartPosOfV_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         */
        this.getStartPosOfV_AtObj = function (s, pos) {
            var l_len = this.getByteLengthOfL_AtObj(s, pos);
            if (l_len < 0) return l_len;
            return pos + (l_len + 1) * 2;
        };

        /**
         * get hexadecimal string of ASN.1 V(value)
         * @name getHexOfV_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         * @return {String} hexadecimal string of ASN.1 value.
         */
        this.getHexOfV_AtObj = function (s, pos) {
            var pos1 = this.getStartPosOfV_AtObj(s, pos);
            var len = this.getIntOfL_AtObj(s, pos);
            return s.substring(pos1, pos1 + len * 2);
        };

        /**
         * get hexadecimal string of ASN.1 TLV at
         * @name getHexOfTLV_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         * @return {String} hexadecimal string of ASN.1 TLV.
         * @since 1.1
         */
        this.getHexOfTLV_AtObj = function (s, pos) {
            var hT = s.substr(pos, 2);
            var hL = this.getHexOfL_AtObj(s, pos);
            var hV = this.getHexOfV_AtObj(s, pos);
            return hT + hL + hV;
        };

        /**
         * get next sibling starting index for ASN.1 object string
         * @name getPosOfNextSibling_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} pos string index
         * @return next sibling starting index for ASN.1 object string
         */
        this.getPosOfNextSibling_AtObj = function (s, pos) {
            var pos1 = this.getStartPosOfV_AtObj(s, pos);
            var len = this.getIntOfL_AtObj(s, pos);
            return pos1 + len * 2;
        };

        /**
         * get array of indexes of child ASN.1 objects
         * @name getPosArrayOfChildren_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} s hexadecimal string of ASN.1 DER encoded data
         * @param {Number} start string index of ASN.1 object
         * @return {Array of Number} array of indexes for childen of ASN.1 objects
         */
        this.getPosArrayOfChildren_AtObj = function (h, pos) {
            var a = new Array();
            var p0 = this.getStartPosOfV_AtObj(h, pos);
            a.push(p0);

            var len = this.getIntOfL_AtObj(h, pos);
            var p = p0;
            var k = 0;
            while (1) {
                var pNext = this.getPosOfNextSibling_AtObj(h, p);
                if (pNext == null || (pNext - p0 >= (len * 2))) break;
                if (k >= 200) break;

                a.push(pNext);
                p = pNext;

                k++;
            }

            return a;
        };

        /**
         * get string index of nth child object of ASN.1 object refered by h, idx
         * @name getNthChildIndex_AtObj
         * @memberOf ASN1HEX
         * @function
         * @param {String} h hexadecimal string of ASN.1 DER encoded data
         * @param {Number} idx start string index of ASN.1 object
         * @param {Number} nth for child
         * @return {Number} string index of nth child.
         * @since 1.1
         */
        this.getNthChildIndex_AtObj = function (h, idx, nth) {
            var a = this.getPosArrayOfChildren_AtObj(h, idx);
            return a[nth];
        };

        // ========== decendant methods ==============================
        /**
         * get string index of nth child object of ASN.1 object refered by h, idx
         * @name getDecendantIndexByNthList
         * @memberOf ASN1HEX
         * @function
         * @param {String} h hexadecimal string of ASN.1 DER encoded data
         * @param {Number} currentIndex start string index of ASN.1 object
         * @param {Array of Number} nthList array list of nth
         * @return {Number} string index refered by nthList
         * @since 1.1
         * @example
         * The "nthList" is a index list of structured ASN.1 object
         * reference. Here is a sample structure and "nthList"s which
         * refers each objects.
         *
         * SQUENCE               - [0]
         *   SEQUENCE            - [0, 0]
         *     IA5STRING 000     - [0, 0, 0]
         *     UTF8STRING 001    - [0, 0, 1]
         *   SET                 - [0, 1]
         *     IA5STRING 010     - [0, 1, 0]
         *     UTF8STRING 011    - [0, 1, 1]
         */
        this.getDecendantIndexByNthList = function (h, currentIndex, nthList) {
            if (nthList.length == 0) {
                return currentIndex;
            }
            var firstNth = nthList.shift();
            var a = this.getPosArrayOfChildren_AtObj(h, currentIndex);
            return this.getDecendantIndexByNthList(h, a[firstNth], nthList);
        };

        /**
         * get hexadecimal string of ASN.1 TLV refered by current index and nth index list.
         * @name getDecendantHexTLVByNthList
         * @memberOf ASN1HEX
         * @function
         * @param {String} h hexadecimal string of ASN.1 DER encoded data
         * @param {Number} currentIndex start string index of ASN.1 object
         * @param {Array of Number} nthList array list of nth
         * @return {Number} hexadecimal string of ASN.1 TLV refered by nthList
         * @since 1.1
         */
        this.getDecendantHexTLVByNthList = function (h, currentIndex, nthList) {
            var idx = this.getDecendantIndexByNthList(h, currentIndex, nthList);
            return this.getHexOfTLV_AtObj(h, idx);
        };

        /**
         * get hexadecimal string of ASN.1 V refered by current index and nth index list.
         * @name getDecendantHexVByNthList
         * @memberOf ASN1HEX
         * @function
         * @param {String} h hexadecimal string of ASN.1 DER encoded data
         * @param {Number} currentIndex start string index of ASN.1 object
         * @param {Array of Number} nthList array list of nth
         * @return {Number} hexadecimal string of ASN.1 V refered by nthList
         * @since 1.1
         */
        this.getDecendantHexVByNthList = function (h, currentIndex, nthList) {
            var idx = this.getDecendantIndexByNthList(h, currentIndex, nthList);
            return this.getHexOfV_AtObj(h, idx);
        };
    };

    /**
     * @since asn1hex 1.1.4
     */
    ASN1HEX.getVbyList = function (h, currentIndex, nthList, checkingTag) {
        var idx = this.getDecendantIndexByNthList(h, currentIndex, nthList);
        if (idx === undefined) {
            throw "can't find nthList object";
        }
        if (checkingTag !== undefined) {
            if (h.substr(idx, 2) != checkingTag) {
                throw "checking tag doesn't match: " + h.substr(idx, 2) + "!=" + checkingTag;
            }
        }
        return this.getHexOfV_AtObj(h, idx);
    };


    /*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
     */
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
    var dbits;

// JavaScript engine analysis
    var canary = 0xdeadbeefcafe;
    var j_lm = ((canary & 0xffffff) == 0xefcafe);

// (public) Constructor
    function BigInteger(a, b, c) {
        if (a != null)
            if ("number" == typeof a) this.fromNumber(a, b, c);
            else if (b == null && "string" != typeof a) this.fromString(a, 256);
            else this.fromString(a, b);
    }

// return new, unset BigInteger
    function nbi() {
        return new BigInteger(null);
    }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
    function am1(i, x, w, j, c, n) {
        while (--n >= 0) {
            var v = x * this[i++] + w[j] + c;
            c = Math.floor(v / 0x4000000);
            w[j++] = v & 0x3ffffff;
        }
        return c;
    }

// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
    function am2(i, x, w, j, c, n) {
        var xl = x & 0x7fff, xh = x >> 15;
        while (--n >= 0) {
            var l = this[i] & 0x7fff;
            var h = this[i++] >> 15;
            var m = xh * l + h * xl;
            l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
            c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
            w[j++] = l & 0x3fffffff;
        }
        return c;
    }

// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
    function am3(i, x, w, j, c, n) {
        var xl = x & 0x3fff, xh = x >> 14;
        while (--n >= 0) {
            var l = this[i] & 0x3fff;
            var h = this[i++] >> 14;
            var m = xh * l + h * xl;
            l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w[j++] = l & 0xfffffff;
        }
        return c;
    }

    if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
        BigInteger.prototype.am = am2;
        dbits = 30;
    }
    else if (j_lm && (navigator.appName != "Netscape")) {
        BigInteger.prototype.am = am1;
        dbits = 26;
    }
    else { // Mozilla/Netscape seems to prefer am3
        BigInteger.prototype.am = am3;
        dbits = 28;
    }

    BigInteger.prototype.DB = dbits;
    BigInteger.prototype.DM = ((1 << dbits) - 1);
    BigInteger.prototype.DV = (1 << dbits);

    var BI_FP = 52;
    BigInteger.prototype.FV = Math.pow(2, BI_FP);
    BigInteger.prototype.F1 = BI_FP - dbits;
    BigInteger.prototype.F2 = 2 * dbits - BI_FP;

// Digit conversions
    var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
    var BI_RC = new Array();
    var rr, vv;
    rr = "0".charCodeAt(0);
    for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
    rr = "a".charCodeAt(0);
    for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
    rr = "A".charCodeAt(0);
    for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

    function int2char(n) {
        return BI_RM.charAt(n);
    }

    function intAt(s, i) {
        var c = BI_RC[s.charCodeAt(i)];
        return (c == null) ? -1 : c;
    }

// (protected) copy this to r
    function bnpCopyTo(r) {
        for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
        r.t = this.t;
        r.s = this.s;
    }

// (protected) set from integer value x, -DV <= x < DV
    function bnpFromInt(x) {
        this.t = 1;
        this.s = (x < 0) ? -1 : 0;
        if (x > 0) this[0] = x;
        else if (x < -1) this[0] = x + this.DV;
        else this.t = 0;
    }

// return bigint initialized to value
    function nbv(i) {
        var r = nbi();
        r.fromInt(i);
        return r;
    }

// (protected) set from string and radix
    function bnpFromString(s, b) {
        var k;
        if (b == 16) k = 4;
        else if (b == 8) k = 3;
        else if (b == 256) k = 8; // byte array
        else if (b == 2) k = 1;
        else if (b == 32) k = 5;
        else if (b == 4) k = 2;
        else {
            this.fromRadix(s, b);
            return;
        }
        this.t = 0;
        this.s = 0;
        var i = s.length, mi = false, sh = 0;
        while (--i >= 0) {
            var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
            if (x < 0) {
                if (s.charAt(i) == "-") mi = true;
                continue;
            }
            mi = false;
            if (sh == 0)
                this[this.t++] = x;
            else if (sh + k > this.DB) {
                this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                this[this.t++] = (x >> (this.DB - sh));
            }
            else
                this[this.t - 1] |= x << sh;
            sh += k;
            if (sh >= this.DB) sh -= this.DB;
        }
        if (k == 8 && (s[0] & 0x80) != 0) {
            this.s = -1;
            if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
        }
        this.clamp();
        if (mi) BigInteger.ZERO.subTo(this, this);
    }

// (protected) clamp off excess high words
    function bnpClamp() {
        var c = this.s & this.DM;
        while (this.t > 0 && this[this.t - 1] == c) --this.t;
    }

// (public) return string representation in given radix
    function bnToString(b) {
        if (this.s < 0) return "-" + this.negate().toString(b);
        var k;
        if (b == 16) k = 4;
        else if (b == 8) k = 3;
        else if (b == 2) k = 1;
        else if (b == 32) k = 5;
        else if (b == 4) k = 2;
        else return this.toRadix(b);
        var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
        var p = this.DB - (i * this.DB) % k;
        if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) > 0) {
                m = true;
                r = int2char(d);
            }
            while (i >= 0) {
                if (p < k) {
                    d = (this[i] & ((1 << p) - 1)) << (k - p);
                    d |= this[--i] >> (p += this.DB - k);
                }
                else {
                    d = (this[i] >> (p -= k)) & km;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if (d > 0) m = true;
                if (m) r += int2char(d);
            }
        }
        return m ? r : "0";
    }

// (public) -this
    function bnNegate() {
        var r = nbi();
        BigInteger.ZERO.subTo(this, r);
        return r;
    }

// (public) |this|
    function bnAbs() {
        return (this.s < 0) ? this.negate() : this;
    }

// (public) return + if this > a, - if this < a, 0 if equal
    function bnCompareTo(a) {
        var r = this.s - a.s;
        if (r != 0) return r;
        var i = this.t;
        r = i - a.t;
        if (r != 0) return (this.s < 0) ? -r : r;
        while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
        return 0;
    }

// returns bit length of the integer x
    function nbits(x) {
        var r = 1, t;
        if ((t = x >>> 16) != 0) {
            x = t;
            r += 16;
        }
        if ((t = x >> 8) != 0) {
            x = t;
            r += 8;
        }
        if ((t = x >> 4) != 0) {
            x = t;
            r += 4;
        }
        if ((t = x >> 2) != 0) {
            x = t;
            r += 2;
        }
        if ((t = x >> 1) != 0) {
            x = t;
            r += 1;
        }
        return r;
    }

// (public) return the number of bits in "this"
    function bnBitLength() {
        if (this.t <= 0) return 0;
        return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
    }

// (protected) r = this << n*DB
    function bnpDLShiftTo(n, r) {
        var i;
        for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
        for (i = n - 1; i >= 0; --i) r[i] = 0;
        r.t = this.t + n;
        r.s = this.s;
    }

// (protected) r = this >> n*DB
    function bnpDRShiftTo(n, r) {
        for (var i = n; i < this.t; ++i) r[i - n] = this[i];
        r.t = Math.max(this.t - n, 0);
        r.s = this.s;
    }

// (protected) r = this << n
    function bnpLShiftTo(n, r) {
        var bs = n % this.DB;
        var cbs = this.DB - bs;
        var bm = (1 << cbs) - 1;
        var ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
        for (i = this.t - 1; i >= 0; --i) {
            r[i + ds + 1] = (this[i] >> cbs) | c;
            c = (this[i] & bm) << bs;
        }
        for (i = ds - 1; i >= 0; --i) r[i] = 0;
        r[ds] = c;
        r.t = this.t + ds + 1;
        r.s = this.s;
        r.clamp();
    }

// (protected) r = this >> n
    function bnpRShiftTo(n, r) {
        r.s = this.s;
        var ds = Math.floor(n / this.DB);
        if (ds >= this.t) {
            r.t = 0;
            return;
        }
        var bs = n % this.DB;
        var cbs = this.DB - bs;
        var bm = (1 << bs) - 1;
        r[0] = this[ds] >> bs;
        for (var i = ds + 1; i < this.t; ++i) {
            r[i - ds - 1] |= (this[i] & bm) << cbs;
            r[i - ds] = this[i] >> bs;
        }
        if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
        r.t = this.t - ds;
        r.clamp();
    }

// (protected) r = this - a
    function bnpSubTo(a, r) {
        var i = 0, c = 0, m = Math.min(a.t, this.t);
        while (i < m) {
            c += this[i] - a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < this.t) {
            c -= a.s;
            while (i < this.t) {
                c += this[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += this.s;
        }
        else {
            c += this.s;
            while (i < a.t) {
                c -= a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c -= a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c < -1) r[i++] = this.DV + c;
        else if (c > 0) r[i++] = c;
        r.t = i;
        r.clamp();
    }

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
    function bnpMultiplyTo(a, r) {
        var x = this.abs(), y = a.abs();
        var i = x.t;
        r.t = i + y.t;
        while (--i >= 0) r[i] = 0;
        for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
        r.s = 0;
        r.clamp();
        if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
    }

// (protected) r = this^2, r != this (HAC 14.16)
    function bnpSquareTo(r) {
        var x = this.abs();
        var i = r.t = 2 * x.t;
        while (--i >= 0) r[i] = 0;
        for (i = 0; i < x.t - 1; ++i) {
            var c = x.am(i, x[i], r, 2 * i, 0, 1);
            if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                r[i + x.t] -= x.DV;
                r[i + x.t + 1] = 1;
            }
        }
        if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
        r.s = 0;
        r.clamp();
    }

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
    function bnpDivRemTo(m, q, r) {
        var pm = m.abs();
        if (pm.t <= 0) return;
        var pt = this.abs();
        if (pt.t < pm.t) {
            if (q != null) q.fromInt(0);
            if (r != null) this.copyTo(r);
            return;
        }
        if (r == null) r = nbi();
        var y = nbi(), ts = this.s, ms = m.s;
        var nsh = this.DB - nbits(pm[pm.t - 1]);	// normalize modulus
        if (nsh > 0) {
            pm.lShiftTo(nsh, y);
            pt.lShiftTo(nsh, r);
        }
        else {
            pm.copyTo(y);
            pt.copyTo(r);
        }
        var ys = y.t;
        var y0 = y[ys - 1];
        if (y0 == 0) return;
        var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
        var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
        var i = r.t, j = i - ys, t = (q == null) ? nbi() : q;
        y.dlShiftTo(j, t);
        if (r.compareTo(t) >= 0) {
            r[r.t++] = 1;
            r.subTo(t, r);
        }
        BigInteger.ONE.dlShiftTo(ys, t);
        t.subTo(y, y);	// "negative" y so we can replace sub with am later
        while (y.t < ys) y[y.t++] = 0;
        while (--j >= 0) {
            // Estimate quotient digit
            var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
            if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {	// Try it out
                y.dlShiftTo(j, t);
                r.subTo(t, r);
                while (r[i] < --qd) r.subTo(t, r);
            }
        }
        if (q != null) {
            r.drShiftTo(ys, q);
            if (ts != ms) BigInteger.ZERO.subTo(q, q);
        }
        r.t = ys;
        r.clamp();
        if (nsh > 0) r.rShiftTo(nsh, r);	// Denormalize remainder
        if (ts < 0) BigInteger.ZERO.subTo(r, r);
    }

// (public) this mod a
    function bnMod(a) {
        var r = nbi();
        this.abs().divRemTo(a, null, r);
        if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
        return r;
    }

// Modular reduction using "classic" algorithm
    function Classic(m) {
        this.m = m;
    }

    function cConvert(x) {
        if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
        else return x;
    }

    function cRevert(x) {
        return x;
    }

    function cReduce(x) {
        x.divRemTo(this.m, null, x);
    }

    function cMulTo(x, y, r) {
        x.multiplyTo(y, r);
        this.reduce(r);
    }

    function cSqrTo(x, r) {
        x.squareTo(r);
        this.reduce(r);
    }

    Classic.prototype.convert = cConvert;
    Classic.prototype.revert = cRevert;
    Classic.prototype.reduce = cReduce;
    Classic.prototype.mulTo = cMulTo;
    Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
    function bnpInvDigit() {
        if (this.t < 1) return 0;
        var x = this[0];
        if ((x & 1) == 0) return 0;
        var y = x & 3;		// y == 1/x mod 2^2
        y = (y * (2 - (x & 0xf) * y)) & 0xf;	// y == 1/x mod 2^4
        y = (y * (2 - (x & 0xff) * y)) & 0xff;	// y == 1/x mod 2^8
        y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;	// y == 1/x mod 2^16
        // last step - calculate inverse mod DV directly;
        // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
        y = (y * (2 - x * y % this.DV)) % this.DV;		// y == 1/x mod 2^dbits
        // we really want the negative inverse, and -DV < y < DV
        return (y > 0) ? this.DV - y : -y;
    }

// Montgomery reduction
    function Montgomery(m) {
        this.m = m;
        this.mp = m.invDigit();
        this.mpl = this.mp & 0x7fff;
        this.mph = this.mp >> 15;
        this.um = (1 << (m.DB - 15)) - 1;
        this.mt2 = 2 * m.t;
    }

// xR mod m
    function montConvert(x) {
        var r = nbi();
        x.abs().dlShiftTo(this.m.t, r);
        r.divRemTo(this.m, null, r);
        if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
        return r;
    }

// x/R mod m
    function montRevert(x) {
        var r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }

// x = x/R mod m (HAC 14.32)
    function montReduce(x) {
        while (x.t <= this.mt2)	// pad x so am has enough room later
            x[x.t++] = 0;
        for (var i = 0; i < this.m.t; ++i) {
            // faster way of calculating u0 = x[i]*mp mod DV
            var j = x[i] & 0x7fff;
            var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
            // use am to combine the multiply-shift-add into one call
            j = i + this.m.t;
            x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
            // propagate carry
            while (x[j] >= x.DV) {
                x[j] -= x.DV;
                x[++j]++;
            }
        }
        x.clamp();
        x.drShiftTo(this.m.t, x);
        if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
    }

// r = "x^2/R mod m"; x != r
    function montSqrTo(x, r) {
        x.squareTo(r);
        this.reduce(r);
    }

// r = "xy/R mod m"; x,y != r
    function montMulTo(x, y, r) {
        x.multiplyTo(y, r);
        this.reduce(r);
    }

    Montgomery.prototype.convert = montConvert;
    Montgomery.prototype.revert = montRevert;
    Montgomery.prototype.reduce = montReduce;
    Montgomery.prototype.mulTo = montMulTo;
    Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
    function bnpIsEven() {
        return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
    }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
    function bnpExp(e, z) {
        if (e > 0xffffffff || e < 1) return BigInteger.ONE;
        var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
        g.copyTo(r);
        while (--i >= 0) {
            z.sqrTo(r, r2);
            if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
            else {
                var t = r;
                r = r2;
                r2 = t;
            }
        }
        return z.revert(r);
    }

// (public) this^e % m, 0 <= e < 2^32
    function bnModPowInt(e, m) {
        var z;
        if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
        return this.exp(e, z);
    }

// protected
    BigInteger.prototype.copyTo = bnpCopyTo;
    BigInteger.prototype.fromInt = bnpFromInt;
    BigInteger.prototype.fromString = bnpFromString;
    BigInteger.prototype.clamp = bnpClamp;
    BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
    BigInteger.prototype.drShiftTo = bnpDRShiftTo;
    BigInteger.prototype.lShiftTo = bnpLShiftTo;
    BigInteger.prototype.rShiftTo = bnpRShiftTo;
    BigInteger.prototype.subTo = bnpSubTo;
    BigInteger.prototype.multiplyTo = bnpMultiplyTo;
    BigInteger.prototype.squareTo = bnpSquareTo;
    BigInteger.prototype.divRemTo = bnpDivRemTo;
    BigInteger.prototype.invDigit = bnpInvDigit;
    BigInteger.prototype.isEven = bnpIsEven;
    BigInteger.prototype.exp = bnpExp;

// public
    BigInteger.prototype.toString = bnToString;
    BigInteger.prototype.negate = bnNegate;
    BigInteger.prototype.abs = bnAbs;
    BigInteger.prototype.compareTo = bnCompareTo;
    BigInteger.prototype.bitLength = bnBitLength;
    BigInteger.prototype.mod = bnMod;
    BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
    BigInteger.ZERO = nbv(0);
    BigInteger.ONE = nbv(1);

    /*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
     */
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
    function bnClone() {
        var r = nbi();
        this.copyTo(r);
        return r;
    }

// (public) return value as integer
    function bnIntValue() {
        if (this.s < 0) {
            if (this.t == 1) return this[0] - this.DV;
            else if (this.t == 0) return -1;
        }
        else if (this.t == 1) return this[0];
        else if (this.t == 0) return 0;
        // assumes 16 < DB < 32
        return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
    }

// (public) return value as byte
    function bnByteValue() {
        return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
    }

// (public) return value as short (assumes DB>=16)
    function bnShortValue() {
        return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
    }

// (protected) return x s.t. r^x < DV
    function bnpChunkSize(r) {
        return Math.floor(Math.LN2 * this.DB / Math.log(r));
    }

// (public) 0 if this == 0, 1 if this > 0
    function bnSigNum() {
        if (this.s < 0) return -1;
        else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
        else return 1;
    }

// (protected) convert to radix string
    function bnpToRadix(b) {
        if (b == null) b = 10;
        if (this.signum() == 0 || b < 2 || b > 36) return "0";
        var cs = this.chunkSize(b);
        var a = Math.pow(b, cs);
        var d = nbv(a), y = nbi(), z = nbi(), r = "";
        this.divRemTo(d, y, z);
        while (y.signum() > 0) {
            r = (a + z.intValue()).toString(b).substr(1) + r;
            y.divRemTo(d, y, z);
        }
        return z.intValue().toString(b) + r;
    }

// (protected) convert from radix string
    function bnpFromRadix(s, b) {
        this.fromInt(0);
        if (b == null) b = 10;
        var cs = this.chunkSize(b);
        var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
        for (var i = 0; i < s.length; ++i) {
            var x = intAt(s, i);
            if (x < 0) {
                if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
                continue;
            }
            w = b * w + x;
            if (++j >= cs) {
                this.dMultiply(d);
                this.dAddOffset(w, 0);
                j = 0;
                w = 0;
            }
        }
        if (j > 0) {
            this.dMultiply(Math.pow(b, j));
            this.dAddOffset(w, 0);
        }
        if (mi) BigInteger.ZERO.subTo(this, this);
    }

// (protected) alternate constructor
    function bnpFromNumber(a, b, c) {
        if ("number" == typeof b) {
            // new BigInteger(int,int,RNG)
            if (a < 2) this.fromInt(1);
            else {
                this.fromNumber(a, c);
                if (!this.testBit(a - 1))	// force MSB set
                    this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
                if (this.isEven()) this.dAddOffset(1, 0); // force odd
                while (!this.isProbablePrime(b)) {
                    this.dAddOffset(2, 0);
                    if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
                }
            }
        }
        else {
            // new BigInteger(int,RNG)
            var x = new Array(), t = a & 7;
            x.length = (a >> 3) + 1;
            b.nextBytes(x);
            if (t > 0) x[0] &= ((1 << t) - 1); else x[0] = 0;
            this.fromString(x, 256);
        }
    }

// (public) convert to bigendian byte array
    function bnToByteArray() {
        var i = this.t, r = new Array();
        r[0] = this.s;
        var p = this.DB - (i * this.DB) % 8, d, k = 0;
        if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
                r[k++] = d | (this.s << (this.DB - p));
            while (i >= 0) {
                if (p < 8) {
                    d = (this[i] & ((1 << p) - 1)) << (8 - p);
                    d |= this[--i] >> (p += this.DB - 8);
                }
                else {
                    d = (this[i] >> (p -= 8)) & 0xff;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if ((d & 0x80) != 0) d |= -256;
                if (k == 0 && (this.s & 0x80) != (d & 0x80)) ++k;
                if (k > 0 || d != this.s) r[k++] = d;
            }
        }
        return r;
    }

    function bnEquals(a) {
        return (this.compareTo(a) == 0);
    }

    function bnMin(a) {
        return (this.compareTo(a) < 0) ? this : a;
    }

    function bnMax(a) {
        return (this.compareTo(a) > 0) ? this : a;
    }

// (protected) r = this op a (bitwise)
    function bnpBitwiseTo(a, op, r) {
        var i, f, m = Math.min(a.t, this.t);
        for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
        if (a.t < this.t) {
            f = a.s & this.DM;
            for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
            r.t = this.t;
        }
        else {
            f = this.s & this.DM;
            for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
            r.t = a.t;
        }
        r.s = op(this.s, a.s);
        r.clamp();
    }

// (public) this & a
    function op_and(x, y) {
        return x & y;
    }

    function bnAnd(a) {
        var r = nbi();
        this.bitwiseTo(a, op_and, r);
        return r;
    }

// (public) this | a
    function op_or(x, y) {
        return x | y;
    }

    function bnOr(a) {
        var r = nbi();
        this.bitwiseTo(a, op_or, r);
        return r;
    }

// (public) this ^ a
    function op_xor(x, y) {
        return x ^ y;
    }

    function bnXor(a) {
        var r = nbi();
        this.bitwiseTo(a, op_xor, r);
        return r;
    }

// (public) this & ~a
    function op_andnot(x, y) {
        return x & ~y;
    }

    function bnAndNot(a) {
        var r = nbi();
        this.bitwiseTo(a, op_andnot, r);
        return r;
    }

// (public) ~this
    function bnNot() {
        var r = nbi();
        for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
        r.t = this.t;
        r.s = ~this.s;
        return r;
    }

// (public) this << n
    function bnShiftLeft(n) {
        var r = nbi();
        if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r);
        return r;
    }

// (public) this >> n
    function bnShiftRight(n) {
        var r = nbi();
        if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r);
        return r;
    }

// return index of lowest 1-bit in x, x < 2^31
    function lbit(x) {
        if (x == 0) return -1;
        var r = 0;
        if ((x & 0xffff) == 0) {
            x >>= 16;
            r += 16;
        }
        if ((x & 0xff) == 0) {
            x >>= 8;
            r += 8;
        }
        if ((x & 0xf) == 0) {
            x >>= 4;
            r += 4;
        }
        if ((x & 3) == 0) {
            x >>= 2;
            r += 2;
        }
        if ((x & 1) == 0) ++r;
        return r;
    }

// (public) returns index of lowest 1-bit (or -1 if none)
    function bnGetLowestSetBit() {
        for (var i = 0; i < this.t; ++i)
            if (this[i] != 0) return i * this.DB + lbit(this[i]);
        if (this.s < 0) return this.t * this.DB;
        return -1;
    }

// return number of 1 bits in x
    function cbit(x) {
        var r = 0;
        while (x != 0) {
            x &= x - 1;
            ++r;
        }
        return r;
    }

// (public) return number of set bits
    function bnBitCount() {
        var r = 0, x = this.s & this.DM;
        for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
        return r;
    }

// (public) true iff nth bit is set
    function bnTestBit(n) {
        var j = Math.floor(n / this.DB);
        if (j >= this.t) return (this.s != 0);
        return ((this[j] & (1 << (n % this.DB))) != 0);
    }

// (protected) this op (1<<n)
    function bnpChangeBit(n, op) {
        var r = BigInteger.ONE.shiftLeft(n);
        this.bitwiseTo(r, op, r);
        return r;
    }

// (public) this | (1<<n)
    function bnSetBit(n) {
        return this.changeBit(n, op_or);
    }

// (public) this & ~(1<<n)
    function bnClearBit(n) {
        return this.changeBit(n, op_andnot);
    }

// (public) this ^ (1<<n)
    function bnFlipBit(n) {
        return this.changeBit(n, op_xor);
    }

// (protected) r = this + a
    function bnpAddTo(a, r) {
        var i = 0, c = 0, m = Math.min(a.t, this.t);
        while (i < m) {
            c += this[i] + a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < this.t) {
            c += a.s;
            while (i < this.t) {
                c += this[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += this.s;
        }
        else {
            c += this.s;
            while (i < a.t) {
                c += a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c > 0) r[i++] = c;
        else if (c < -1) r[i++] = this.DV + c;
        r.t = i;
        r.clamp();
    }

// (public) this + a
    function bnAdd(a) {
        var r = nbi();
        this.addTo(a, r);
        return r;
    }

// (public) this - a
    function bnSubtract(a) {
        var r = nbi();
        this.subTo(a, r);
        return r;
    }

// (public) this * a
    function bnMultiply(a) {
        var r = nbi();
        this.multiplyTo(a, r);
        return r;
    }

// (public) this^2
    function bnSquare() {
        var r = nbi();
        this.squareTo(r);
        return r;
    }

// (public) this / a
    function bnDivide(a) {
        var r = nbi();
        this.divRemTo(a, r, null);
        return r;
    }

// (public) this % a
    function bnRemainder(a) {
        var r = nbi();
        this.divRemTo(a, null, r);
        return r;
    }

// (public) [this/a,this%a]
    function bnDivideAndRemainder(a) {
        var q = nbi(), r = nbi();
        this.divRemTo(a, q, r);
        return new Array(q, r);
    }

// (protected) this *= n, this >= 0, 1 < n < DV
    function bnpDMultiply(n) {
        this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
        ++this.t;
        this.clamp();
    }

// (protected) this += n << w words, this >= 0
    function bnpDAddOffset(n, w) {
        if (n == 0) return;
        while (this.t <= w) this[this.t++] = 0;
        this[w] += n;
        while (this[w] >= this.DV) {
            this[w] -= this.DV;
            if (++w >= this.t) this[this.t++] = 0;
            ++this[w];
        }
    }

// A "null" reducer
    function NullExp() {
    }

    function nNop(x) {
        return x;
    }

    function nMulTo(x, y, r) {
        x.multiplyTo(y, r);
    }

    function nSqrTo(x, r) {
        x.squareTo(r);
    }

    NullExp.prototype.convert = nNop;
    NullExp.prototype.revert = nNop;
    NullExp.prototype.mulTo = nMulTo;
    NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
    function bnPow(e) {
        return this.exp(e, new NullExp());
    }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
    function bnpMultiplyLowerTo(a, n, r) {
        var i = Math.min(this.t + a.t, n);
        r.s = 0; // assumes a,this >= 0
        r.t = i;
        while (i > 0) r[--i] = 0;
        var j;
        for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
        for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
        r.clamp();
    }

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
    function bnpMultiplyUpperTo(a, n, r) {
        --n;
        var i = r.t = this.t + a.t - n;
        r.s = 0; // assumes a,this >= 0
        while (--i >= 0) r[i] = 0;
        for (i = Math.max(n - this.t, 0); i < a.t; ++i)
            r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
        r.clamp();
        r.drShiftTo(1, r);
    }

// Barrett modular reduction
    function Barrett(m) {
        // setup Barrett
        this.r2 = nbi();
        this.q3 = nbi();
        BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
        this.mu = this.r2.divide(m);
        this.m = m;
    }

    function barrettConvert(x) {
        if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
        else if (x.compareTo(this.m) < 0) return x;
        else {
            var r = nbi();
            x.copyTo(r);
            this.reduce(r);
            return r;
        }
    }

    function barrettRevert(x) {
        return x;
    }

// x = x mod m (HAC 14.42)
    function barrettReduce(x) {
        x.drShiftTo(this.m.t - 1, this.r2);
        if (x.t > this.m.t + 1) {
            x.t = this.m.t + 1;
            x.clamp();
        }
        this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
        this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
        while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
        x.subTo(this.r2, x);
        while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
    }

// r = x^2 mod m; x != r
    function barrettSqrTo(x, r) {
        x.squareTo(r);
        this.reduce(r);
    }

// r = x*y mod m; x,y != r
    function barrettMulTo(x, y, r) {
        x.multiplyTo(y, r);
        this.reduce(r);
    }

    Barrett.prototype.convert = barrettConvert;
    Barrett.prototype.revert = barrettRevert;
    Barrett.prototype.reduce = barrettReduce;
    Barrett.prototype.mulTo = barrettMulTo;
    Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
    function bnModPow(e, m) {
        var i = e.bitLength(), k, r = nbv(1), z;
        if (i <= 0) return r;
        else if (i < 18) k = 1;
        else if (i < 48) k = 3;
        else if (i < 144) k = 4;
        else if (i < 768) k = 5;
        else k = 6;
        if (i < 8)
            z = new Classic(m);
        else if (m.isEven())
            z = new Barrett(m);
        else
            z = new Montgomery(m);

        // precomputation
        var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
        g[1] = z.convert(this);
        if (k > 1) {
            var g2 = nbi();
            z.sqrTo(g[1], g2);
            while (n <= km) {
                g[n] = nbi();
                z.mulTo(g2, g[n - 2], g[n]);
                n += 2;
            }
        }

        var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
        i = nbits(e[j]) - 1;
        while (j >= 0) {
            if (i >= k1) w = (e[j] >> (i - k1)) & km;
            else {
                w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
            }

            n = k;
            while ((w & 1) == 0) {
                w >>= 1;
                --n;
            }
            if ((i -= n) < 0) {
                i += this.DB;
                --j;
            }
            if (is1) {	// ret == 1, don't bother squaring or multiplying it
                g[w].copyTo(r);
                is1 = false;
            }
            else {
                while (n > 1) {
                    z.sqrTo(r, r2);
                    z.sqrTo(r2, r);
                    n -= 2;
                }
                if (n > 0) z.sqrTo(r, r2); else {
                    t = r;
                    r = r2;
                    r2 = t;
                }
                z.mulTo(r2, g[w], r);
            }

            while (j >= 0 && (e[j] & (1 << i)) == 0) {
                z.sqrTo(r, r2);
                t = r;
                r = r2;
                r2 = t;
                if (--i < 0) {
                    i = this.DB - 1;
                    --j;
                }
            }
        }
        return z.revert(r);
    }

// (public) gcd(this,a) (HAC 14.54)
    function bnGCD(a) {
        var x = (this.s < 0) ? this.negate() : this.clone();
        var y = (a.s < 0) ? a.negate() : a.clone();
        if (x.compareTo(y) < 0) {
            var t = x;
            x = y;
            y = t;
        }
        var i = x.getLowestSetBit(), g = y.getLowestSetBit();
        if (g < 0) return x;
        if (i < g) g = i;
        if (g > 0) {
            x.rShiftTo(g, x);
            y.rShiftTo(g, y);
        }
        while (x.signum() > 0) {
            if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
            if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
            if (x.compareTo(y) >= 0) {
                x.subTo(y, x);
                x.rShiftTo(1, x);
            }
            else {
                y.subTo(x, y);
                y.rShiftTo(1, y);
            }
        }
        if (g > 0) y.lShiftTo(g, y);
        return y;
    }

// (protected) this % n, n < 2^26
    function bnpModInt(n) {
        if (n <= 0) return 0;
        var d = this.DV % n, r = (this.s < 0) ? n - 1 : 0;
        if (this.t > 0)
            if (d == 0) r = this[0] % n;
            else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
        return r;
    }

// (public) 1/this % m (HAC 14.61)
    function bnModInverse(m) {
        var ac = m.isEven();
        if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
        var u = m.clone(), v = this.clone();
        var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
        while (u.signum() != 0) {
            while (u.isEven()) {
                u.rShiftTo(1, u);
                if (ac) {
                    if (!a.isEven() || !b.isEven()) {
                        a.addTo(this, a);
                        b.subTo(m, b);
                    }
                    a.rShiftTo(1, a);
                }
                else if (!b.isEven()) b.subTo(m, b);
                b.rShiftTo(1, b);
            }
            while (v.isEven()) {
                v.rShiftTo(1, v);
                if (ac) {
                    if (!c.isEven() || !d.isEven()) {
                        c.addTo(this, c);
                        d.subTo(m, d);
                    }
                    c.rShiftTo(1, c);
                }
                else if (!d.isEven()) d.subTo(m, d);
                d.rShiftTo(1, d);
            }
            if (u.compareTo(v) >= 0) {
                u.subTo(v, u);
                if (ac) a.subTo(c, a);
                b.subTo(d, b);
            }
            else {
                v.subTo(u, v);
                if (ac) c.subTo(a, c);
                d.subTo(b, d);
            }
        }
        if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
        if (d.compareTo(m) >= 0) return d.subtract(m);
        if (d.signum() < 0) d.addTo(m, d); else return d;
        if (d.signum() < 0) return d.add(m); else return d;
    }

    var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
    var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

// (public) test primality with certainty >= 1-.5^t
    function bnIsProbablePrime(t) {
        var i, x = this.abs();
        if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
            for (i = 0; i < lowprimes.length; ++i)
                if (x[0] == lowprimes[i]) return true;
            return false;
        }
        if (x.isEven()) return false;
        i = 1;
        while (i < lowprimes.length) {
            var m = lowprimes[i], j = i + 1;
            while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
            m = x.modInt(m);
            while (i < j) if (m % lowprimes[i++] == 0) return false;
        }
        return x.millerRabin(t);
    }

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
    function bnpMillerRabin(t) {
        var n1 = this.subtract(BigInteger.ONE);
        var k = n1.getLowestSetBit();
        if (k <= 0) return false;
        var r = n1.shiftRight(k);
        t = (t + 1) >> 1;
        if (t > lowprimes.length) t = lowprimes.length;
        var a = nbi();
        for (var i = 0; i < t; ++i) {
            //Pick bases at random, instead of starting at 2
            a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
            var y = a.modPow(r, this);
            if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
                var j = 1;
                while (j++ < k && y.compareTo(n1) != 0) {
                    y = y.modPowInt(2, this);
                    if (y.compareTo(BigInteger.ONE) == 0) return false;
                }
                if (y.compareTo(n1) != 0) return false;
            }
        }
        return true;
    }

// protected
    BigInteger.prototype.chunkSize = bnpChunkSize;
    BigInteger.prototype.toRadix = bnpToRadix;
    BigInteger.prototype.fromRadix = bnpFromRadix;
    BigInteger.prototype.fromNumber = bnpFromNumber;
    BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
    BigInteger.prototype.changeBit = bnpChangeBit;
    BigInteger.prototype.addTo = bnpAddTo;
    BigInteger.prototype.dMultiply = bnpDMultiply;
    BigInteger.prototype.dAddOffset = bnpDAddOffset;
    BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
    BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
    BigInteger.prototype.modInt = bnpModInt;
    BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
    BigInteger.prototype.clone = bnClone;
    BigInteger.prototype.intValue = bnIntValue;
    BigInteger.prototype.byteValue = bnByteValue;
    BigInteger.prototype.shortValue = bnShortValue;
    BigInteger.prototype.signum = bnSigNum;
    BigInteger.prototype.toByteArray = bnToByteArray;
    BigInteger.prototype.equals = bnEquals;
    BigInteger.prototype.min = bnMin;
    BigInteger.prototype.max = bnMax;
    BigInteger.prototype.and = bnAnd;
    BigInteger.prototype.or = bnOr;
    BigInteger.prototype.xor = bnXor;
    BigInteger.prototype.andNot = bnAndNot;
    BigInteger.prototype.not = bnNot;
    BigInteger.prototype.shiftLeft = bnShiftLeft;
    BigInteger.prototype.shiftRight = bnShiftRight;
    BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
    BigInteger.prototype.bitCount = bnBitCount;
    BigInteger.prototype.testBit = bnTestBit;
    BigInteger.prototype.setBit = bnSetBit;
    BigInteger.prototype.clearBit = bnClearBit;
    BigInteger.prototype.flipBit = bnFlipBit;
    BigInteger.prototype.add = bnAdd;
    BigInteger.prototype.subtract = bnSubtract;
    BigInteger.prototype.multiply = bnMultiply;
    BigInteger.prototype.divide = bnDivide;
    BigInteger.prototype.remainder = bnRemainder;
    BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
    BigInteger.prototype.modPow = bnModPow;
    BigInteger.prototype.modInverse = bnModInverse;
    BigInteger.prototype.pow = bnPow;
    BigInteger.prototype.gcd = bnGCD;
    BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
    BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)


    /*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
     */
// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
    function parseBigInt(str, r) {
        return new BigInteger(str, r);
    }

    function linebrk(s, n) {
        var ret = "";
        var i = 0;
        while (i + n < s.length) {
            ret += s.substring(i, i + n) + "\n";
            i += n;
        }
        return ret + s.substring(i, s.length);
    }

    function byte2Hex(b) {
        if (b < 0x10)
            return "0" + b.toString(16);
        else
            return b.toString(16);
    }

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
    function pkcs1pad2(s, n) {
        if (n < s.length + 11) { // TODO: fix for utf-8
            alert("Message too long for RSA");
            return null;
        }
        var ba = new Array();
        var i = s.length - 1;
        while (i >= 0 && n > 0) {
            var c = s.charCodeAt(i--);
            if (c < 128) { // encode using utf-8
                ba[--n] = c;
            }
            else if ((c > 127) && (c < 2048)) {
                ba[--n] = (c & 63) | 128;
                ba[--n] = (c >> 6) | 192;
            }
            else {
                ba[--n] = (c & 63) | 128;
                ba[--n] = ((c >> 6) & 63) | 128;
                ba[--n] = (c >> 12) | 224;
            }
        }
        ba[--n] = 0;
        var rng = new SecureRandom();
        var x = new Array();
        while (n > 2) { // random non-zero pad
            x[0] = 0;
            while (x[0] == 0) rng.nextBytes(x);
            ba[--n] = x[0];
        }
        ba[--n] = 2;
        ba[--n] = 0;
        return new BigInteger(ba);
    }

// PKCS#1 (OAEP) mask generation function
    function oaep_mgf1_arr(seed, len, hash) {
        var mask = '', i = 0;

        while (mask.length < len) {
            mask += hash(String.fromCharCode.apply(String, seed.concat([
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff])));
            i += 1;
        }

        return mask;
    }

    var SHA1_SIZE = 20;

// PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
    function oaep_pad(s, n, hash) {
        if (s.length + 2 * SHA1_SIZE + 2 > n) {
            throw "Message too long for RSA";
        }

        var PS = '', i;

        for (i = 0; i < n - s.length - 2 * SHA1_SIZE - 2; i += 1) {
            PS += '\x00';
        }

        var DB = rstr_sha1('') + PS + '\x01' + s;
        var seed = new Array(SHA1_SIZE);
        new SecureRandom().nextBytes(seed);

        var dbMask = oaep_mgf1_arr(seed, DB.length, hash || rstr_sha1);
        var maskedDB = [];

        for (i = 0; i < DB.length; i += 1) {
            maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
        }

        var seedMask = oaep_mgf1_arr(maskedDB, seed.length, rstr_sha1);
        var maskedSeed = [0];

        for (i = 0; i < seed.length; i += 1) {
            maskedSeed[i + 1] = seed[i] ^ seedMask.charCodeAt(i);
        }

        return new BigInteger(maskedSeed.concat(maskedDB));
    }

// "empty" RSA key constructor
    function RSAKey() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
    }

// Set the public key fields N and e from hex strings
    function RSASetPublic(N, E) {
        this.isPublic = true;
        if (typeof N !== "string") {
            this.n = N;
            this.e = E;
        }
        else if (N != null && E != null && N.length > 0 && E.length > 0) {
            this.n = parseBigInt(N, 16);
            this.e = parseInt(E, 16);
        }
        else
            alert("Invalid RSA public key");
    }

// Perform raw public operation on "x": return x^e (mod n)
    function RSADoPublic(x) {
        return x.modPowInt(this.e, this.n);
    }

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
    function RSAEncrypt(text) {
        var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
        if (m == null) return null;
        var c = this.doPublic(m);
        if (c == null) return null;
        var h = c.toString(16);
        if ((h.length & 1) == 0) return h; else return "0" + h;
    }

// Return the PKCS#1 OAEP RSA encryption of "text" as an even-length hex string
    function RSAEncryptOAEP(text, hash) {
        var m = oaep_pad(text, (this.n.bitLength() + 7) >> 3, hash);
        if (m == null) return null;
        var c = this.doPublic(m);
        if (c == null) return null;
        var h = c.toString(16);
        if ((h.length & 1) == 0) return h; else return "0" + h;
    }

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
    RSAKey.prototype.doPublic = RSADoPublic;

// public
    RSAKey.prototype.setPublic = RSASetPublic;
    RSAKey.prototype.encrypt = RSAEncrypt;
    RSAKey.prototype.encryptOAEP = RSAEncryptOAEP;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

    RSAKey.prototype.type = "RSA";

    /*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
     */
    var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var b64pad = "=";

    function hex2b64(h) {
        var i;
        var c;
        var ret = "";
        for (i = 0; i + 3 <= h.length; i += 3) {
            c = parseInt(h.substring(i, i + 3), 16);
            ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
        }
        if (i + 1 == h.length) {
            c = parseInt(h.substring(i, i + 1), 16);
            ret += b64map.charAt(c << 2);
        }
        else if (i + 2 == h.length) {
            c = parseInt(h.substring(i, i + 2), 16);
            ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
        }
        if (b64pad) while ((ret.length & 3) > 0) ret += b64pad;
        return ret;
    }

// convert a base64 string to hex
    function b64tohex(s) {
        var ret = ""
        var i;
        var k = 0; // b64 state, 0-3
        var slop;
        var v;
        for (i = 0; i < s.length; ++i) {
            if (s.charAt(i) == b64pad) break;
            v = b64map.indexOf(s.charAt(i));
            if (v < 0) continue;
            if (k == 0) {
                ret += int2char(v >> 2);
                slop = v & 3;
                k = 1;
            }
            else if (k == 1) {
                ret += int2char((slop << 2) | (v >> 4));
                slop = v & 0xf;
                k = 2;
            }
            else if (k == 2) {
                ret += int2char(slop);
                ret += int2char(v >> 2);
                slop = v & 3;
                k = 3;
            }
            else {
                ret += int2char((slop << 2) | (v >> 4));
                ret += int2char(v & 0xf);
                k = 0;
            }
        }
        if (k == 1)
            ret += int2char(slop << 2);
        return ret;
    }

// convert a base64 string to a byte/number array
    function b64toBA(s) {
        //piggyback on b64tohex for now, optimize later
        var h = b64tohex(s);
        var i;
        var a = new Array();
        for (i = 0; 2 * i < h.length; ++i) {
            a[i] = parseInt(h.substring(2 * i, 2 * i + 2), 16);
        }
        return a;
    }


    /*
     CryptoJS v3.1.2
     code.google.com/p/crypto-js
     (c) 2009-2013 by Jeff Mott. All rights reserved.
     code.google.com/p/crypto-js/wiki/License
     */
    /**
     * CryptoJS core components.
     */
    var CryptoJS = CryptoJS || (function (Math, undefined) {
            /**
             * CryptoJS namespace.
             */
            var C = {};

            /**
             * Library namespace.
             */
            var C_lib = C.lib = {};

            /**
             * Base object for prototypal inheritance.
             */
            var Base = C_lib.Base = (function () {
                function F() {
                }

                return {
                    /**
                     * Creates a new object that inherits from this object.
                     *
                     * @param {Object} overrides Properties to copy into the new object.
                     *
                     * @return {Object} The new object.
                     *
                     * @static
                     *
                     * @example
                     *
                     *     var MyType = CryptoJS.lib.Base.extend({
             *         field: 'value',
             *
             *         method: function () {
             *         }
             *     });
                     */
                    extend: function (overrides) {
                        // Spawn
                        F.prototype = this;
                        var subtype = new F();

                        // Augment
                        if (overrides) {
                            subtype.mixIn(overrides);
                        }

                        // Create default initializer
                        if (!subtype.hasOwnProperty('init')) {
                            subtype.init = function () {
                                subtype.$super.init.apply(this, arguments);
                            };
                        }

                        // Initializer's prototype is the subtype object
                        subtype.init.prototype = subtype;

                        // Reference supertype
                        subtype.$super = this;

                        return subtype;
                    },

                    /**
                     * Extends this object and runs the init method.
                     * Arguments to create() will be passed to init().
                     *
                     * @return {Object} The new object.
                     *
                     * @static
                     *
                     * @example
                     *
                     *     var instance = MyType.create();
                     */
                    create: function () {
                        var instance = this.extend();
                        instance.init.apply(instance, arguments);

                        return instance;
                    },

                    /**
                     * Initializes a newly created object.
                     * Override this method to add some logic when your objects are created.
                     *
                     * @example
                     *
                     *     var MyType = CryptoJS.lib.Base.extend({
             *         init: function () {
             *             // ...
             *         }
             *     });
                     */
                    init: function () {
                    },

                    /**
                     * Copies properties into this object.
                     *
                     * @param {Object} properties The properties to mix in.
                     *
                     * @example
                     *
                     *     MyType.mixIn({
             *         field: 'value'
             *     });
                     */
                    mixIn: function (properties) {
                        for (var propertyName in properties) {
                            if (properties.hasOwnProperty(propertyName)) {
                                this[propertyName] = properties[propertyName];
                            }
                        }

                        // IE won't copy toString using the loop above
                        if (properties.hasOwnProperty('toString')) {
                            this.toString = properties.toString;
                        }
                    },

                    /**
                     * Creates a copy of this object.
                     *
                     * @return {Object} The clone.
                     *
                     * @example
                     *
                     *     var clone = instance.clone();
                     */
                    clone: function () {
                        return this.init.prototype.extend(this);
                    }
                };
            }());

            /**
             * An array of 32-bit words.
             *
             * @property {Array} words The array of 32-bit words.
             * @property {number} sigBytes The number of significant bytes in this word array.
             */
            var WordArray = C_lib.WordArray = Base.extend({
                /**
                 * Initializes a newly created word array.
                 *
                 * @param {Array} words (Optional) An array of 32-bit words.
                 * @param {number} sigBytes (Optional) The number of significant bytes in the words.
                 *
                 * @example
                 *
                 *     var wordArray = CryptoJS.lib.WordArray.create();
                 *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
                 *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
                 */
                init: function (words, sigBytes) {
                    words = this.words = words || [];

                    if (sigBytes != undefined) {
                        this.sigBytes = sigBytes;
                    } else {
                        this.sigBytes = words.length * 4;
                    }
                },

                /**
                 * Converts this word array to a string.
                 *
                 * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
                 *
                 * @return {string} The stringified word array.
                 *
                 * @example
                 *
                 *     var string = wordArray + '';
                 *     var string = wordArray.toString();
                 *     var string = wordArray.toString(CryptoJS.enc.Utf8);
                 */
                toString: function (encoder) {
                    return (encoder || Hex).stringify(this);
                },

                /**
                 * Concatenates a word array to this word array.
                 *
                 * @param {WordArray} wordArray The word array to append.
                 *
                 * @return {WordArray} This word array.
                 *
                 * @example
                 *
                 *     wordArray1.concat(wordArray2);
                 */
                concat: function (wordArray) {
                    // Shortcuts
                    var thisWords = this.words;
                    var thatWords = wordArray.words;
                    var thisSigBytes = this.sigBytes;
                    var thatSigBytes = wordArray.sigBytes;

                    // Clamp excess bits
                    this.clamp();

                    // Concat
                    if (thisSigBytes % 4) {
                        // Copy one byte at a time
                        for (var i = 0; i < thatSigBytes; i++) {
                            var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                            thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                        }
                    } else if (thatWords.length > 0xffff) {
                        // Copy one word at a time
                        for (var i = 0; i < thatSigBytes; i += 4) {
                            thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                        }
                    } else {
                        // Copy all words at once
                        thisWords.push.apply(thisWords, thatWords);
                    }
                    this.sigBytes += thatSigBytes;

                    // Chainable
                    return this;
                },

                /**
                 * Removes insignificant bits.
                 *
                 * @example
                 *
                 *     wordArray.clamp();
                 */
                clamp: function () {
                    // Shortcuts
                    var words = this.words;
                    var sigBytes = this.sigBytes;

                    // Clamp
                    words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
                    words.length = Math.ceil(sigBytes / 4);
                },

                /**
                 * Creates a copy of this word array.
                 *
                 * @return {WordArray} The clone.
                 *
                 * @example
                 *
                 *     var clone = wordArray.clone();
                 */
                clone: function () {
                    var clone = Base.clone.call(this);
                    clone.words = this.words.slice(0);

                    return clone;
                },

                /**
                 * Creates a word array filled with random bytes.
                 *
                 * @param {number} nBytes The number of random bytes to generate.
                 *
                 * @return {WordArray} The random word array.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var wordArray = CryptoJS.lib.WordArray.random(16);
                 */
                random: function (nBytes) {
                    var words = [];
                    for (var i = 0; i < nBytes; i += 4) {
                        words.push((Math.random() * 0x100000000) | 0);
                    }

                    return new WordArray.init(words, nBytes);
                }
            });

            /**
             * Encoder namespace.
             */
            var C_enc = C.enc = {};

            /**
             * Hex encoding strategy.
             */
            var Hex = C_enc.Hex = {
                /**
                 * Converts a word array to a hex string.
                 *
                 * @param {WordArray} wordArray The word array.
                 *
                 * @return {string} The hex string.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
                 */
                stringify: function (wordArray) {
                    // Shortcuts
                    var words = wordArray.words;
                    var sigBytes = wordArray.sigBytes;

                    // Convert
                    var hexChars = [];
                    for (var i = 0; i < sigBytes; i++) {
                        var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        hexChars.push((bite >>> 4).toString(16));
                        hexChars.push((bite & 0x0f).toString(16));
                    }

                    return hexChars.join('');
                },

                /**
                 * Converts a hex string to a word array.
                 *
                 * @param {string} hexStr The hex string.
                 *
                 * @return {WordArray} The word array.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
                 */
                parse: function (hexStr) {
                    // Shortcut
                    var hexStrLength = hexStr.length;

                    // Convert
                    var words = [];
                    for (var i = 0; i < hexStrLength; i += 2) {
                        words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
                    }

                    return new WordArray.init(words, hexStrLength / 2);
                }
            };

            /**
             * Latin1 encoding strategy.
             */
            var Latin1 = C_enc.Latin1 = {
                /**
                 * Converts a word array to a Latin1 string.
                 *
                 * @param {WordArray} wordArray The word array.
                 *
                 * @return {string} The Latin1 string.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
                 */
                stringify: function (wordArray) {
                    // Shortcuts
                    var words = wordArray.words;
                    var sigBytes = wordArray.sigBytes;

                    // Convert
                    var latin1Chars = [];
                    for (var i = 0; i < sigBytes; i++) {
                        var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        latin1Chars.push(String.fromCharCode(bite));
                    }

                    return latin1Chars.join('');
                },

                /**
                 * Converts a Latin1 string to a word array.
                 *
                 * @param {string} latin1Str The Latin1 string.
                 *
                 * @return {WordArray} The word array.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
                 */
                parse: function (latin1Str) {
                    // Shortcut
                    var latin1StrLength = latin1Str.length;

                    // Convert
                    var words = [];
                    for (var i = 0; i < latin1StrLength; i++) {
                        words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
                    }

                    return new WordArray.init(words, latin1StrLength);
                }
            };

            /**
             * UTF-8 encoding strategy.
             */
            var Utf8 = C_enc.Utf8 = {
                /**
                 * Converts a word array to a UTF-8 string.
                 *
                 * @param {WordArray} wordArray The word array.
                 *
                 * @return {string} The UTF-8 string.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
                 */
                stringify: function (wordArray) {
                    try {
                        return decodeURIComponent(escape(Latin1.stringify(wordArray)));
                    } catch (e) {
                        throw new Error('Malformed UTF-8 data');
                    }
                },

                /**
                 * Converts a UTF-8 string to a word array.
                 *
                 * @param {string} utf8Str The UTF-8 string.
                 *
                 * @return {WordArray} The word array.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
                 */
                parse: function (utf8Str) {
                    return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
                }
            };

            /**
             * Abstract buffered block algorithm template.
             *
             * The property blockSize must be implemented in a concrete subtype.
             *
             * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
             */
            var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
                /**
                 * Resets this block algorithm's data buffer to its initial state.
                 *
                 * @example
                 *
                 *     bufferedBlockAlgorithm.reset();
                 */
                reset: function () {
                    // Initial values
                    this._data = new WordArray.init();
                    this._nDataBytes = 0;
                },

                /**
                 * Adds new data to this block algorithm's buffer.
                 *
                 * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
                 *
                 * @example
                 *
                 *     bufferedBlockAlgorithm._append('data');
                 *     bufferedBlockAlgorithm._append(wordArray);
                 */
                _append: function (data) {
                    // Convert string to WordArray, else assume WordArray already
                    if (typeof data == 'string') {
                        data = Utf8.parse(data);
                    }

                    // Append
                    this._data.concat(data);
                    this._nDataBytes += data.sigBytes;
                },

                /**
                 * Processes available data blocks.
                 *
                 * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
                 *
                 * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
                 *
                 * @return {WordArray} The processed data.
                 *
                 * @example
                 *
                 *     var processedData = bufferedBlockAlgorithm._process();
                 *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
                 */
                _process: function (doFlush) {
                    // Shortcuts
                    var data = this._data;
                    var dataWords = data.words;
                    var dataSigBytes = data.sigBytes;
                    var blockSize = this.blockSize;
                    var blockSizeBytes = blockSize * 4;

                    // Count blocks ready
                    var nBlocksReady = dataSigBytes / blockSizeBytes;
                    if (doFlush) {
                        // Round up to include partial blocks
                        nBlocksReady = Math.ceil(nBlocksReady);
                    } else {
                        // Round down to include only full blocks,
                        // less the number of blocks that must remain in the buffer
                        nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
                    }

                    // Count words ready
                    var nWordsReady = nBlocksReady * blockSize;

                    // Count bytes ready
                    var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

                    // Process blocks
                    if (nWordsReady) {
                        for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                            // Perform concrete-algorithm logic
                            this._doProcessBlock(dataWords, offset);
                        }

                        // Remove processed words
                        var processedWords = dataWords.splice(0, nWordsReady);
                        data.sigBytes -= nBytesReady;
                    }

                    // Return processed words
                    return new WordArray.init(processedWords, nBytesReady);
                },

                /**
                 * Creates a copy of this object.
                 *
                 * @return {Object} The clone.
                 *
                 * @example
                 *
                 *     var clone = bufferedBlockAlgorithm.clone();
                 */
                clone: function () {
                    var clone = Base.clone.call(this);
                    clone._data = this._data.clone();

                    return clone;
                },

                _minBufferSize: 0
            });

            /**
             * Abstract hasher template.
             *
             * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
             */
            var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
                /**
                 * Configuration options.
                 */
                cfg: Base.extend(),

                /**
                 * Initializes a newly created hasher.
                 *
                 * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
                 *
                 * @example
                 *
                 *     var hasher = CryptoJS.algo.SHA256.create();
                 */
                init: function (cfg) {
                    // Apply config defaults
                    this.cfg = this.cfg.extend(cfg);

                    // Set initial values
                    this.reset();
                },

                /**
                 * Resets this hasher to its initial state.
                 *
                 * @example
                 *
                 *     hasher.reset();
                 */
                reset: function () {
                    // Reset data buffer
                    BufferedBlockAlgorithm.reset.call(this);

                    // Perform concrete-hasher logic
                    this._doReset();
                },

                /**
                 * Updates this hasher with a message.
                 *
                 * @param {WordArray|string} messageUpdate The message to append.
                 *
                 * @return {Hasher} This hasher.
                 *
                 * @example
                 *
                 *     hasher.update('message');
                 *     hasher.update(wordArray);
                 */
                update: function (messageUpdate) {
                    // Append
                    this._append(messageUpdate);

                    // Update the hash
                    this._process();

                    // Chainable
                    return this;
                },

                /**
                 * Finalizes the hash computation.
                 * Note that the finalize operation is effectively a destructive, read-once operation.
                 *
                 * @param {WordArray|string} messageUpdate (Optional) A final message update.
                 *
                 * @return {WordArray} The hash.
                 *
                 * @example
                 *
                 *     var hash = hasher.finalize();
                 *     var hash = hasher.finalize('message');
                 *     var hash = hasher.finalize(wordArray);
                 */
                finalize: function (messageUpdate) {
                    // Final message update
                    if (messageUpdate) {
                        this._append(messageUpdate);
                    }

                    // Perform concrete-hasher logic
                    var hash = this._doFinalize();

                    return hash;
                },

                blockSize: 512 / 32,

                /**
                 * Creates a shortcut function to a hasher's object interface.
                 *
                 * @param {Hasher} hasher The hasher to create a helper for.
                 *
                 * @return {Function} The shortcut function.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
                 */
                _createHelper: function (hasher) {
                    return function (message, cfg) {
                        return new hasher.init(cfg).finalize(message);
                    };
                },

                /**
                 * Creates a shortcut function to the HMAC's object interface.
                 *
                 * @param {Hasher} hasher The hasher to use in this HMAC helper.
                 *
                 * @return {Function} The shortcut function.
                 *
                 * @static
                 *
                 * @example
                 *
                 *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
                 */
                _createHmacHelper: function (hasher) {
                    return function (message, key) {
                        return new C_algo.HMAC.init(hasher, key).finalize(message);
                    };
                }
            });

            /**
             * Algorithm namespace.
             */
            var C_algo = C.algo = {};

            return C;
        }(Math));

    /*
     CryptoJS v3.1.2
     code.google.com/p/crypto-js
     (c) 2009-2013 by Jeff Mott. All rights reserved.
     code.google.com/p/crypto-js/wiki/License
     */
    (function (undefined) {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var Base = C_lib.Base;
        var X32WordArray = C_lib.WordArray;

        /**
         * x64 namespace.
         */
        var C_x64 = C.x64 = {};

        /**
         * A 64-bit word.
         */
        var X64Word = C_x64.Word = Base.extend({
            /**
             * Initializes a newly created 64-bit word.
             *
             * @param {number} high The high 32 bits.
             * @param {number} low The low 32 bits.
             *
             * @example
             *
             *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
             */
            init: function (high, low) {
                this.high = high;
                this.low = low;
            }

            /**
             * Bitwise NOTs this word.
             *
             * @return {X64Word} A new x64-Word object after negating.
             *
             * @example
             *
             *     var negated = x64Word.not();
             */
            // not: function () {
            // var high = ~this.high;
            // var low = ~this.low;

            // return X64Word.create(high, low);
            // },

            /**
             * Bitwise ANDs this word with the passed word.
             *
             * @param {X64Word} word The x64-Word to AND with this word.
             *
             * @return {X64Word} A new x64-Word object after ANDing.
             *
             * @example
             *
             *     var anded = x64Word.and(anotherX64Word);
             */
            // and: function (word) {
            // var high = this.high & word.high;
            // var low = this.low & word.low;

            // return X64Word.create(high, low);
            // },

            /**
             * Bitwise ORs this word with the passed word.
             *
             * @param {X64Word} word The x64-Word to OR with this word.
             *
             * @return {X64Word} A new x64-Word object after ORing.
             *
             * @example
             *
             *     var ored = x64Word.or(anotherX64Word);
             */
            // or: function (word) {
            // var high = this.high | word.high;
            // var low = this.low | word.low;

            // return X64Word.create(high, low);
            // },

            /**
             * Bitwise XORs this word with the passed word.
             *
             * @param {X64Word} word The x64-Word to XOR with this word.
             *
             * @return {X64Word} A new x64-Word object after XORing.
             *
             * @example
             *
             *     var xored = x64Word.xor(anotherX64Word);
             */
            // xor: function (word) {
            // var high = this.high ^ word.high;
            // var low = this.low ^ word.low;

            // return X64Word.create(high, low);
            // },

            /**
             * Shifts this word n bits to the left.
             *
             * @param {number} n The number of bits to shift.
             *
             * @return {X64Word} A new x64-Word object after shifting.
             *
             * @example
             *
             *     var shifted = x64Word.shiftL(25);
             */
            // shiftL: function (n) {
            // if (n < 32) {
            // var high = (this.high << n) | (this.low >>> (32 - n));
            // var low = this.low << n;
            // } else {
            // var high = this.low << (n - 32);
            // var low = 0;
            // }

            // return X64Word.create(high, low);
            // },

            /**
             * Shifts this word n bits to the right.
             *
             * @param {number} n The number of bits to shift.
             *
             * @return {X64Word} A new x64-Word object after shifting.
             *
             * @example
             *
             *     var shifted = x64Word.shiftR(7);
             */
            // shiftR: function (n) {
            // if (n < 32) {
            // var low = (this.low >>> n) | (this.high << (32 - n));
            // var high = this.high >>> n;
            // } else {
            // var low = this.high >>> (n - 32);
            // var high = 0;
            // }

            // return X64Word.create(high, low);
            // },

            /**
             * Rotates this word n bits to the left.
             *
             * @param {number} n The number of bits to rotate.
             *
             * @return {X64Word} A new x64-Word object after rotating.
             *
             * @example
             *
             *     var rotated = x64Word.rotL(25);
             */
            // rotL: function (n) {
            // return this.shiftL(n).or(this.shiftR(64 - n));
            // },

            /**
             * Rotates this word n bits to the right.
             *
             * @param {number} n The number of bits to rotate.
             *
             * @return {X64Word} A new x64-Word object after rotating.
             *
             * @example
             *
             *     var rotated = x64Word.rotR(7);
             */
            // rotR: function (n) {
            // return this.shiftR(n).or(this.shiftL(64 - n));
            // },

            /**
             * Adds this word with the passed word.
             *
             * @param {X64Word} word The x64-Word to add with this word.
             *
             * @return {X64Word} A new x64-Word object after adding.
             *
             * @example
             *
             *     var added = x64Word.add(anotherX64Word);
             */
            // add: function (word) {
            // var low = (this.low + word.low) | 0;
            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
            // var high = (this.high + word.high + carry) | 0;

            // return X64Word.create(high, low);
            // }
        });

        /**
         * An array of 64-bit words.
         *
         * @property {Array} words The array of CryptoJS.x64.Word objects.
         * @property {number} sigBytes The number of significant bytes in this word array.
         */
        var X64WordArray = C_x64.WordArray = Base.extend({
            /**
             * Initializes a newly created word array.
             *
             * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
             * @param {number} sigBytes (Optional) The number of significant bytes in the words.
             *
             * @example
             *
             *     var wordArray = CryptoJS.x64.WordArray.create();
             *
             *     var wordArray = CryptoJS.x64.WordArray.create([
             *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
             *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
             *     ]);
             *
             *     var wordArray = CryptoJS.x64.WordArray.create([
             *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
             *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
             *     ], 10);
             */
            init: function (words, sigBytes) {
                words = this.words = words || [];

                if (sigBytes != undefined) {
                    this.sigBytes = sigBytes;
                } else {
                    this.sigBytes = words.length * 8;
                }
            },

            /**
             * Converts this 64-bit word array to a 32-bit word array.
             *
             * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
             *
             * @example
             *
             *     var x32WordArray = x64WordArray.toX32();
             */
            toX32: function () {
                // Shortcuts
                var x64Words = this.words;
                var x64WordsLength = x64Words.length;

                // Convert
                var x32Words = [];
                for (var i = 0; i < x64WordsLength; i++) {
                    var x64Word = x64Words[i];
                    x32Words.push(x64Word.high);
                    x32Words.push(x64Word.low);
                }

                return X32WordArray.create(x32Words, this.sigBytes);
            },

            /**
             * Creates a copy of this word array.
             *
             * @return {X64WordArray} The clone.
             *
             * @example
             *
             *     var clone = x64WordArray.clone();
             */
            clone: function () {
                var clone = Base.clone.call(this);

                // Clone "words" array
                var words = clone.words = this.words.slice(0);

                // Clone each X64Word object
                var wordsLength = words.length;
                for (var i = 0; i < wordsLength; i++) {
                    words[i] = words[i].clone();
                }

                return clone;
            }
        });
    }());

    /*
     CryptoJS v3.1.2
     code.google.com/p/crypto-js
     (c) 2009-2013 by Jeff Mott. All rights reserved.
     code.google.com/p/crypto-js/wiki/License
     */
    (function () {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var Hasher = C_lib.Hasher;
        var C_x64 = C.x64;
        var X64Word = C_x64.Word;
        var X64WordArray = C_x64.WordArray;
        var C_algo = C.algo;

        function X64Word_create() {
            return X64Word.create.apply(X64Word, arguments);
        }

        // Constants
        var K = [
            X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
            X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
            X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
            X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
            X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
            X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
            X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
            X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
            X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
            X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
            X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
            X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
            X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
            X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
            X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
            X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
            X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
            X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
            X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
            X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
            X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
            X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
            X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
            X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
            X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
            X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
            X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
            X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
            X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
            X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
            X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
            X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
            X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
            X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
            X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
            X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
            X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
            X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
            X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
            X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
        ];

        // Reusable objects
        var W = [];
        (function () {
            for (var i = 0; i < 80; i++) {
                W[i] = X64Word_create();
            }
        }());

        /**
         * SHA-512 hash algorithm.
         */
        var SHA512 = C_algo.SHA512 = Hasher.extend({
            _doReset: function () {
                this._hash = new X64WordArray.init([
                    new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
                    new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
                    new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
                    new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
                ]);
            },

            _doProcessBlock: function (M, offset) {
                // Shortcuts
                var H = this._hash.words;

                var H0 = H[0];
                var H1 = H[1];
                var H2 = H[2];
                var H3 = H[3];
                var H4 = H[4];
                var H5 = H[5];
                var H6 = H[6];
                var H7 = H[7];

                var H0h = H0.high;
                var H0l = H0.low;
                var H1h = H1.high;
                var H1l = H1.low;
                var H2h = H2.high;
                var H2l = H2.low;
                var H3h = H3.high;
                var H3l = H3.low;
                var H4h = H4.high;
                var H4l = H4.low;
                var H5h = H5.high;
                var H5l = H5.low;
                var H6h = H6.high;
                var H6l = H6.low;
                var H7h = H7.high;
                var H7l = H7.low;

                // Working variables
                var ah = H0h;
                var al = H0l;
                var bh = H1h;
                var bl = H1l;
                var ch = H2h;
                var cl = H2l;
                var dh = H3h;
                var dl = H3l;
                var eh = H4h;
                var el = H4l;
                var fh = H5h;
                var fl = H5l;
                var gh = H6h;
                var gl = H6l;
                var hh = H7h;
                var hl = H7l;

                // Rounds
                for (var i = 0; i < 80; i++) {
                    // Shortcut
                    var Wi = W[i];

                    // Extend message
                    if (i < 16) {
                        var Wih = Wi.high = M[offset + i * 2] | 0;
                        var Wil = Wi.low = M[offset + i * 2 + 1] | 0;
                    } else {
                        // Gamma0
                        var gamma0x = W[i - 15];
                        var gamma0xh = gamma0x.high;
                        var gamma0xl = gamma0x.low;
                        var gamma0h = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
                        var gamma0l = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

                        // Gamma1
                        var gamma1x = W[i - 2];
                        var gamma1xh = gamma1x.high;
                        var gamma1xl = gamma1x.low;
                        var gamma1h = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
                        var gamma1l = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

                        // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
                        var Wi7 = W[i - 7];
                        var Wi7h = Wi7.high;
                        var Wi7l = Wi7.low;

                        var Wi16 = W[i - 16];
                        var Wi16h = Wi16.high;
                        var Wi16l = Wi16.low;

                        var Wil = gamma0l + Wi7l;
                        var Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
                        var Wil = Wil + gamma1l;
                        var Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
                        var Wil = Wil + Wi16l;
                        var Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

                        Wi.high = Wih;
                        Wi.low = Wil;
                    }

                    var chh = (eh & fh) ^ (~eh & gh);
                    var chl = (el & fl) ^ (~el & gl);
                    var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
                    var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

                    var sigma0h = ((ah >>> 28) | (al << 4)) ^ ((ah << 30) | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
                    var sigma0l = ((al >>> 28) | (ah << 4)) ^ ((al << 30) | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
                    var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
                    var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

                    // t1 = h + sigma1 + ch + K[i] + W[i]
                    var Ki = K[i];
                    var Kih = Ki.high;
                    var Kil = Ki.low;

                    var t1l = hl + sigma1l;
                    var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
                    var t1l = t1l + chl;
                    var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
                    var t1l = t1l + Kil;
                    var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
                    var t1l = t1l + Wil;
                    var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

                    // t2 = sigma0 + maj
                    var t2l = sigma0l + majl;
                    var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

                    // Update working variables
                    hh = gh;
                    hl = gl;
                    gh = fh;
                    gl = fl;
                    fh = eh;
                    fl = el;
                    el = (dl + t1l) | 0;
                    eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
                    dh = ch;
                    dl = cl;
                    ch = bh;
                    cl = bl;
                    bh = ah;
                    bl = al;
                    al = (t1l + t2l) | 0;
                    ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
                }

                // Intermediate hash value
                H0l = H0.low = (H0l + al);
                H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
                H1l = H1.low = (H1l + bl);
                H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
                H2l = H2.low = (H2l + cl);
                H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
                H3l = H3.low = (H3l + dl);
                H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
                H4l = H4.low = (H4l + el);
                H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
                H5l = H5.low = (H5l + fl);
                H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
                H6l = H6.low = (H6l + gl);
                H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
                H7l = H7.low = (H7l + hl);
                H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
            },

            _doFinalize: function () {
                // Shortcuts
                var data = this._data;
                var dataWords = data.words;

                var nBitsTotal = this._nDataBytes * 8;
                var nBitsLeft = data.sigBytes * 8;

                // Add padding
                dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
                dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
                dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
                data.sigBytes = dataWords.length * 4;

                // Hash final blocks
                this._process();

                // Convert hash to 32-bit word array before returning
                var hash = this._hash.toX32();

                // Return final computed hash
                return hash;
            },

            clone: function () {
                var clone = Hasher.clone.call(this);
                clone._hash = this._hash.clone();

                return clone;
            },

            blockSize: 1024 / 32
        });

        /**
         * Shortcut function to the hasher's object interface.
         *
         * @param {WordArray|string} message The message to hash.
         *
         * @return {WordArray} The hash.
         *
         * @static
         *
         * @example
         *
         *     var hash = CryptoJS.SHA512('message');
         *     var hash = CryptoJS.SHA512(wordArray);
         */
        C.SHA512 = Hasher._createHelper(SHA512);

        /**
         * Shortcut function to the HMAC's object interface.
         *
         * @param {WordArray|string} message The message to hash.
         * @param {WordArray|string} key The secret key.
         *
         * @return {WordArray} The HMAC.
         *
         * @static
         *
         * @example
         *
         *     var hmac = CryptoJS.HmacSHA512(message, key);
         */
        C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
    }());

    /*
     CryptoJS v3.1.2
     code.google.com/p/crypto-js
     (c) 2009-2013 by Jeff Mott. All rights reserved.
     code.google.com/p/crypto-js/wiki/License
     */
    var CryptoJS = CryptoJS || function (u, p) {
            var d = {}, l = d.lib = {}, s = function () {
                }, t = l.Base = {
                    extend: function (a) {
                        s.prototype = this;
                        var c = new s;
                        a && c.mixIn(a);
                        c.hasOwnProperty("init") || (c.init = function () {
                            c.$super.init.apply(this, arguments)
                        });
                        c.init.prototype = c;
                        c.$super = this;
                        return c
                    }, create: function () {
                        var a = this.extend();
                        a.init.apply(a, arguments);
                        return a
                    }, init: function () {
                    }, mixIn: function (a) {
                        for (var c in a)a.hasOwnProperty(c) && (this[c] = a[c]);
                        a.hasOwnProperty("toString") && (this.toString = a.toString)
                    }, clone: function () {
                        return this.init.prototype.extend(this)
                    }
                },
                r = l.WordArray = t.extend({
                    init: function (a, c) {
                        a = this.words = a || [];
                        this.sigBytes = c != p ? c : 4 * a.length
                    }, toString: function (a) {
                        return (a || v).stringify(this)
                    }, concat: function (a) {
                        var c = this.words, e = a.words, j = this.sigBytes;
                        a = a.sigBytes;
                        this.clamp();
                        if (j % 4)for (var k = 0; k < a; k++)c[j + k >>> 2] |= (e[k >>> 2] >>> 24 - 8 * (k % 4) & 255) << 24 - 8 * ((j + k) % 4); else if (65535 < e.length)for (k = 0; k < a; k += 4)c[j + k >>> 2] = e[k >>> 2]; else c.push.apply(c, e);
                        this.sigBytes += a;
                        return this
                    }, clamp: function () {
                        var a = this.words, c = this.sigBytes;
                        a[c >>> 2] &= 4294967295 <<
                        32 - 8 * (c % 4);
                        a.length = u.ceil(c / 4)
                    }, clone: function () {
                        var a = t.clone.call(this);
                        a.words = this.words.slice(0);
                        return a
                    }, random: function (a) {
                        for (var c = [], e = 0; e < a; e += 4)c.push(4294967296 * u.random() | 0);
                        return new r.init(c, a)
                    }
                }), w = d.enc = {}, v = w.Hex = {
                    stringify: function (a) {
                        var c = a.words;
                        a = a.sigBytes;
                        for (var e = [], j = 0; j < a; j++) {
                            var k = c[j >>> 2] >>> 24 - 8 * (j % 4) & 255;
                            e.push((k >>> 4).toString(16));
                            e.push((k & 15).toString(16))
                        }
                        return e.join("")
                    }, parse: function (a) {
                        for (var c = a.length, e = [], j = 0; j < c; j += 2)e[j >>> 3] |= parseInt(a.substr(j,
                            2), 16) << 24 - 4 * (j % 8);
                        return new r.init(e, c / 2)
                    }
                }, b = w.Latin1 = {
                    stringify: function (a) {
                        var c = a.words;
                        a = a.sigBytes;
                        for (var e = [], j = 0; j < a; j++)e.push(String.fromCharCode(c[j >>> 2] >>> 24 - 8 * (j % 4) & 255));
                        return e.join("")
                    }, parse: function (a) {
                        for (var c = a.length, e = [], j = 0; j < c; j++)e[j >>> 2] |= (a.charCodeAt(j) & 255) << 24 - 8 * (j % 4);
                        return new r.init(e, c)
                    }
                }, x = w.Utf8 = {
                    stringify: function (a) {
                        try {
                            return decodeURIComponent(escape(b.stringify(a)))
                        } catch (c) {
                            throw Error("Malformed UTF-8 data");
                        }
                    }, parse: function (a) {
                        return b.parse(unescape(encodeURIComponent(a)))
                    }
                },
                q = l.BufferedBlockAlgorithm = t.extend({
                    reset: function () {
                        this._data = new r.init;
                        this._nDataBytes = 0
                    }, _append: function (a) {
                        "string" == typeof a && (a = x.parse(a));
                        this._data.concat(a);
                        this._nDataBytes += a.sigBytes
                    }, _process: function (a) {
                        var c = this._data, e = c.words, j = c.sigBytes, k = this.blockSize, b = j / (4 * k), b = a ? u.ceil(b) : u.max((b | 0) - this._minBufferSize, 0);
                        a = b * k;
                        j = u.min(4 * a, j);
                        if (a) {
                            for (var q = 0; q < a; q += k)this._doProcessBlock(e, q);
                            q = e.splice(0, a);
                            c.sigBytes -= j
                        }
                        return new r.init(q, j)
                    }, clone: function () {
                        var a = t.clone.call(this);
                        a._data = this._data.clone();
                        return a
                    }, _minBufferSize: 0
                });
            l.Hasher = q.extend({
                cfg: t.extend(), init: function (a) {
                    this.cfg = this.cfg.extend(a);
                    this.reset()
                }, reset: function () {
                    q.reset.call(this);
                    this._doReset()
                }, update: function (a) {
                    this._append(a);
                    this._process();
                    return this
                }, finalize: function (a) {
                    a && this._append(a);
                    return this._doFinalize()
                }, blockSize: 16, _createHelper: function (a) {
                    return function (b, e) {
                        return (new a.init(e)).finalize(b)
                    }
                }, _createHmacHelper: function (a) {
                    return function (b, e) {
                        return (new n.HMAC.init(a,
                            e)).finalize(b)
                    }
                }
            });
            var n = d.algo = {};
            return d
        }(Math);
    (function () {
        var u = CryptoJS, p = u.lib.WordArray;
        u.enc.Base64 = {
            stringify: function (d) {
                var l = d.words, p = d.sigBytes, t = this._map;
                d.clamp();
                d = [];
                for (var r = 0; r < p; r += 3)for (var w = (l[r >>> 2] >>> 24 - 8 * (r % 4) & 255) << 16 | (l[r + 1 >>> 2] >>> 24 - 8 * ((r + 1) % 4) & 255) << 8 | l[r + 2 >>> 2] >>> 24 - 8 * ((r + 2) % 4) & 255, v = 0; 4 > v && r + 0.75 * v < p; v++)d.push(t.charAt(w >>> 6 * (3 - v) & 63));
                if (l = t.charAt(64))for (; d.length % 4;)d.push(l);
                return d.join("")
            }, parse: function (d) {
                var l = d.length, s = this._map, t = s.charAt(64);
                t && (t = d.indexOf(t), -1 != t && (l = t));
                for (var t = [], r = 0, w = 0; w <
                l; w++)if (w % 4) {
                    var v = s.indexOf(d.charAt(w - 1)) << 2 * (w % 4), b = s.indexOf(d.charAt(w)) >>> 6 - 2 * (w % 4);
                    t[r >>> 2] |= (v | b) << 24 - 8 * (r % 4);
                    r++
                }
                return p.create(t, r)
            }, _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        }
    })();
    (function (u) {
        function p(b, n, a, c, e, j, k) {
            b = b + (n & a | ~n & c) + e + k;
            return (b << j | b >>> 32 - j) + n
        }

        function d(b, n, a, c, e, j, k) {
            b = b + (n & c | a & ~c) + e + k;
            return (b << j | b >>> 32 - j) + n
        }

        function l(b, n, a, c, e, j, k) {
            b = b + (n ^ a ^ c) + e + k;
            return (b << j | b >>> 32 - j) + n
        }

        function s(b, n, a, c, e, j, k) {
            b = b + (a ^ (n | ~c)) + e + k;
            return (b << j | b >>> 32 - j) + n
        }

        for (var t = CryptoJS, r = t.lib, w = r.WordArray, v = r.Hasher, r = t.algo, b = [], x = 0; 64 > x; x++)b[x] = 4294967296 * u.abs(u.sin(x + 1)) | 0;
        r = r.MD5 = v.extend({
            _doReset: function () {
                this._hash = new w.init([1732584193, 4023233417, 2562383102, 271733878])
            },
            _doProcessBlock: function (q, n) {
                for (var a = 0; 16 > a; a++) {
                    var c = n + a, e = q[c];
                    q[c] = (e << 8 | e >>> 24) & 16711935 | (e << 24 | e >>> 8) & 4278255360
                }
                var a = this._hash.words, c = q[n + 0], e = q[n + 1], j = q[n + 2], k = q[n + 3], z = q[n + 4], r = q[n + 5], t = q[n + 6], w = q[n + 7], v = q[n + 8], A = q[n + 9], B = q[n + 10], C = q[n + 11], u = q[n + 12], D = q[n + 13], E = q[n + 14], x = q[n + 15], f = a[0], m = a[1], g = a[2], h = a[3], f = p(f, m, g, h, c, 7, b[0]), h = p(h, f, m, g, e, 12, b[1]), g = p(g, h, f, m, j, 17, b[2]), m = p(m, g, h, f, k, 22, b[3]), f = p(f, m, g, h, z, 7, b[4]), h = p(h, f, m, g, r, 12, b[5]), g = p(g, h, f, m, t, 17, b[6]), m = p(m, g, h, f, w, 22, b[7]),
                    f = p(f, m, g, h, v, 7, b[8]), h = p(h, f, m, g, A, 12, b[9]), g = p(g, h, f, m, B, 17, b[10]), m = p(m, g, h, f, C, 22, b[11]), f = p(f, m, g, h, u, 7, b[12]), h = p(h, f, m, g, D, 12, b[13]), g = p(g, h, f, m, E, 17, b[14]), m = p(m, g, h, f, x, 22, b[15]), f = d(f, m, g, h, e, 5, b[16]), h = d(h, f, m, g, t, 9, b[17]), g = d(g, h, f, m, C, 14, b[18]), m = d(m, g, h, f, c, 20, b[19]), f = d(f, m, g, h, r, 5, b[20]), h = d(h, f, m, g, B, 9, b[21]), g = d(g, h, f, m, x, 14, b[22]), m = d(m, g, h, f, z, 20, b[23]), f = d(f, m, g, h, A, 5, b[24]), h = d(h, f, m, g, E, 9, b[25]), g = d(g, h, f, m, k, 14, b[26]), m = d(m, g, h, f, v, 20, b[27]), f = d(f, m, g, h, D, 5, b[28]), h = d(h, f,
                        m, g, j, 9, b[29]), g = d(g, h, f, m, w, 14, b[30]), m = d(m, g, h, f, u, 20, b[31]), f = l(f, m, g, h, r, 4, b[32]), h = l(h, f, m, g, v, 11, b[33]), g = l(g, h, f, m, C, 16, b[34]), m = l(m, g, h, f, E, 23, b[35]), f = l(f, m, g, h, e, 4, b[36]), h = l(h, f, m, g, z, 11, b[37]), g = l(g, h, f, m, w, 16, b[38]), m = l(m, g, h, f, B, 23, b[39]), f = l(f, m, g, h, D, 4, b[40]), h = l(h, f, m, g, c, 11, b[41]), g = l(g, h, f, m, k, 16, b[42]), m = l(m, g, h, f, t, 23, b[43]), f = l(f, m, g, h, A, 4, b[44]), h = l(h, f, m, g, u, 11, b[45]), g = l(g, h, f, m, x, 16, b[46]), m = l(m, g, h, f, j, 23, b[47]), f = s(f, m, g, h, c, 6, b[48]), h = s(h, f, m, g, w, 10, b[49]), g = s(g, h, f, m,
                        E, 15, b[50]), m = s(m, g, h, f, r, 21, b[51]), f = s(f, m, g, h, u, 6, b[52]), h = s(h, f, m, g, k, 10, b[53]), g = s(g, h, f, m, B, 15, b[54]), m = s(m, g, h, f, e, 21, b[55]), f = s(f, m, g, h, v, 6, b[56]), h = s(h, f, m, g, x, 10, b[57]), g = s(g, h, f, m, t, 15, b[58]), m = s(m, g, h, f, D, 21, b[59]), f = s(f, m, g, h, z, 6, b[60]), h = s(h, f, m, g, C, 10, b[61]), g = s(g, h, f, m, j, 15, b[62]), m = s(m, g, h, f, A, 21, b[63]);
                a[0] = a[0] + f | 0;
                a[1] = a[1] + m | 0;
                a[2] = a[2] + g | 0;
                a[3] = a[3] + h | 0
            }, _doFinalize: function () {
                var b = this._data, n = b.words, a = 8 * this._nDataBytes, c = 8 * b.sigBytes;
                n[c >>> 5] |= 128 << 24 - c % 32;
                var e = u.floor(a /
                4294967296);
                n[(c + 64 >>> 9 << 4) + 15] = (e << 8 | e >>> 24) & 16711935 | (e << 24 | e >>> 8) & 4278255360;
                n[(c + 64 >>> 9 << 4) + 14] = (a << 8 | a >>> 24) & 16711935 | (a << 24 | a >>> 8) & 4278255360;
                b.sigBytes = 4 * (n.length + 1);
                this._process();
                b = this._hash;
                n = b.words;
                for (a = 0; 4 > a; a++)c = n[a], n[a] = (c << 8 | c >>> 24) & 16711935 | (c << 24 | c >>> 8) & 4278255360;
                return b
            }, clone: function () {
                var b = v.clone.call(this);
                b._hash = this._hash.clone();
                return b
            }
        });
        t.MD5 = v._createHelper(r);
        t.HmacMD5 = v._createHmacHelper(r)
    })(Math);
    (function () {
        var u = CryptoJS, p = u.lib, d = p.Base, l = p.WordArray, p = u.algo, s = p.EvpKDF = d.extend({
            cfg: d.extend({
                keySize: 4,
                hasher: p.MD5,
                iterations: 1
            }), init: function (d) {
                this.cfg = this.cfg.extend(d)
            }, compute: function (d, r) {
                for (var p = this.cfg, s = p.hasher.create(), b = l.create(), u = b.words, q = p.keySize, p = p.iterations; u.length < q;) {
                    n && s.update(n);
                    var n = s.update(d).finalize(r);
                    s.reset();
                    for (var a = 1; a < p; a++)n = s.finalize(n), s.reset();
                    b.concat(n)
                }
                b.sigBytes = 4 * q;
                return b
            }
        });
        u.EvpKDF = function (d, l, p) {
            return s.create(p).compute(d,
                l)
        }
    })();
    CryptoJS.lib.Cipher || function (u) {
        var p = CryptoJS, d = p.lib, l = d.Base, s = d.WordArray, t = d.BufferedBlockAlgorithm, r = p.enc.Base64, w = p.algo.EvpKDF, v = d.Cipher = t.extend({
            cfg: l.extend(), createEncryptor: function (e, a) {
                return this.create(this._ENC_XFORM_MODE, e, a)
            }, createDecryptor: function (e, a) {
                return this.create(this._DEC_XFORM_MODE, e, a)
            }, init: function (e, a, b) {
                this.cfg = this.cfg.extend(b);
                this._xformMode = e;
                this._key = a;
                this.reset()
            }, reset: function () {
                t.reset.call(this);
                this._doReset()
            }, process: function (e) {
                this._append(e);
                return this._process()
            },
            finalize: function (e) {
                e && this._append(e);
                return this._doFinalize()
            }, keySize: 4, ivSize: 4, _ENC_XFORM_MODE: 1, _DEC_XFORM_MODE: 2, _createHelper: function (e) {
                return {
                    encrypt: function (b, k, d) {
                        return ("string" == typeof k ? c : a).encrypt(e, b, k, d)
                    }, decrypt: function (b, k, d) {
                        return ("string" == typeof k ? c : a).decrypt(e, b, k, d)
                    }
                }
            }
        });
        d.StreamCipher = v.extend({
            _doFinalize: function () {
                return this._process(!0)
            }, blockSize: 1
        });
        var b = p.mode = {}, x = function (e, a, b) {
            var c = this._iv;
            c ? this._iv = u : c = this._prevBlock;
            for (var d = 0; d < b; d++)e[a + d] ^=
                c[d]
        }, q = (d.BlockCipherMode = l.extend({
            createEncryptor: function (e, a) {
                return this.Encryptor.create(e, a)
            }, createDecryptor: function (e, a) {
                return this.Decryptor.create(e, a)
            }, init: function (e, a) {
                this._cipher = e;
                this._iv = a
            }
        })).extend();
        q.Encryptor = q.extend({
            processBlock: function (e, a) {
                var b = this._cipher, c = b.blockSize;
                x.call(this, e, a, c);
                b.encryptBlock(e, a);
                this._prevBlock = e.slice(a, a + c)
            }
        });
        q.Decryptor = q.extend({
            processBlock: function (e, a) {
                var b = this._cipher, c = b.blockSize, d = e.slice(a, a + c);
                b.decryptBlock(e, a);
                x.call(this,
                    e, a, c);
                this._prevBlock = d
            }
        });
        b = b.CBC = q;
        q = (p.pad = {}).Pkcs7 = {
            pad: function (a, b) {
                for (var c = 4 * b, c = c - a.sigBytes % c, d = c << 24 | c << 16 | c << 8 | c, l = [], n = 0; n < c; n += 4)l.push(d);
                c = s.create(l, c);
                a.concat(c)
            }, unpad: function (a) {
                a.sigBytes -= a.words[a.sigBytes - 1 >>> 2] & 255
            }
        };
        d.BlockCipher = v.extend({
            cfg: v.cfg.extend({mode: b, padding: q}), reset: function () {
                v.reset.call(this);
                var a = this.cfg, b = a.iv, a = a.mode;
                if (this._xformMode == this._ENC_XFORM_MODE)var c = a.createEncryptor; else c = a.createDecryptor, this._minBufferSize = 1;
                this._mode = c.call(a,
                    this, b && b.words)
            }, _doProcessBlock: function (a, b) {
                this._mode.processBlock(a, b)
            }, _doFinalize: function () {
                var a = this.cfg.padding;
                if (this._xformMode == this._ENC_XFORM_MODE) {
                    a.pad(this._data, this.blockSize);
                    var b = this._process(!0)
                } else b = this._process(!0), a.unpad(b);
                return b
            }, blockSize: 4
        });
        var n = d.CipherParams = l.extend({
            init: function (a) {
                this.mixIn(a)
            }, toString: function (a) {
                return (a || this.formatter).stringify(this)
            }
        }), b = (p.format = {}).OpenSSL = {
            stringify: function (a) {
                var b = a.ciphertext;
                a = a.salt;
                return (a ? s.create([1398893684,
                    1701076831]).concat(a).concat(b) : b).toString(r)
            }, parse: function (a) {
                a = r.parse(a);
                var b = a.words;
                if (1398893684 == b[0] && 1701076831 == b[1]) {
                    var c = s.create(b.slice(2, 4));
                    b.splice(0, 4);
                    a.sigBytes -= 16
                }
                return n.create({ciphertext: a, salt: c})
            }
        }, a = d.SerializableCipher = l.extend({
            cfg: l.extend({format: b}), encrypt: function (a, b, c, d) {
                d = this.cfg.extend(d);
                var l = a.createEncryptor(c, d);
                b = l.finalize(b);
                l = l.cfg;
                return n.create({
                    ciphertext: b,
                    key: c,
                    iv: l.iv,
                    algorithm: a,
                    mode: l.mode,
                    padding: l.padding,
                    blockSize: a.blockSize,
                    formatter: d.format
                })
            },
            decrypt: function (a, b, c, d) {
                d = this.cfg.extend(d);
                b = this._parse(b, d.format);
                return a.createDecryptor(c, d).finalize(b.ciphertext)
            }, _parse: function (a, b) {
                return "string" == typeof a ? b.parse(a, this) : a
            }
        }), p = (p.kdf = {}).OpenSSL = {
            execute: function (a, b, c, d) {
                d || (d = s.random(8));
                a = w.create({keySize: b + c}).compute(a, d);
                c = s.create(a.words.slice(b), 4 * c);
                a.sigBytes = 4 * b;
                return n.create({key: a, iv: c, salt: d})
            }
        }, c = d.PasswordBasedCipher = a.extend({
            cfg: a.cfg.extend({kdf: p}), encrypt: function (b, c, d, l) {
                l = this.cfg.extend(l);
                d = l.kdf.execute(d,
                    b.keySize, b.ivSize);
                l.iv = d.iv;
                b = a.encrypt.call(this, b, c, d.key, l);
                b.mixIn(d);
                return b
            }, decrypt: function (b, c, d, l) {
                l = this.cfg.extend(l);
                c = this._parse(c, l.format);
                d = l.kdf.execute(d, b.keySize, b.ivSize, c.salt);
                l.iv = d.iv;
                return a.decrypt.call(this, b, c, d.key, l)
            }
        })
    }();
    (function () {
        for (var u = CryptoJS, p = u.lib.BlockCipher, d = u.algo, l = [], s = [], t = [], r = [], w = [], v = [], b = [], x = [], q = [], n = [], a = [], c = 0; 256 > c; c++)a[c] = 128 > c ? c << 1 : c << 1 ^ 283;
        for (var e = 0, j = 0, c = 0; 256 > c; c++) {
            var k = j ^ j << 1 ^ j << 2 ^ j << 3 ^ j << 4, k = k >>> 8 ^ k & 255 ^ 99;
            l[e] = k;
            s[k] = e;
            var z = a[e], F = a[z], G = a[F], y = 257 * a[k] ^ 16843008 * k;
            t[e] = y << 24 | y >>> 8;
            r[e] = y << 16 | y >>> 16;
            w[e] = y << 8 | y >>> 24;
            v[e] = y;
            y = 16843009 * G ^ 65537 * F ^ 257 * z ^ 16843008 * e;
            b[k] = y << 24 | y >>> 8;
            x[k] = y << 16 | y >>> 16;
            q[k] = y << 8 | y >>> 24;
            n[k] = y;
            e ? (e = z ^ a[a[a[G ^ z]]], j ^= a[a[j]]) : e = j = 1
        }
        var H = [0, 1, 2, 4, 8,
            16, 32, 64, 128, 27, 54], d = d.AES = p.extend({
            _doReset: function () {
                for (var a = this._key, c = a.words, d = a.sigBytes / 4, a = 4 * ((this._nRounds = d + 6) + 1), e = this._keySchedule = [], j = 0; j < a; j++)if (j < d)e[j] = c[j]; else {
                    var k = e[j - 1];
                    j % d ? 6 < d && 4 == j % d && (k = l[k >>> 24] << 24 | l[k >>> 16 & 255] << 16 | l[k >>> 8 & 255] << 8 | l[k & 255]) : (k = k << 8 | k >>> 24, k = l[k >>> 24] << 24 | l[k >>> 16 & 255] << 16 | l[k >>> 8 & 255] << 8 | l[k & 255], k ^= H[j / d | 0] << 24);
                    e[j] = e[j - d] ^ k
                }
                c = this._invKeySchedule = [];
                for (d = 0; d < a; d++)j = a - d, k = d % 4 ? e[j] : e[j - 4], c[d] = 4 > d || 4 >= j ? k : b[l[k >>> 24]] ^ x[l[k >>> 16 & 255]] ^ q[l[k >>>
                8 & 255]] ^ n[l[k & 255]]
            }, encryptBlock: function (a, b) {
                this._doCryptBlock(a, b, this._keySchedule, t, r, w, v, l)
            }, decryptBlock: function (a, c) {
                var d = a[c + 1];
                a[c + 1] = a[c + 3];
                a[c + 3] = d;
                this._doCryptBlock(a, c, this._invKeySchedule, b, x, q, n, s);
                d = a[c + 1];
                a[c + 1] = a[c + 3];
                a[c + 3] = d
            }, _doCryptBlock: function (a, b, c, d, e, j, l, f) {
                for (var m = this._nRounds, g = a[b] ^ c[0], h = a[b + 1] ^ c[1], k = a[b + 2] ^ c[2], n = a[b + 3] ^ c[3], p = 4, r = 1; r < m; r++)var q = d[g >>> 24] ^ e[h >>> 16 & 255] ^ j[k >>> 8 & 255] ^ l[n & 255] ^ c[p++], s = d[h >>> 24] ^ e[k >>> 16 & 255] ^ j[n >>> 8 & 255] ^ l[g & 255] ^ c[p++], t =
                    d[k >>> 24] ^ e[n >>> 16 & 255] ^ j[g >>> 8 & 255] ^ l[h & 255] ^ c[p++], n = d[n >>> 24] ^ e[g >>> 16 & 255] ^ j[h >>> 8 & 255] ^ l[k & 255] ^ c[p++], g = q, h = s, k = t;
                q = (f[g >>> 24] << 24 | f[h >>> 16 & 255] << 16 | f[k >>> 8 & 255] << 8 | f[n & 255]) ^ c[p++];
                s = (f[h >>> 24] << 24 | f[k >>> 16 & 255] << 16 | f[n >>> 8 & 255] << 8 | f[g & 255]) ^ c[p++];
                t = (f[k >>> 24] << 24 | f[n >>> 16 & 255] << 16 | f[g >>> 8 & 255] << 8 | f[h & 255]) ^ c[p++];
                n = (f[n >>> 24] << 24 | f[g >>> 16 & 255] << 16 | f[h >>> 8 & 255] << 8 | f[k & 255]) ^ c[p++];
                a[b] = q;
                a[b + 1] = s;
                a[b + 2] = t;
                a[b + 3] = n
            }, keySize: 8
        });
        u.AES = p._createHelper(d)
    })();

    /*
     CryptoJS v3.1.2
     code.google.com/p/crypto-js
     (c) 2009-2013 by Jeff Mott. All rights reserved.
     code.google.com/p/crypto-js/wiki/License
     */
    CryptoJS.mode.CFB = function () {
        function g(c, b, e, a) {
            var d = this._iv;
            d ? (d = d.slice(0), this._iv = void 0) : d = this._prevBlock;
            a.encryptBlock(d, 0);
            for (a = 0; a < e; a++)c[b + a] ^= d[a]
        }

        var f = CryptoJS.lib.BlockCipherMode.extend();
        f.Encryptor = f.extend({
            processBlock: function (c, b) {
                var e = this._cipher, a = e.blockSize;
                g.call(this, c, b, a, e);
                this._prevBlock = c.slice(b, b + a)
            }
        });
        f.Decryptor = f.extend({
            processBlock: function (c, b) {
                var e = this._cipher, a = e.blockSize, d = c.slice(b, b + a);
                g.call(this, c, b, a, e);
                this._prevBlock = d
            }
        });
        return f
    }();

    /*
     CryptoJS v3.1.2
     code.google.com/p/crypto-js
     (c) 2009-2013 by Jeff Mott. All rights reserved.
     code.google.com/p/crypto-js/wiki/License
     */
    CryptoJS.pad.AnsiX923 = {
        pad: function (a, d) {
            var b = a.sigBytes, c = 4 * d, c = c - b % c, b = b + c - 1;
            a.clamp();
            a.words[b >>> 2] |= c << 24 - 8 * (b % 4);
            a.sigBytes += c
        }, unpad: function (a) {
            a.sigBytes -= a.words[a.sigBytes - 1 >>> 2] & 255
        }
    };

    /*! rsasign-1.2.7.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
     */
    /*
     * rsa-sign.js - adding signing functions to RSAKey class.
     *
     * version: 1.2.7 (2013 Aug 25)
     *
     * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
     *
     * This software is licensed under the terms of the MIT License.
     * http://kjur.github.com/jsrsasign/license/
     *
     * The above copyright and license notice shall be
     * included in all copies or substantial portions of the Software.
     */

    /**
     * @fileOverview
     * @name rsasign-1.2.js
     * @author Kenji Urushima kenji.urushima@gmail.com
     * @version rsasign 1.2.7
     * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
     */

    var _RE_HEXDECONLY = new RegExp("");
    _RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

// ========================================================================
// Signature Generation
// ========================================================================

    function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
        var hashFunc = function (s) {
            return KJUR.crypto.Util.hashString(s, hashAlg);
        };
        var sHashHex = hashFunc(s);

        return KJUR.crypto.Util.getPaddedDigestInfoHex(sHashHex, hashAlg, keySize);
    }

    function _zeroPaddingOfSignature(hex, bitLength) {
        var s = "";
        var nZero = bitLength / 4 - hex.length;
        for (var i = 0; i < nZero; i++) {
            s = s + "0";
        }
        return s + hex;
    }

    /**
     * sign for a message string with RSA private key.<br/>
     * @name signString
     * @memberOf RSAKey
     * @function
     * @param {String} s message string to be signed.
     * @param {String} hashAlg hash algorithm name for signing.<br/>
     * @return returns hexadecimal string of signature value.
     */
    function _rsasign_signString(s, hashAlg) {
        var hashFunc = function (s) {
            return KJUR.crypto.Util.hashString(s, hashAlg);
        };
        var sHashHex = hashFunc(s);

        return this.signWithMessageHash(sHashHex, hashAlg);
    }

    /**
     * sign hash value of message to be signed with RSA private key.<br/>
     * @name signWithMessageHash
     * @memberOf RSAKey
     * @function
     * @param {String} sHashHex hexadecimal string of hash value of message to be signed.
     * @param {String} hashAlg hash algorithm name for signing.<br/>
     * @return returns hexadecimal string of signature value.
     * @since rsasign 1.2.6
     */
    function _rsasign_signWithMessageHash(sHashHex, hashAlg) {
        var hPM = KJUR.crypto.Util.getPaddedDigestInfoHex(sHashHex, hashAlg, this.n.bitLength());
        var biPaddedMessage = parseBigInt(hPM, 16);
        var biSign = this.doPrivate(biPaddedMessage);
        var hexSign = biSign.toString(16);
        return _zeroPaddingOfSignature(hexSign, this.n.bitLength());
    }

    function _rsasign_signStringWithSHA1(s) {
        return _rsasign_signString.call(this, s, 'sha1');
    }

    function _rsasign_signStringWithSHA256(s) {
        return _rsasign_signString.call(this, s, 'sha256');
    }

// PKCS#1 (PSS) mask generation function
    function pss_mgf1_str(seed, len, hash) {
        var mask = '', i = 0;

        while (mask.length < len) {
            mask += hextorstr(hash(rstrtohex(seed + String.fromCharCode.apply(String, [
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff]))));
            i += 1;
        }

        return mask;
    }

    /**
     * sign for a message string with RSA private key by PKCS#1 PSS signing.<br/>
     * @name signStringPSS
     * @memberOf RSAKey
     * @function
     * @param {String} s message string to be signed.
     * @param {String} hashAlg hash algorithm name for signing.
     * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
     *        There are two special values:
     *        <ul>
     *        <li>-1: sets the salt length to the digest length</li>
     *        <li>-2: sets the salt length to maximum permissible value
     *           (i.e. keybytelen - hashbytelen - 2)</li>
     *        </ul>
     *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
     * @return returns hexadecimal string of signature value.
     */
    function _rsasign_signStringPSS(s, hashAlg, sLen) {
        var hashFunc = function (sHex) {
            return KJUR.crypto.Util.hashHex(sHex, hashAlg);
        }
        var hHash = hashFunc(rstrtohex(s));

        if (sLen === undefined) sLen = -1;
        return this.signWithMessageHashPSS(hHash, hashAlg, sLen);
    }

    /**
     * sign hash value of message with RSA private key by PKCS#1 PSS signing.<br/>
     * @name signWithMessageHashPSS
     * @memberOf RSAKey
     * @function
     * @param {String} hHash hexadecimal hash value of message to be signed.
     * @param {String} hashAlg hash algorithm name for signing.
     * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
     *        There are two special values:
     *        <ul>
     *        <li>-1: sets the salt length to the digest length</li>
     *        <li>-2: sets the salt length to maximum permissible value
     *           (i.e. keybytelen - hashbytelen - 2)</li>
     *        </ul>
     *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
     * @return returns hexadecimal string of signature value.
     * @since rsasign 1.2.6
     */
    function _rsasign_signWithMessageHashPSS(hHash, hashAlg, sLen) {
        var mHash = hextorstr(hHash);
        var hLen = mHash.length;
        var emBits = this.n.bitLength() - 1;
        var emLen = Math.ceil(emBits / 8);
        var i;
        var hashFunc = function (sHex) {
            return KJUR.crypto.Util.hashHex(sHex, hashAlg);
        }

        if (sLen === -1 || sLen === undefined) {
            sLen = hLen; // same as hash length
        } else if (sLen === -2) {
            sLen = emLen - hLen - 2; // maximum
        } else if (sLen < -2) {
            throw "invalid salt length";
        }

        if (emLen < (hLen + sLen + 2)) {
            throw "data too long";
        }

        var salt = '';

        if (sLen > 0) {
            salt = new Array(sLen);
            new SecureRandom().nextBytes(salt);
            salt = String.fromCharCode.apply(String, salt);
        }

        var H = hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash + salt)));
        var PS = [];

        for (i = 0; i < emLen - sLen - hLen - 2; i += 1) {
            PS[i] = 0x00;
        }

        var DB = String.fromCharCode.apply(String, PS) + '\x01' + salt;
        var dbMask = pss_mgf1_str(H, DB.length, hashFunc);
        var maskedDB = [];

        for (i = 0; i < DB.length; i += 1) {
            maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
        }

        var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;
        maskedDB[0] &= ~mask;

        for (i = 0; i < hLen; i++) {
            maskedDB.push(H.charCodeAt(i));
        }

        maskedDB.push(0xbc);

        return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(maskedDB)).toString(16),
            this.n.bitLength());
    }

// ========================================================================
// Signature Verification
// ========================================================================

    function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
        var rsa = new RSAKey();
        rsa.setPublic(hN, hE);
        var biDecryptedSig = rsa.doPublic(biSig);
        return biDecryptedSig;
    }

    function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
        var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
        var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
        return hDigestInfo;
    }

    function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
        for (var algName in KJUR.crypto.Util.DIGESTINFOHEAD) {
            var head = KJUR.crypto.Util.DIGESTINFOHEAD[algName];
            var len = head.length;
            if (hDigestInfo.substring(0, len) == head) {
                var a = [algName, hDigestInfo.substring(len)];
                return a;
            }
        }
        return [];
    }

    function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
        var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
        var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
        if (digestInfoAry.length == 0) return false;
        var algName = digestInfoAry[0];
        var diHashValue = digestInfoAry[1];
        var ff = function (s) {
            return KJUR.crypto.Util.hashString(s, algName);
        };
        var msgHashValue = ff(sMsg);
        return (diHashValue == msgHashValue);
    }

    function _rsasign_verifyHexSignatureForMessage(hSig, sMsg) {
        var biSig = parseBigInt(hSig, 16);
        var result = _rsasign_verifySignatureWithArgs(sMsg, biSig,
            this.n.toString(16),
            this.e.toString(16));
        return result;
    }

    /**
     * verifies a sigature for a message string with RSA public key.<br/>
     * @name verifyString
     * @memberOf RSAKey#
     * @function
     * @param {String} sMsg message string to be verified.
     * @param {String} hSig hexadecimal string of siganture.<br/>
     *                 non-hexadecimal charactors including new lines will be ignored.
     * @return returns 1 if valid, otherwise 0
     */
    function _rsasign_verifyString(sMsg, hSig) {
        hSig = hSig.replace(_RE_HEXDECONLY, '');
        hSig = hSig.replace(/[ \n]+/g, "");
        var biSig = parseBigInt(hSig, 16);
        if (biSig.bitLength() > this.n.bitLength()) return 0;
        var biDecryptedSig = this.doPublic(biSig);
        var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
        var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

        if (digestInfoAry.length == 0) return false;
        var algName = digestInfoAry[0];
        var diHashValue = digestInfoAry[1];
        var ff = function (s) {
            return KJUR.crypto.Util.hashString(s, algName);
        };
        var msgHashValue = ff(sMsg);
        return (diHashValue == msgHashValue);
    }

    /**
     * verifies a sigature for a message string with RSA public key.<br/>
     * @name verifyWithMessageHash
     * @memberOf RSAKey
     * @function
     * @param {String} sHashHex hexadecimal hash value of message to be verified.
     * @param {String} hSig hexadecimal string of siganture.<br/>
     *                 non-hexadecimal charactors including new lines will be ignored.
     * @return returns 1 if valid, otherwise 0
     * @since rsasign 1.2.6
     */
    function _rsasign_verifyWithMessageHash(sHashHex, hSig) {
        hSig = hSig.replace(_RE_HEXDECONLY, '');
        hSig = hSig.replace(/[ \n]+/g, "");
        var biSig = parseBigInt(hSig, 16);
        if (biSig.bitLength() > this.n.bitLength()) return 0;
        var biDecryptedSig = this.doPublic(biSig);
        var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
        var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

        if (digestInfoAry.length == 0) return false;
        var algName = digestInfoAry[0];
        var diHashValue = digestInfoAry[1];
        return (diHashValue == sHashHex);
    }

    /**
     * verifies a sigature for a message string with RSA public key by PKCS#1 PSS sign.<br/>
     * @name verifyStringPSS
     * @memberOf RSAKey
     * @function
     * @param {String} sMsg message string to be verified.
     * @param {String} hSig hexadecimal string of signature value
     * @param {String} hashAlg hash algorithm name
     * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
     *        There are two special values:
     *        <ul>
     *        <li>-1: sets the salt length to the digest length</li>
     *        <li>-2: sets the salt length to maximum permissible value
     *           (i.e. keybytelen - hashbytelen - 2)</li>
     *        </ul>
     *        DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
     * @return returns true if valid, otherwise false
     */
    function _rsasign_verifyStringPSS(sMsg, hSig, hashAlg, sLen) {
        var hashFunc = function (sHex) {
            return KJUR.crypto.Util.hashHex(sHex, hashAlg);
        };
        var hHash = hashFunc(rstrtohex(sMsg));

        if (sLen === undefined) sLen = -1;
        return this.verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen);
    }

    /**
     * verifies a sigature for a hash value of message string with RSA public key by PKCS#1 PSS sign.<br/>
     * @name verifyWithMessageHashPSS
     * @memberOf RSAKey
     * @function
     * @param {String} hHash hexadecimal hash value of message string to be verified.
     * @param {String} hSig hexadecimal string of signature value
     * @param {String} hashAlg hash algorithm name
     * @param {Integer} sLen salt byte length from 0 to (keybytelen - hashbytelen - 2).
     *        There are two special values:
     *        <ul>
     *        <li>-1: sets the salt length to the digest length</li>
     *        <li>-2: sets the salt length to maximum permissible value
     *           (i.e. keybytelen - hashbytelen - 2)</li>
     *        </ul>
     *        DEFAULT is -1 (NOTE: OpenSSL's default is -2.)
     * @return returns true if valid, otherwise false
     * @since rsasign 1.2.6
     */
    function _rsasign_verifyWithMessageHashPSS(hHash, hSig, hashAlg, sLen) {
        var biSig = new BigInteger(hSig, 16);

        if (biSig.bitLength() > this.n.bitLength()) {
            return false;
        }

        var hashFunc = function (sHex) {
            return KJUR.crypto.Util.hashHex(sHex, hashAlg);
        };
        var mHash = hextorstr(hHash);
        var hLen = mHash.length;
        var emBits = this.n.bitLength() - 1;
        var emLen = Math.ceil(emBits / 8);
        var i;

        if (sLen === -1 || sLen === undefined) {
            sLen = hLen; // same as hash length
        } else if (sLen === -2) {
            sLen = emLen - hLen - 2; // recover
        } else if (sLen < -2) {
            throw "invalid salt length";
        }

        if (emLen < (hLen + sLen + 2)) {
            throw "data too long";
        }

        var em = this.doPublic(biSig).toByteArray();

        for (i = 0; i < em.length; i += 1) {
            em[i] &= 0xff;
        }

        while (em.length < emLen) {
            em.unshift(0);
        }

        if (em[emLen - 1] !== 0xbc) {
            throw "encoded message does not end in 0xbc";
        }

        em = String.fromCharCode.apply(String, em);

        var maskedDB = em.substr(0, emLen - hLen - 1);
        var H = em.substr(maskedDB.length, hLen);

        var mask = (0xff00 >> (8 * emLen - emBits)) & 0xff;

        if ((maskedDB.charCodeAt(0) & mask) !== 0) {
            throw "bits beyond keysize not zero";
        }

        var dbMask = pss_mgf1_str(H, maskedDB.length, hashFunc);
        var DB = [];

        for (i = 0; i < maskedDB.length; i += 1) {
            DB[i] = maskedDB.charCodeAt(i) ^ dbMask.charCodeAt(i);
        }

        DB[0] &= ~mask;

        var checkLen = emLen - hLen - sLen - 2;

        for (i = 0; i < checkLen; i += 1) {
            if (DB[i] !== 0x00) {
                throw "leftmost octets not zero";
            }
        }

        if (DB[checkLen] !== 0x01) {
            throw "0x01 marker not found";
        }

        return H === hextorstr(hashFunc(rstrtohex('\x00\x00\x00\x00\x00\x00\x00\x00' + mHash +
            String.fromCharCode.apply(String, DB.slice(-sLen)))));
    }

    RSAKey.prototype.signWithMessageHash = _rsasign_signWithMessageHash;
    RSAKey.prototype.signString = _rsasign_signString;
    RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
    RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
    RSAKey.prototype.sign = _rsasign_signString;
    RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
    RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;

    RSAKey.prototype.signWithMessageHashPSS = _rsasign_signWithMessageHashPSS;
    RSAKey.prototype.signStringPSS = _rsasign_signStringPSS;
    RSAKey.prototype.signPSS = _rsasign_signStringPSS;
    RSAKey.SALT_LEN_HLEN = -1;
    RSAKey.SALT_LEN_MAX = -2;

    RSAKey.prototype.verifyWithMessageHash = _rsasign_verifyWithMessageHash;
    RSAKey.prototype.verifyString = _rsasign_verifyString;
    RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
    RSAKey.prototype.verify = _rsasign_verifyString;
    RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;

    RSAKey.prototype.verifyWithMessageHashPSS = _rsasign_verifyWithMessageHashPSS;
    RSAKey.prototype.verifyStringPSS = _rsasign_verifyStringPSS;
    RSAKey.prototype.verifyPSS = _rsasign_verifyStringPSS;
    RSAKey.SALT_LEN_RECOVER = -2;

    /**
     * @name RSAKey
     * @class key of RSA public key algorithm
     * @description Tom Wu's RSA Key class and extension
     */


    /*! x509-1.1.2.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
     */
    /*
     * x509.js - X509 class to read subject public key from certificate.
     *
     * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
     *
     * This software is licensed under the terms of the MIT License.
     * http://kjur.github.com/jsrsasign/license
     *
     * The above copyright and license notice shall be
     * included in all copies or substantial portions of the Software.
     */

    /**
     * @fileOverview
     * @name x509-1.1.js
     * @author Kenji Urushima kenji.urushima@gmail.com
     * @version x509 1.1.2 (2013-Oct-06)
     * @since jsrsasign 1.x.x
     * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
     */

    /*
     * Depends:
     *   base64.js
     *   rsa.js
     *   asn1hex.js
     */

    /**
     * X.509 certificate class.<br/>
     * @class X.509 certificate class
     * @property {RSAKey} subjectPublicKeyRSA Tom Wu's RSAKey object
     * @property {String} subjectPublicKeyRSA_hN hexadecimal string for modulus of RSA public key
     * @property {String} subjectPublicKeyRSA_hE hexadecimal string for public exponent of RSA public key
     * @property {String} hex hexacedimal string for X.509 certificate.
     * @author Kenji Urushima
     * @version 1.0.1 (08 May 2012)
     * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
     */
    function X509() {
        this.subjectPublicKeyRSA = null;
        this.subjectPublicKeyRSA_hN = null;
        this.subjectPublicKeyRSA_hE = null;
        this.hex = null;

        // ===== get basic fields from hex =====================================

        /**
         * get hexadecimal string of serialNumber field of certificate.<br/>
         * @name getSerialNumberHex
         * @memberOf X509#
         * @function
         */
        this.getSerialNumberHex = function () {
            return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]);
        };

        /**
         * get hexadecimal string of issuer field of certificate.<br/>
         * @name getIssuerHex
         * @memberOf X509#
         * @function
         */
        this.getIssuerHex = function () {
            return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]);
        };

        /**
         * get string of issuer field of certificate.<br/>
         * @name getIssuerString
         * @memberOf X509#
         * @function
         */
        this.getIssuerString = function () {
            return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]));
        };

        /**
         * get hexadecimal string of subject field of certificate.<br/>
         * @name getSubjectHex
         * @memberOf X509#
         * @function
         */
        this.getSubjectHex = function () {
            return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]);
        };

        /**
         * get string of subject field of certificate.<br/>
         * @name getSubjectString
         * @memberOf X509#
         * @function
         */
        this.getSubjectString = function () {
            return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
        };

        /**
         * get notBefore field string of certificate.<br/>
         * @name getNotBefore
         * @memberOf X509#
         * @function
         */
        this.getNotBefore = function () {
            var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
            s = s.replace(/(..)/g, "%$1");
            s = decodeURIComponent(s);
            return s;
        };

        /**
         * get notAfter field string of certificate.<br/>
         * @name getNotAfter
         * @memberOf X509#
         * @function
         */
        this.getNotAfter = function () {
            var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
            s = s.replace(/(..)/g, "%$1");
            s = decodeURIComponent(s);
            return s;
        };

        // ===== read certificate public key ==========================

        // ===== read certificate =====================================
        /**
         * read PEM formatted X.509 certificate from string.<br/>
         * @name readCertPEM
         * @memberOf X509#
         * @function
         * @param {String} sCertPEM string for PEM formatted X.509 certificate
         */
        this.readCertPEM = function (sCertPEM) {
            var hCert = X509.pemToHex(sCertPEM);
            var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
            var rsa = new RSAKey();
            rsa.setPublic(a[0], a[1]);
            this.subjectPublicKeyRSA = rsa;
            this.subjectPublicKeyRSA_hN = a[0];
            this.subjectPublicKeyRSA_hE = a[1];
            this.hex = hCert;
        };

        this.readCertPEMWithoutRSAInit = function (sCertPEM) {
            var hCert = X509.pemToHex(sCertPEM);
            var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
            this.subjectPublicKeyRSA.setPublic(a[0], a[1]);
            this.subjectPublicKeyRSA_hN = a[0];
            this.subjectPublicKeyRSA_hE = a[1];
            this.hex = hCert;
        };
    };

    X509.pemToBase64 = function (sCertPEM) {
        var s = sCertPEM;
        s = s.replace("-----BEGIN CERTIFICATE-----", "");
        s = s.replace("-----END CERTIFICATE-----", "");
        s = s.replace(/[ \n]+/g, "");
        return s;
    };

    X509.pemToHex = function (sCertPEM) {
        var b64Cert = X509.pemToBase64(sCertPEM);
        var hCert = b64tohex(b64Cert);
        return hCert;
    };

// NOTE: Without BITSTRING encapsulation.
    X509.getSubjectPublicKeyPosFromCertHex = function (hCert) {
        var pInfo = X509.getSubjectPublicKeyInfoPosFromCertHex(hCert);
        if (pInfo == -1) return -1;
        var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo);
        if (a.length != 2) return -1;
        var pBitString = a[1];
        if (hCert.substring(pBitString, pBitString + 2) != '03') return -1;
        var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString);

        if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
        return pBitStringV + 2;
    };

// NOTE: privateKeyUsagePeriod field of X509v2 not supported.
// NOTE: v1 and v3 supported
    X509.getSubjectPublicKeyInfoPosFromCertHex = function (hCert) {
        var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
        var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert);
        if (a.length < 1) return -1;
        if (hCert.substring(a[0], a[0] + 10) == "a003020102") { // v3
            if (a.length < 6) return -1;
            return a[6];
        } else {
            if (a.length < 5) return -1;
            return a[5];
        }
    };

    X509.getPublicKeyHexArrayFromCertHex = function (hCert) {
        var p = X509.getSubjectPublicKeyPosFromCertHex(hCert);
        var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p);
        if (a.length != 2) return [];
        var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]);
        var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]);
        if (hN != null && hE != null) {
            return [hN, hE];
        } else {
            return [];
        }
    };

    X509.getHexTbsCertificateFromCert = function (hCert) {
        var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0);
        return pTbsCert;
    };

    X509.getPublicKeyHexArrayFromCertPEM = function (sCertPEM) {
        var hCert = X509.pemToHex(sCertPEM);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        return a;
    };

    X509.hex2dn = function (hDN) {
        var s = "";
        var a = ASN1HEX.getPosArrayOfChildren_AtObj(hDN, 0);
        for (var i = 0; i < a.length; i++) {
            var hRDN = ASN1HEX.getHexOfTLV_AtObj(hDN, a[i]);
            s = s + "/" + X509.hex2rdn(hRDN);
        }
        return s;
    };

    X509.hex2rdn = function (hRDN) {
        var hType = ASN1HEX.getDecendantHexTLVByNthList(hRDN, 0, [0, 0]);
        var hValue = ASN1HEX.getDecendantHexVByNthList(hRDN, 0, [0, 1]);
        var type = "";
        try {
            type = X509.DN_ATTRHEX[hType];
        } catch (ex) {
            type = hType;
        }
        hValue = hValue.replace(/(..)/g, "%$1");
        var value = decodeURIComponent(hValue);
        return type + "=" + value;
    };

    X509.DN_ATTRHEX = {
        "0603550406": "C",
        "060355040a": "O",
        "060355040b": "OU",
        "0603550403": "CN",
        "0603550405": "SN",
        "0603550408": "ST",
        "0603550407": "L",
    };

    /**
     * get RSAKey/ECDSA public key object from PEM certificate string
     * @name getPublicKeyFromCertPEM
     * @memberOf X509
     * @function
     * @param {String} sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
     * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
     * @since x509 1.1.1
     * @description
     * NOTE: DSA is also supported since x509 1.1.2.
     */
    X509.getPublicKeyFromCertPEM = function (sCertPEM) {
        var info = X509.getPublicKeyInfoPropOfCertPEM(sCertPEM);

        if (info.algoid == "2a864886f70d010101") { // RSA
            var aRSA = KEYUTIL.parsePublicRawRSAKeyHex(info.keyhex);
            var key = new RSAKey();
            key.setPublic(aRSA.n, aRSA.e);
            return key;
        } else if (info.algoid == "2a8648ce3d0201") { // ECC
            var curveName = KJUR.crypto.OID.oidhex2name[info.algparam];
            var key = new KJUR.crypto.ECDSA({'curve': curveName, 'info': info.keyhex});
            key.setPublicKeyHex(info.keyhex);
            return key;
        } else if (info.algoid == "2a8648ce380401") { // DSA 1.2.840.10040.4.1
            var p = ASN1HEX.getVbyList(info.algparam, 0, [0], "02");
            var q = ASN1HEX.getVbyList(info.algparam, 0, [1], "02");
            var g = ASN1HEX.getVbyList(info.algparam, 0, [2], "02");
            var y = ASN1HEX.getHexOfV_AtObj(info.keyhex, 0);
            y = y.substr(2);
            var key = new KJUR.crypto.DSA();
            key.setPublic(new BigInteger(p, 16),
                new BigInteger(q, 16),
                new BigInteger(g, 16),
                new BigInteger(y, 16));
            return key;
        } else {
            throw "unsupported key";
        }
    };

    /**
     * get public key information from PEM certificate
     * @name getPublicKeyInfoPropOfCertPEM
     * @memberOf X509
     * @function
     * @param {String} sCertPEM string of PEM formatted certificate
     * @return {Hash} hash of information for public key
     * @since x509 1.1.1
     * @description
     * Resulted associative array has following properties:
     * <ul>
     * <li>algoid - hexadecimal string of OID of asymmetric key algorithm</li>
     * <li>algparam - hexadecimal string of OID of ECC curve name or null</li>
     * <li>keyhex - hexadecimal string of key in the certificate</li>
     * </ul>
     * @since x509 1.1.1
     */
    X509.getPublicKeyInfoPropOfCertPEM = function (sCertPEM) {
        var result = {};
        result.algparam = null;
        var hCert = X509.pemToHex(sCertPEM);

        // 1. Certificate ASN.1
        var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0);
        if (a1.length != 3)
            throw "malformed X.509 certificate PEM (code:001)"; // not 3 item of seq Cert

        // 2. tbsCertificate
        if (hCert.substr(a1[0], 2) != "30")
            throw "malformed X.509 certificate PEM (code:002)"; // tbsCert not seq

        var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]);

        // 3. subjectPublicKeyInfo
        if (a2.length < 7)
            throw "malformed X.509 certificate PEM (code:003)"; // no subjPubKeyInfo

        var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[6]);

        if (a3.length != 2)
            throw "malformed X.509 certificate PEM (code:004)"; // not AlgId and PubKey

        // 4. AlgId
        var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]);

        if (a4.length != 2)
            throw "malformed X.509 certificate PEM (code:005)"; // not 2 item in AlgId

        result.algoid = ASN1HEX.getHexOfV_AtObj(hCert, a4[0]);

        if (hCert.substr(a4[1], 2) == "06") { // EC
            result.algparam = ASN1HEX.getHexOfV_AtObj(hCert, a4[1]);
        } else if (hCert.substr(a4[1], 2) == "30") { // DSA
            result.algparam = ASN1HEX.getHexOfTLV_AtObj(hCert, a4[1]);
        }

        // 5. Public Key Hex
        if (hCert.substr(a3[1], 02) != "03")
            throw "malformed X.509 certificate PEM (code:006)"; // not bitstring

        var unusedBitAndKeyHex = ASN1HEX.getHexOfV_AtObj(hCert, a3[1]);
        result.keyhex = unusedBitAndKeyHex.substr(2);

        return result;
    };

    /*
     X509.prototype.readCertPEM = _x509_readCertPEM;
     X509.prototype.readCertPEMWithoutRSAInit = _x509_readCertPEMWithoutRSAInit;
     X509.prototype.getSerialNumberHex = _x509_getSerialNumberHex;
     X509.prototype.getIssuerHex = _x509_getIssuerHex;
     X509.prototype.getSubjectHex = _x509_getSubjectHex;
     X509.prototype.getIssuerString = _x509_getIssuerString;
     X509.prototype.getSubjectString = _x509_getSubjectString;
     X509.prototype.getNotBefore = _x509_getNotBefore;
     X509.prototype.getNotAfter = _x509_getNotAfter;
     */


    /*! crypto-1.1.5.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
     */
    /*
     * crypto.js - Cryptographic Algorithm Provider class
     *
     * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
     *
     * This software is licensed under the terms of the MIT License.
     * http://kjur.github.com/jsrsasign/license
     *
     * The above copyright and license notice shall be
     * included in all copies or substantial portions of the Software.
     */

    /**
     * @fileOverview
     * @name crypto-1.1.js
     * @author Kenji Urushima kenji.urushima@gmail.com
     * @version 1.1.5 (2013-Oct-06)
     * @since jsrsasign 2.2
     * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
     */

    /**
     * kjur's class library name space
     * @name KJUR
     * @namespace kjur's class library name space
     */
    if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
    /**
     * kjur's cryptographic algorithm provider library name space
     * <p>
     * This namespace privides following crytpgrahic classes.
     * <ul>
     * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
     * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
     * <li>{@link KJUR.crypto.Util} - cryptographic utility functions and properties</li>
     * </ul>
     * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
     * </p>
     * @name KJUR.crypto
     * @namespace
     */
    if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

    /**
     * static object for cryptographic function utilities
     * @name KJUR.crypto.Util
     * @class static object for cryptographic function utilities
     * @property {Array} DIGESTINFOHEAD PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
     * @property {Array} DEFAULTPROVIDER associative array of default provider name for each hash and signature algorithms
     * @description
     */
    KJUR.crypto.Util = new function () {
        this.DIGESTINFOHEAD = {
            'sha1': "3021300906052b0e03021a05000414",
            'sha224': "302d300d06096086480165030402040500041c",
            'sha256': "3031300d060960864801650304020105000420",
            'sha384': "3041300d060960864801650304020205000430",
            'sha512': "3051300d060960864801650304020305000440",
            'md2': "3020300c06082a864886f70d020205000410",
            'md5': "3020300c06082a864886f70d020505000410",
            'ripemd160': "3021300906052b2403020105000414",
        };

        /**
         * @since crypto 1.1.1
         */
        this.DEFAULTPROVIDER = {
            'md5': 'cryptojs',
            'sha1': 'cryptojs',
            'sha224': 'cryptojs',
            'sha256': 'cryptojs',
            'sha384': 'cryptojs',
            'sha512': 'cryptojs',
            'ripemd160': 'cryptojs',
            'hmacmd5': 'cryptojs',
            'hmacsha1': 'cryptojs',
            'hmacsha224': 'cryptojs',
            'hmacsha256': 'cryptojs',
            'hmacsha384': 'cryptojs',
            'hmacsha512': 'cryptojs',
            'hmacripemd160': 'cryptojs',

            'MD5withRSA': 'cryptojs/jsrsa',
            'SHA1withRSA': 'cryptojs/jsrsa',
            'SHA224withRSA': 'cryptojs/jsrsa',
            'SHA256withRSA': 'cryptojs/jsrsa',
            'SHA384withRSA': 'cryptojs/jsrsa',
            'SHA512withRSA': 'cryptojs/jsrsa',
            'RIPEMD160withRSA': 'cryptojs/jsrsa',

            'MD5withECDSA': 'cryptojs/jsrsa',
            'SHA1withECDSA': 'cryptojs/jsrsa',
            'SHA224withECDSA': 'cryptojs/jsrsa',
            'SHA256withECDSA': 'cryptojs/jsrsa',
            'SHA384withECDSA': 'cryptojs/jsrsa',
            'SHA512withECDSA': 'cryptojs/jsrsa',
            'RIPEMD160withECDSA': 'cryptojs/jsrsa',

            'SHA1withDSA': 'cryptojs/jsrsa',
            'SHA224withDSA': 'cryptojs/jsrsa',
            'SHA256withDSA': 'cryptojs/jsrsa',

            'MD5withRSAandMGF1': 'cryptojs/jsrsa',
            'SHA1withRSAandMGF1': 'cryptojs/jsrsa',
            'SHA224withRSAandMGF1': 'cryptojs/jsrsa',
            'SHA256withRSAandMGF1': 'cryptojs/jsrsa',
            'SHA384withRSAandMGF1': 'cryptojs/jsrsa',
            'SHA512withRSAandMGF1': 'cryptojs/jsrsa',
            'RIPEMD160withRSAandMGF1': 'cryptojs/jsrsa',
        };

        /**
         * @since crypto 1.1.2
         */
        this.CRYPTOJSMESSAGEDIGESTNAME = {
            'md5': 'CryptoJS.algo.MD5',
            'sha1': 'CryptoJS.algo.SHA1',
            'sha224': 'CryptoJS.algo.SHA224',
            'sha256': 'CryptoJS.algo.SHA256',
            'sha384': 'CryptoJS.algo.SHA384',
            'sha512': 'CryptoJS.algo.SHA512',
            'ripemd160': 'CryptoJS.algo.RIPEMD160'
        };

        /**
         * get hexadecimal DigestInfo
         * @name getDigestInfoHex
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} hHash hexadecimal hash value
         * @param {String} alg hash algorithm name (ex. 'sha1')
         * @return {String} hexadecimal string DigestInfo ASN.1 structure
         */
        this.getDigestInfoHex = function (hHash, alg) {
            if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
                throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
            return this.DIGESTINFOHEAD[alg] + hHash;
        };

        /**
         * get PKCS#1 padded hexadecimal DigestInfo
         * @name getPaddedDigestInfoHex
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} hHash hexadecimal hash value of message to be signed
         * @param {String} alg hash algorithm name (ex. 'sha1')
         * @param {Integer} keySize key bit length (ex. 1024)
         * @return {String} hexadecimal string of PKCS#1 padded DigestInfo
         */
        this.getPaddedDigestInfoHex = function (hHash, alg, keySize) {
            var hDigestInfo = this.getDigestInfoHex(hHash, alg);
            var pmStrLen = keySize / 4; // minimum PM length

            if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
                throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

            var hHead = "0001";
            var hTail = "00" + hDigestInfo;
            var hMid = "";
            var fLen = pmStrLen - hHead.length - hTail.length;
            for (var i = 0; i < fLen; i += 2) {
                hMid += "ff";
            }
            var hPaddedMessage = hHead + hMid + hTail;
            return hPaddedMessage;
        };

        /**
         * get hexadecimal hash of string with specified algorithm
         * @name hashString
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} s input string to be hashed
         * @param {String} alg hash algorithm name
         * @return {String} hexadecimal string of hash value
         * @since 1.1.1
         */
        this.hashString = function (s, alg) {
            var md = new KJUR.crypto.MessageDigest({'alg': alg});
            return md.digestString(s);
        };

        /**
         * get hexadecimal hash of hexadecimal string with specified algorithm
         * @name hashHex
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} sHex input hexadecimal string to be hashed
         * @param {String} alg hash algorithm name
         * @return {String} hexadecimal string of hash value
         * @since 1.1.1
         */
        this.hashHex = function (sHex, alg) {
            var md = new KJUR.crypto.MessageDigest({'alg': alg});
            return md.digestHex(sHex);
        };

        /**
         * get hexadecimal SHA1 hash of string
         * @name sha1
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} s input string to be hashed
         * @return {String} hexadecimal string of hash value
         * @since 1.0.3
         */
        this.sha1 = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'sha1', 'prov': 'cryptojs'});
            return md.digestString(s);
        };

        /**
         * get hexadecimal SHA256 hash of string
         * @name sha256
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} s input string to be hashed
         * @return {String} hexadecimal string of hash value
         * @since 1.0.3
         */
        this.sha256 = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'sha256', 'prov': 'cryptojs'});
            return md.digestString(s);
        };

        this.sha256Hex = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'sha256', 'prov': 'cryptojs'});
            return md.digestHex(s);
        };

        /**
         * get hexadecimal SHA512 hash of string
         * @name sha512
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} s input string to be hashed
         * @return {String} hexadecimal string of hash value
         * @since 1.0.3
         */
        this.sha512 = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'sha512', 'prov': 'cryptojs'});
            return md.digestString(s);
        };

        this.sha512Hex = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'sha512', 'prov': 'cryptojs'});
            return md.digestHex(s);
        };

        /**
         * get hexadecimal MD5 hash of string
         * @name md5
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} s input string to be hashed
         * @return {String} hexadecimal string of hash value
         * @since 1.0.3
         */
        this.md5 = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'md5', 'prov': 'cryptojs'});
            return md.digestString(s);
        };

        /**
         * get hexadecimal RIPEMD160 hash of string
         * @name ripemd160
         * @memberOf KJUR.crypto.Util
         * @function
         * @param {String} s input string to be hashed
         * @return {String} hexadecimal string of hash value
         * @since 1.0.3
         */
        this.ripemd160 = function (s) {
            var md = new KJUR.crypto.MessageDigest({'alg': 'ripemd160', 'prov': 'cryptojs'});
            return md.digestString(s);
        };

        /**
         * @since 1.1.2
         */
        this.getCryptoJSMDByName = function (s) {

        };
    };

    /**
     * MessageDigest class which is very similar to java.security.MessageDigest class
     * @name KJUR.crypto.MessageDigest
     * @class MessageDigest class which is very similar to java.security.MessageDigest class
     * @param {Array} params parameters for constructor
     * @description
     * <br/>
     * Currently this supports following algorithm and providers combination:
     * <ul>
     * <li>md5 - cryptojs</li>
     * <li>sha1 - cryptojs</li>
     * <li>sha224 - cryptojs</li>
     * <li>sha256 - cryptojs</li>
     * <li>sha384 - cryptojs</li>
     * <li>sha512 - cryptojs</li>
     * <li>ripemd160 - cryptojs</li>
     * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
     * </ul>
     * @example
     * // CryptoJS provider sample
     * &lt;script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/core.js"&gt;&lt;/script&gt;
     * &lt;script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/sha1.js"&gt;&lt;/script&gt;
     * &lt;script src="crypto-1.0.js"&gt;&lt;/script&gt;
     * var md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
     * md.updateString('aaa')
     * var mdHex = md.digest()
     *
     * // SJCL(Stanford JavaScript Crypto Library) provider sample
     * &lt;script src="http://bitwiseshiftleft.github.io/sjcl/sjcl.js"&gt;&lt;/script&gt;
     * &lt;script src="crypto-1.0.js"&gt;&lt;/script&gt;
     * var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
     * md.updateString('aaa')
     * var mdHex = md.digest()
     */
    KJUR.crypto.MessageDigest = function (params) {
        var md = null;
        var algName = null;
        var provName = null;

        /**
         * set hash algorithm and provider
         * @name setAlgAndProvider
         * @memberOf KJUR.crypto.MessageDigest
         * @function
         * @param {String} alg hash algorithm name
         * @param {String} prov provider name
         * @description
         * @example
         * // for SHA1
         * md.setAlgAndProvider('sha1', 'cryptojs');
         * // for RIPEMD160
         * md.setAlgAndProvider('ripemd160', 'cryptojs');
         */
        this.setAlgAndProvider = function (alg, prov) {
            if (alg != null && prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];

            // for cryptojs
            if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(alg) != -1 &&
                prov == 'cryptojs') {
                try {
                    this.md = eval(KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[alg]).create();
                } catch (ex) {
                    throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
                }
                this.updateString = function (str) {
                    this.md.update(str);
                };
                this.updateHex = function (hex) {
                    var wHex = CryptoJS.enc.Hex.parse(hex);
                    this.md.update(wHex);
                };
                this.digest = function () {
                    var hash = this.md.finalize();
                    return hash.toString(CryptoJS.enc.Hex);
                };
                this.digestString = function (str) {
                    this.updateString(str);
                    return this.digest();
                };
                this.digestHex = function (hex) {
                    this.updateHex(hex);
                    return this.digest();
                };
            }
            if (':sha256:'.indexOf(alg) != -1 &&
                prov == 'sjcl') {
                try {
                    this.md = new sjcl.hash.sha256();
                } catch (ex) {
                    throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
                }
                this.updateString = function (str) {
                    this.md.update(str);
                };
                this.updateHex = function (hex) {
                    var baHex = sjcl.codec.hex.toBits(hex);
                    this.md.update(baHex);
                };
                this.digest = function () {
                    var hash = this.md.finalize();
                    return sjcl.codec.hex.fromBits(hash);
                };
                this.digestString = function (str) {
                    this.updateString(str);
                    return this.digest();
                };
                this.digestHex = function (hex) {
                    this.updateHex(hex);
                    return this.digest();
                };
            }
        };

        /**
         * update digest by specified string
         * @name updateString
         * @memberOf KJUR.crypto.MessageDigest
         * @function
         * @param {String} str string to update
         * @description
         * @example
         * md.updateString('New York');
         */
        this.updateString = function (str) {
            throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
        };

        /**
         * update digest by specified hexadecimal string
         * @name updateHex
         * @memberOf KJUR.crypto.MessageDigest
         * @function
         * @param {String} hex hexadecimal string to update
         * @description
         * @example
         * md.updateHex('0afe36');
         */
        this.updateHex = function (hex) {
            throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
        };

        /**
         * completes hash calculation and returns hash result
         * @name digest
         * @memberOf KJUR.crypto.MessageDigest
         * @function
         * @description
         * @example
         * md.digest()
         */
        this.digest = function () {
            throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
        };

        /**
         * performs final update on the digest using string, then completes the digest computation
         * @name digestString
         * @memberOf KJUR.crypto.MessageDigest
         * @function
         * @param {String} str string to final update
         * @description
         * @example
         * md.digestString('aaa')
         */
        this.digestString = function (str) {
            throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
        };

        /**
         * performs final update on the digest using hexadecimal string, then completes the digest computation
         * @name digestHex
         * @memberOf KJUR.crypto.MessageDigest
         * @function
         * @param {String} hex hexadecimal string to final update
         * @description
         * @example
         * md.digestHex('0f2abd')
         */
        this.digestHex = function (hex) {
            throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
        };

        if (params !== undefined) {
            if (params['alg'] !== undefined) {
                this.algName = params['alg'];
                if (params['prov'] === undefined)
                    this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
                this.setAlgAndProvider(this.algName, this.provName);
            }
        }
    };

    /**
     * Mac(Message Authentication Code) class which is very similar to java.security.Mac class
     * @name KJUR.crypto.Mac
     * @class Mac class which is very similar to java.security.Mac class
     * @param {Array} params parameters for constructor
     * @description
     * <br/>
     * Currently this supports following algorithm and providers combination:
     * <ul>
     * <li>hmacmd5 - cryptojs</li>
     * <li>hmacsha1 - cryptojs</li>
     * <li>hmacsha224 - cryptojs</li>
     * <li>hmacsha256 - cryptojs</li>
     * <li>hmacsha384 - cryptojs</li>
     * <li>hmacsha512 - cryptojs</li>
     * </ul>
     * NOTE: HmacSHA224 and HmacSHA384 issue was fixed since jsrsasign 4.1.4.
     * Please use 'ext/cryptojs-312-core-fix*.js' instead of 'core.js' of original CryptoJS
     * to avoid those issue.
     * @example
     * var mac = new KJUR.crypto.Mac({alg: "HmacSHA1", prov: "cryptojs", "pass": "pass"});
     * mac.updateString('aaa')
     * var macHex = md.doFinal()
     */
    KJUR.crypto.Mac = function (params) {
        var mac = null;
        var pass = null;
        var algName = null;
        var provName = null;
        var algProv = null;

        this.setAlgAndProvider = function (alg, prov) {
            if (alg == null) alg = "hmacsha1";

            alg = alg.toLowerCase();
            if (alg.substr(0, 4) != "hmac") {
                throw "setAlgAndProvider unsupported HMAC alg: " + alg;
            }

            if (prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];
            this.algProv = alg + "/" + prov;

            var hashAlg = alg.substr(4);

            // for cryptojs
            if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 &&
                prov == 'cryptojs') {
                try {
                    var mdObj = eval(KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[hashAlg]);
                    this.mac = CryptoJS.algo.HMAC.create(mdObj, this.pass);
                } catch (ex) {
                    throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
                }
                this.updateString = function (str) {
                    this.mac.update(str);
                };
                this.updateHex = function (hex) {
                    var wHex = CryptoJS.enc.Hex.parse(hex);
                    this.mac.update(wHex);
                };
                this.doFinal = function () {
                    var hash = this.mac.finalize();
                    return hash.toString(CryptoJS.enc.Hex);
                };
                this.doFinalString = function (str) {
                    this.updateString(str);
                    return this.doFinal();
                };
                this.doFinalHex = function (hex) {
                    this.updateHex(hex);
                    return this.doFinal();
                };
            }
        };

        /**
         * update digest by specified string
         * @name updateString
         * @memberOf KJUR.crypto.Mac
         * @function
         * @param {String} str string to update
         * @description
         * @example
         * md.updateString('New York');
         */
        this.updateString = function (str) {
            throw "updateString(str) not supported for this alg/prov: " + this.algProv;
        };

        /**
         * update digest by specified hexadecimal string
         * @name updateHex
         * @memberOf KJUR.crypto.Mac
         * @function
         * @param {String} hex hexadecimal string to update
         * @description
         * @example
         * md.updateHex('0afe36');
         */
        this.updateHex = function (hex) {
            throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
        };

        /**
         * completes hash calculation and returns hash result
         * @name doFinal
         * @memberOf KJUR.crypto.Mac
         * @function
         * @description
         * @example
         * md.digest()
         */
        this.doFinal = function () {
            throw "digest() not supported for this alg/prov: " + this.algProv;
        };

        /**
         * performs final update on the digest using string, then completes the digest computation
         * @name doFinalString
         * @memberOf KJUR.crypto.Mac
         * @function
         * @param {String} str string to final update
         * @description
         * @example
         * md.digestString('aaa')
         */
        this.doFinalString = function (str) {
            throw "digestString(str) not supported for this alg/prov: " + this.algProv;
        };

        /**
         * performs final update on the digest using hexadecimal string,
         * then completes the digest computation
         * @name doFinalHex
         * @memberOf KJUR.crypto.Mac
         * @function
         * @param {String} hex hexadecimal string to final update
         * @description
         * @example
         * md.digestHex('0f2abd')
         */
        this.doFinalHex = function (hex) {
            throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
        };

        if (params !== undefined) {
            if (params['pass'] !== undefined) {
                this.pass = params['pass'];
            }
            if (params['alg'] !== undefined) {
                this.algName = params['alg'];
                if (params['prov'] === undefined)
                    this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
                this.setAlgAndProvider(this.algName, this.provName);
            }
        }
    };

    /**
     * Signature class which is very similar to java.security.Signature class
     * @name KJUR.crypto.Signature
     * @class Signature class which is very similar to java.security.Signature class
     * @param {Array} params parameters for constructor
     * @property {String} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
     * @description
     * <br/>
     * As for params of constructor's argument, it can be specify following attributes:
     * <ul>
     * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}with{RSA,ECDSA,DSA})</li>
     * <li>provider - currently 'cryptojs/jsrsa' only</li>
     * </ul>
     * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
     * This Signature class supports following signature algorithm and provider names:
     * <ul>
     * <li>MD5withRSA - cryptojs/jsrsa</li>
     * <li>SHA1withRSA - cryptojs/jsrsa</li>
     * <li>SHA224withRSA - cryptojs/jsrsa</li>
     * <li>SHA256withRSA - cryptojs/jsrsa</li>
     * <li>SHA384withRSA - cryptojs/jsrsa</li>
     * <li>SHA512withRSA - cryptojs/jsrsa</li>
     * <li>RIPEMD160withRSA - cryptojs/jsrsa</li>
     * <li>MD5withECDSA - cryptojs/jsrsa</li>
     * <li>SHA1withECDSA - cryptojs/jsrsa</li>
     * <li>SHA224withECDSA - cryptojs/jsrsa</li>
     * <li>SHA256withECDSA - cryptojs/jsrsa</li>
     * <li>SHA384withECDSA - cryptojs/jsrsa</li>
     * <li>SHA512withECDSA - cryptojs/jsrsa</li>
     * <li>RIPEMD160withECDSA - cryptojs/jsrsa</li>
     * <li>MD5withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>SHA1withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>SHA224withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>SHA256withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>SHA384withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>SHA512withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>RIPEMD160withRSAandMGF1 - cryptojs/jsrsa</li>
     * <li>SHA1withDSA - cryptojs/jsrsa</li>
     * <li>SHA224withDSA - cryptojs/jsrsa</li>
     * <li>SHA256withDSA - cryptojs/jsrsa</li>
     * </ul>
     * Here are supported elliptic cryptographic curve names and their aliases for ECDSA:
     * <ul>
     * <li>secp256k1</li>
     * <li>secp256r1, NIST P-256, P-256, prime256v1</li>
     * <li>secp384r1, NIST P-384, P-384</li>
     * </ul>
     * NOTE1: DSA signing algorithm is also supported since crypto 1.1.5.
     * <h4>EXAMPLES</h4>
     * @example
     * // RSA signature generation
     * var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
     * sig.init(prvKeyPEM);
     * sig.updateString('aaa');
     * var hSigVal = sig.sign();
     *
     * // DSA signature validation
     * var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withDSA"});
     * sig2.init(certPEM);
     * sig.updateString('aaa');
     * var isValid = sig2.verify(hSigVal);
     *
     * // ECDSA signing
     * var sig = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
     * sig.init(prvKeyPEM);
     * sig.updateString('aaa');
     * var sigValueHex = sig.sign();
     *
     * // ECDSA verifying
     * var sig2 = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
     * sig.init(certPEM);
     * sig.updateString('aaa');
     * var isValid = sig.verify(sigValueHex);
     */
    KJUR.crypto.Signature = function (params) {
        var prvKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for signing
        var pubKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for verifying

        var md = null; // KJUR.crypto.MessageDigest object
        var sig = null;
        var algName = null;
        var provName = null;
        var algProvName = null;
        var mdAlgName = null;
        var pubkeyAlgName = null;	// rsa,ecdsa,rsaandmgf1(=rsapss)
        var state = null;
        var pssSaltLen = -1;
        var initParams = null;

        var sHashHex = null; // hex hash value for hex
        var hDigestInfo = null;
        var hPaddedDigestInfo = null;
        var hSign = null;

        this._setAlgNames = function () {
            if (this.algName.match(/^(.+)with(.+)$/)) {
                this.mdAlgName = RegExp.$1.toLowerCase();
                this.pubkeyAlgName = RegExp.$2.toLowerCase();
            }
        };

        this._zeroPaddingOfSignature = function (hex, bitLength) {
            var s = "";
            var nZero = bitLength / 4 - hex.length;
            for (var i = 0; i < nZero; i++) {
                s = s + "0";
            }
            return s + hex;
        };

        /**
         * set signature algorithm and provider
         * @name setAlgAndProvider
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} alg signature algorithm name
         * @param {String} prov provider name
         * @description
         * @example
         * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
         */
        this.setAlgAndProvider = function (alg, prov) {
            this._setAlgNames();
            if (prov != 'cryptojs/jsrsa')
                throw "provider not supported: " + prov;

            if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(this.mdAlgName) != -1) {
                try {
                    this.md = new KJUR.crypto.MessageDigest({'alg': this.mdAlgName});
                } catch (ex) {
                    throw "setAlgAndProvider hash alg set fail alg=" +
                    this.mdAlgName + "/" + ex;
                }

                this.init = function (keyparam, pass) {
                    var keyObj = null;
                    try {
                        if (pass === undefined) {
                            keyObj = KEYUTIL.getKey(keyparam);
                        } else {
                            keyObj = KEYUTIL.getKey(keyparam, pass);
                        }
                    } catch (ex) {
                        throw "init failed:" + ex;
                    }

                    if (keyObj.isPrivate === true) {
                        this.prvKey = keyObj;
                        this.state = "SIGN";
                    } else if (keyObj.isPublic === true) {
                        this.pubKey = keyObj;
                        this.state = "VERIFY";
                    } else {
                        throw "init failed.:" + keyObj;
                    }
                };

                this.initSign = function (params) {
                    if (typeof params['ecprvhex'] == 'string' &&
                        typeof params['eccurvename'] == 'string') {
                        this.ecprvhex = params['ecprvhex'];
                        this.eccurvename = params['eccurvename'];
                    } else {
                        this.prvKey = params;
                    }
                    this.state = "SIGN";
                };

                this.initVerifyByPublicKey = function (params) {
                    if (typeof params['ecpubhex'] == 'string' &&
                        typeof params['eccurvename'] == 'string') {
                        this.ecpubhex = params['ecpubhex'];
                        this.eccurvename = params['eccurvename'];
                    } else if (params instanceof KJUR.crypto.ECDSA) {
                        this.pubKey = params;
                    } else if (params instanceof RSAKey) {
                        this.pubKey = params;
                    }
                    this.state = "VERIFY";
                };

                this.initVerifyByCertificatePEM = function (certPEM) {
                    var x509 = new X509();
                    x509.readCertPEM(certPEM);
                    this.pubKey = x509.subjectPublicKeyRSA;
                    this.state = "VERIFY";
                };

                this.updateString = function (str) {
                    this.md.updateString(str);
                };
                this.updateHex = function (hex) {
                    this.md.updateHex(hex);
                };

                this.sign = function () {
                    this.sHashHex = this.md.digest();
                    if (typeof this.ecprvhex != "undefined" &&
                        typeof this.eccurvename != "undefined") {
                        var ec = new KJUR.crypto.ECDSA({'curve': this.eccurvename});
                        this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
                    } else if (this.pubkeyAlgName == "rsaandmgf1") {
                        this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
                            this.mdAlgName,
                            this.pssSaltLen);
                    } else if (this.pubkeyAlgName == "rsa") {
                        this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
                            this.mdAlgName);
                    } else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
                        this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
                    } else if (this.prvKey instanceof KJUR.crypto.DSA) {
                        this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
                    } else {
                        throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
                    }
                    return this.hSign;
                };
                this.signString = function (str) {
                    this.updateString(str);
                    this.sign();
                };
                this.signHex = function (hex) {
                    this.updateHex(hex);
                    this.sign();
                };
                this.verify = function (hSigVal) {
                    this.sHashHex = this.md.digest();
                    if (typeof this.ecpubhex != "undefined" &&
                        typeof this.eccurvename != "undefined") {
                        var ec = new KJUR.crypto.ECDSA({curve: this.eccurvename});
                        return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
                    } else if (this.pubkeyAlgName == "rsaandmgf1") {
                        return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal,
                            this.mdAlgName,
                            this.pssSaltLen);
                    } else if (this.pubkeyAlgName == "rsa") {
                        return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
                    } else if (this.pubKey instanceof KJUR.crypto.ECDSA) {
                        return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
                    } else if (this.pubKey instanceof KJUR.crypto.DSA) {
                        return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
                    } else {
                        throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
                    }
                };
            }
        };

        /**
         * Initialize this object for signing or verifying depends on key
         * @name init
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
         * @param {String} pass (OPTION) passcode for encrypted private key
         * @since crypto 1.1.3
         * @description
         * This method is very useful initialize method for Signature class since
         * you just specify key then this method will automatically initialize it
         * using {@link KEYUTIL.getKey} method.
         * As for 'key',  following argument type are supported:
         * <h5>signing</h5>
         * <ul>
         * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
         * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
         * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
         * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
         * <li>RSAKey object of private key</li>
         * <li>KJUR.crypto.ECDSA object of private key</li>
         * <li>KJUR.crypto.DSA object of private key</li>
         * </ul>
         * <h5>verification</h5>
         * <ul>
         * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
         * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
         *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
         * <li>RSAKey object of public key</li>
         * <li>KJUR.crypto.ECDSA object of public key</li>
         * <li>KJUR.crypto.DSA object of public key</li>
         * </ul>
         * @example
         * sig.init(sCertPEM)
         */
        this.init = function (key, pass) {
            throw "init(key, pass) not supported for this alg:prov=" +
            this.algProvName;
        };

        /**
         * Initialize this object for verifying with a public key
         * @name initVerifyByPublicKey
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {Object} param RSAKey object of public key or associative array for ECDSA
         * @since 1.0.2
         * @deprecated from crypto 1.1.5. please use init() method instead.
         * @description
         * Public key information will be provided as 'param' parameter and the value will be
         * following:
         * <ul>
         * <li>{@link RSAKey} object for RSA verification</li>
         * <li>associative array for ECDSA verification
         *     (ex. <code>{'ecpubhex': '041f..', 'eccurvename': 'secp256r1'}</code>)
         * </li>
         * </ul>
         * @example
         * sig.initVerifyByPublicKey(rsaPrvKey)
         */
        this.initVerifyByPublicKey = function (rsaPubKey) {
            throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" +
            this.algProvName;
        };

        /**
         * Initialize this object for verifying with a certficate
         * @name initVerifyByCertificatePEM
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} certPEM PEM formatted string of certificate
         * @since 1.0.2
         * @deprecated from crypto 1.1.5. please use init() method instead.
         * @description
         * @example
         * sig.initVerifyByCertificatePEM(certPEM)
         */
        this.initVerifyByCertificatePEM = function (certPEM) {
            throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" +
            this.algProvName;
        };

        /**
         * Initialize this object for signing
         * @name initSign
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {Object} param RSAKey object of public key or associative array for ECDSA
         * @deprecated from crypto 1.1.5. please use init() method instead.
         * @description
         * Private key information will be provided as 'param' parameter and the value will be
         * following:
         * <ul>
         * <li>{@link RSAKey} object for RSA signing</li>
         * <li>associative array for ECDSA signing
         *     (ex. <code>{'ecprvhex': '1d3f..', 'eccurvename': 'secp256r1'}</code>)</li>
         * </ul>
         * @example
         * sig.initSign(prvKey)
         */
        this.initSign = function (prvKey) {
            throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
        };

        /**
         * Updates the data to be signed or verified by a string
         * @name updateString
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} str string to use for the update
         * @description
         * @example
         * sig.updateString('aaa')
         */
        this.updateString = function (str) {
            throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
        };

        /**
         * Updates the data to be signed or verified by a hexadecimal string
         * @name updateHex
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} hex hexadecimal string to use for the update
         * @description
         * @example
         * sig.updateHex('1f2f3f')
         */
        this.updateHex = function (hex) {
            throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
        };

        /**
         * Returns the signature bytes of all data updates as a hexadecimal string
         * @name sign
         * @memberOf KJUR.crypto.Signature
         * @function
         * @return the signature bytes as a hexadecimal string
         * @description
         * @example
         * var hSigValue = sig.sign()
         */
        this.sign = function () {
            throw "sign() not supported for this alg:prov=" + this.algProvName;
        };

        /**
         * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
         * @name signString
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} str string to final update
         * @return the signature bytes of a hexadecimal string
         * @description
         * @example
         * var hSigValue = sig.signString('aaa')
         */
        this.signString = function (str) {
            throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
        };

        /**
         * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
         * @name signHex
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} hex hexadecimal string to final update
         * @return the signature bytes of a hexadecimal string
         * @description
         * @example
         * var hSigValue = sig.signHex('1fdc33')
         */
        this.signHex = function (hex) {
            throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
        };

        /**
         * verifies the passed-in signature.
         * @name verify
         * @memberOf KJUR.crypto.Signature
         * @function
         * @param {String} str string to final update
         * @return {Boolean} true if the signature was verified, otherwise false
         * @description
         * @example
         * var isValid = sig.verify('1fbcefdca4823a7(snip)')
         */
        this.verify = function (hSigVal) {
            throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
        };

        this.initParams = params;

        if (params !== undefined) {
            if (params['alg'] !== undefined) {
                this.algName = params['alg'];
                if (params['prov'] === undefined) {
                    this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
                } else {
                    this.provName = params['prov'];
                }
                this.algProvName = this.algName + ":" + this.provName;
                this.setAlgAndProvider(this.algName, this.provName);
                this._setAlgNames();
            }

            if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'];

            if (params['prvkeypem'] !== undefined) {
                if (params['prvkeypas'] !== undefined) {
                    throw "both prvkeypem and prvkeypas parameters not supported";
                } else {
                    try {
                        var prvKey = new RSAKey();
                        prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
                        this.initSign(prvKey);
                    } catch (ex) {
                        throw "fatal error to load pem private key: " + ex;
                    }
                }
            }
        }
    };

    /**
     * static object for cryptographic function utilities
     * @name KJUR.crypto.OID
     * @class static object for cryptography related OIDs
     * @property {Array} oidhex2name key value of hexadecimal OID and its name
     *           (ex. '2a8648ce3d030107' and 'secp256r1')
     * @since crypto 1.1.3
     * @description
     */


    KJUR.crypto.OID = new function () {
        this.oidhex2name = {
            '2a864886f70d010101': 'rsaEncryption',
            '2a8648ce3d0201': 'ecPublicKey',
            '2a8648ce380401': 'dsa',
            '2a8648ce3d030107': 'secp256r1',
            '2b8104001f': 'secp192k1',
            '2b81040021': 'secp224r1',
            '2b8104000a': 'secp256k1',
            '2b81040023': 'secp521r1',
            '2b81040022': 'secp384r1',
            '2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
            '608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
            '608648016503040302': 'SHA256withDSA', // 2.16.840.1.101.3.4.3.2
        };
    };


    var JSEncryptExports = {};
    (function (exports) {
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
        var dbits;

// JavaScript engine analysis
        var canary = 0xdeadbeefcafe;
        var j_lm = ((canary & 0xffffff) == 0xefcafe);

// (public) Constructor
        function BigInteger(a, b, c) {
            if (a != null)
                if ("number" == typeof a) this.fromNumber(a, b, c);
                else if (b == null && "string" != typeof a) this.fromString(a, 256);
                else this.fromString(a, b);
        }

// return new, unset BigInteger
        function nbi() {
            return new BigInteger(null);
        }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
        function am1(i, x, w, j, c, n) {
            while (--n >= 0) {
                var v = x * this[i++] + w[j] + c;
                c = Math.floor(v / 0x4000000);
                w[j++] = v & 0x3ffffff;
            }
            return c;
        }

// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
        function am2(i, x, w, j, c, n) {
            var xl = x & 0x7fff, xh = x >> 15;
            while (--n >= 0) {
                var l = this[i] & 0x7fff;
                var h = this[i++] >> 15;
                var m = xh * l + h * xl;
                l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
                c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
                w[j++] = l & 0x3fffffff;
            }
            return c;
        }

// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
        function am3(i, x, w, j, c, n) {
            var xl = x & 0x3fff, xh = x >> 14;
            while (--n >= 0) {
                var l = this[i] & 0x3fff;
                var h = this[i++] >> 14;
                var m = xh * l + h * xl;
                l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
                c = (l >> 28) + (m >> 14) + xh * h;
                w[j++] = l & 0xfffffff;
            }
            return c;
        }

        if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
            BigInteger.prototype.am = am2;
            dbits = 30;
        }
        else if (j_lm && (navigator.appName != "Netscape")) {
            BigInteger.prototype.am = am1;
            dbits = 26;
        }
        else { // Mozilla/Netscape seems to prefer am3
            BigInteger.prototype.am = am3;
            dbits = 28;
        }

        BigInteger.prototype.DB = dbits;
        BigInteger.prototype.DM = ((1 << dbits) - 1);
        BigInteger.prototype.DV = (1 << dbits);

        var BI_FP = 52;
        BigInteger.prototype.FV = Math.pow(2, BI_FP);
        BigInteger.prototype.F1 = BI_FP - dbits;
        BigInteger.prototype.F2 = 2 * dbits - BI_FP;

// Digit conversions
        var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
        var BI_RC = new Array();
        var rr, vv;
        rr = "0".charCodeAt(0);
        for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
        rr = "a".charCodeAt(0);
        for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
        rr = "A".charCodeAt(0);
        for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

        function int2char(n) {
            return BI_RM.charAt(n);
        }

        function intAt(s, i) {
            var c = BI_RC[s.charCodeAt(i)];
            return (c == null) ? -1 : c;
        }

// (protected) copy this to r
        function bnpCopyTo(r) {
            for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
            r.t = this.t;
            r.s = this.s;
        }

// (protected) set from integer value x, -DV <= x < DV
        function bnpFromInt(x) {
            this.t = 1;
            this.s = (x < 0) ? -1 : 0;
            if (x > 0) this[0] = x;
            else if (x < -1) this[0] = x + DV;
            else this.t = 0;
        }

// return bigint initialized to value
        function nbv(i) {
            var r = nbi();
            r.fromInt(i);
            return r;
        }

// (protected) set from string and radix
        function bnpFromString(s, b) {
            var k;
            if (b == 16) k = 4;
            else if (b == 8) k = 3;
            else if (b == 256) k = 8; // byte array
            else if (b == 2) k = 1;
            else if (b == 32) k = 5;
            else if (b == 4) k = 2;
            else {
                this.fromRadix(s, b);
                return;
            }
            this.t = 0;
            this.s = 0;
            var i = s.length, mi = false, sh = 0;
            while (--i >= 0) {
                var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
                if (x < 0) {
                    if (s.charAt(i) == "-") mi = true;
                    continue;
                }
                mi = false;
                if (sh == 0)
                    this[this.t++] = x;
                else if (sh + k > this.DB) {
                    this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                    this[this.t++] = (x >> (this.DB - sh));
                }
                else
                    this[this.t - 1] |= x << sh;
                sh += k;
                if (sh >= this.DB) sh -= this.DB;
            }
            if (k == 8 && (s[0] & 0x80) != 0) {
                this.s = -1;
                if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
            }
            this.clamp();
            if (mi) BigInteger.ZERO.subTo(this, this);
        }

// (protected) clamp off excess high words
        function bnpClamp() {
            var c = this.s & this.DM;
            while (this.t > 0 && this[this.t - 1] == c) --this.t;
        }

// (public) return string representation in given radix
        function bnToString(b) {
            if (this.s < 0) return "-" + this.negate().toString(b);
            var k;
            if (b == 16) k = 4;
            else if (b == 8) k = 3;
            else if (b == 2) k = 1;
            else if (b == 32) k = 5;
            else if (b == 4) k = 2;
            else return this.toRadix(b);
            var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
            var p = this.DB - (i * this.DB) % k;
            if (i-- > 0) {
                if (p < this.DB && (d = this[i] >> p) > 0) {
                    m = true;
                    r = int2char(d);
                }
                while (i >= 0) {
                    if (p < k) {
                        d = (this[i] & ((1 << p) - 1)) << (k - p);
                        d |= this[--i] >> (p += this.DB - k);
                    }
                    else {
                        d = (this[i] >> (p -= k)) & km;
                        if (p <= 0) {
                            p += this.DB;
                            --i;
                        }
                    }
                    if (d > 0) m = true;
                    if (m) r += int2char(d);
                }
            }
            return m ? r : "0";
        }

// (public) -this
        function bnNegate() {
            var r = nbi();
            BigInteger.ZERO.subTo(this, r);
            return r;
        }

// (public) |this|
        function bnAbs() {
            return (this.s < 0) ? this.negate() : this;
        }

// (public) return + if this > a, - if this < a, 0 if equal
        function bnCompareTo(a) {
            var r = this.s - a.s;
            if (r != 0) return r;
            var i = this.t;
            r = i - a.t;
            if (r != 0) return (this.s < 0) ? -r : r;
            while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
            return 0;
        }

// returns bit length of the integer x
        function nbits(x) {
            var r = 1, t;
            if ((t = x >>> 16) != 0) {
                x = t;
                r += 16;
            }
            if ((t = x >> 8) != 0) {
                x = t;
                r += 8;
            }
            if ((t = x >> 4) != 0) {
                x = t;
                r += 4;
            }
            if ((t = x >> 2) != 0) {
                x = t;
                r += 2;
            }
            if ((t = x >> 1) != 0) {
                x = t;
                r += 1;
            }
            return r;
        }

// (public) return the number of bits in "this"
        function bnBitLength() {
            if (this.t <= 0) return 0;
            return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
        }

// (protected) r = this << n*DB
        function bnpDLShiftTo(n, r) {
            var i;
            for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
            for (i = n - 1; i >= 0; --i) r[i] = 0;
            r.t = this.t + n;
            r.s = this.s;
        }

// (protected) r = this >> n*DB
        function bnpDRShiftTo(n, r) {
            for (var i = n; i < this.t; ++i) r[i - n] = this[i];
            r.t = Math.max(this.t - n, 0);
            r.s = this.s;
        }

// (protected) r = this << n
        function bnpLShiftTo(n, r) {
            var bs = n % this.DB;
            var cbs = this.DB - bs;
            var bm = (1 << cbs) - 1;
            var ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
            for (i = this.t - 1; i >= 0; --i) {
                r[i + ds + 1] = (this[i] >> cbs) | c;
                c = (this[i] & bm) << bs;
            }
            for (i = ds - 1; i >= 0; --i) r[i] = 0;
            r[ds] = c;
            r.t = this.t + ds + 1;
            r.s = this.s;
            r.clamp();
        }

// (protected) r = this >> n
        function bnpRShiftTo(n, r) {
            r.s = this.s;
            var ds = Math.floor(n / this.DB);
            if (ds >= this.t) {
                r.t = 0;
                return;
            }
            var bs = n % this.DB;
            var cbs = this.DB - bs;
            var bm = (1 << bs) - 1;
            r[0] = this[ds] >> bs;
            for (var i = ds + 1; i < this.t; ++i) {
                r[i - ds - 1] |= (this[i] & bm) << cbs;
                r[i - ds] = this[i] >> bs;
            }
            if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
            r.t = this.t - ds;
            r.clamp();
        }

// (protected) r = this - a
        function bnpSubTo(a, r) {
            var i = 0, c = 0, m = Math.min(a.t, this.t);
            while (i < m) {
                c += this[i] - a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            if (a.t < this.t) {
                c -= a.s;
                while (i < this.t) {
                    c += this[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB;
                }
                c += this.s;
            }
            else {
                c += this.s;
                while (i < a.t) {
                    c -= a[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB;
                }
                c -= a.s;
            }
            r.s = (c < 0) ? -1 : 0;
            if (c < -1) r[i++] = this.DV + c;
            else if (c > 0) r[i++] = c;
            r.t = i;
            r.clamp();
        }

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
        function bnpMultiplyTo(a, r) {
            var x = this.abs(), y = a.abs();
            var i = x.t;
            r.t = i + y.t;
            while (--i >= 0) r[i] = 0;
            for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
            r.s = 0;
            r.clamp();
            if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
        }

// (protected) r = this^2, r != this (HAC 14.16)
        function bnpSquareTo(r) {
            var x = this.abs();
            var i = r.t = 2 * x.t;
            while (--i >= 0) r[i] = 0;
            for (i = 0; i < x.t - 1; ++i) {
                var c = x.am(i, x[i], r, 2 * i, 0, 1);
                if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                    r[i + x.t] -= x.DV;
                    r[i + x.t + 1] = 1;
                }
            }
            if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
            r.s = 0;
            r.clamp();
        }

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
        function bnpDivRemTo(m, q, r) {
            var pm = m.abs();
            if (pm.t <= 0) return;
            var pt = this.abs();
            if (pt.t < pm.t) {
                if (q != null) q.fromInt(0);
                if (r != null) this.copyTo(r);
                return;
            }
            if (r == null) r = nbi();
            var y = nbi(), ts = this.s, ms = m.s;
            var nsh = this.DB - nbits(pm[pm.t - 1]);	// normalize modulus
            if (nsh > 0) {
                pm.lShiftTo(nsh, y);
                pt.lShiftTo(nsh, r);
            }
            else {
                pm.copyTo(y);
                pt.copyTo(r);
            }
            var ys = y.t;
            var y0 = y[ys - 1];
            if (y0 == 0) return;
            var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
            var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
            var i = r.t, j = i - ys, t = (q == null) ? nbi() : q;
            y.dlShiftTo(j, t);
            if (r.compareTo(t) >= 0) {
                r[r.t++] = 1;
                r.subTo(t, r);
            }
            BigInteger.ONE.dlShiftTo(ys, t);
            t.subTo(y, y);	// "negative" y so we can replace sub with am later
            while (y.t < ys) y[y.t++] = 0;
            while (--j >= 0) {
                // Estimate quotient digit
                var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
                if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {	// Try it out
                    y.dlShiftTo(j, t);
                    r.subTo(t, r);
                    while (r[i] < --qd) r.subTo(t, r);
                }
            }
            if (q != null) {
                r.drShiftTo(ys, q);
                if (ts != ms) BigInteger.ZERO.subTo(q, q);
            }
            r.t = ys;
            r.clamp();
            if (nsh > 0) r.rShiftTo(nsh, r);	// Denormalize remainder
            if (ts < 0) BigInteger.ZERO.subTo(r, r);
        }

// (public) this mod a
        function bnMod(a) {
            var r = nbi();
            this.abs().divRemTo(a, null, r);
            if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
            return r;
        }

// Modular reduction using "classic" algorithm
        function Classic(m) {
            this.m = m;
        }

        function cConvert(x) {
            if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
            else return x;
        }

        function cRevert(x) {
            return x;
        }

        function cReduce(x) {
            x.divRemTo(this.m, null, x);
        }

        function cMulTo(x, y, r) {
            x.multiplyTo(y, r);
            this.reduce(r);
        }

        function cSqrTo(x, r) {
            x.squareTo(r);
            this.reduce(r);
        }

        Classic.prototype.convert = cConvert;
        Classic.prototype.revert = cRevert;
        Classic.prototype.reduce = cReduce;
        Classic.prototype.mulTo = cMulTo;
        Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
        function bnpInvDigit() {
            if (this.t < 1) return 0;
            var x = this[0];
            if ((x & 1) == 0) return 0;
            var y = x & 3;		// y == 1/x mod 2^2
            y = (y * (2 - (x & 0xf) * y)) & 0xf;	// y == 1/x mod 2^4
            y = (y * (2 - (x & 0xff) * y)) & 0xff;	// y == 1/x mod 2^8
            y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;	// y == 1/x mod 2^16
            // last step - calculate inverse mod DV directly;
            // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
            y = (y * (2 - x * y % this.DV)) % this.DV;		// y == 1/x mod 2^dbits
            // we really want the negative inverse, and -DV < y < DV
            return (y > 0) ? this.DV - y : -y;
        }

// Montgomery reduction
        function Montgomery(m) {
            this.m = m;
            this.mp = m.invDigit();
            this.mpl = this.mp & 0x7fff;
            this.mph = this.mp >> 15;
            this.um = (1 << (m.DB - 15)) - 1;
            this.mt2 = 2 * m.t;
        }

// xR mod m
        function montConvert(x) {
            var r = nbi();
            x.abs().dlShiftTo(this.m.t, r);
            r.divRemTo(this.m, null, r);
            if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
            return r;
        }

// x/R mod m
        function montRevert(x) {
            var r = nbi();
            x.copyTo(r);
            this.reduce(r);
            return r;
        }

// x = x/R mod m (HAC 14.32)
        function montReduce(x) {
            while (x.t <= this.mt2)	// pad x so am has enough room later
                x[x.t++] = 0;
            for (var i = 0; i < this.m.t; ++i) {
                // faster way of calculating u0 = x[i]*mp mod DV
                var j = x[i] & 0x7fff;
                var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
                // use am to combine the multiply-shift-add into one call
                j = i + this.m.t;
                x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
                // propagate carry
                while (x[j] >= x.DV) {
                    x[j] -= x.DV;
                    x[++j]++;
                }
            }
            x.clamp();
            x.drShiftTo(this.m.t, x);
            if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
        }

// r = "x^2/R mod m"; x != r
        function montSqrTo(x, r) {
            x.squareTo(r);
            this.reduce(r);
        }

// r = "xy/R mod m"; x,y != r
        function montMulTo(x, y, r) {
            x.multiplyTo(y, r);
            this.reduce(r);
        }

        Montgomery.prototype.convert = montConvert;
        Montgomery.prototype.revert = montRevert;
        Montgomery.prototype.reduce = montReduce;
        Montgomery.prototype.mulTo = montMulTo;
        Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
        function bnpIsEven() {
            return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
        }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
        function bnpExp(e, z) {
            if (e > 0xffffffff || e < 1) return BigInteger.ONE;
            var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
            g.copyTo(r);
            while (--i >= 0) {
                z.sqrTo(r, r2);
                if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
                else {
                    var t = r;
                    r = r2;
                    r2 = t;
                }
            }
            return z.revert(r);
        }

// (public) this^e % m, 0 <= e < 2^32
        function bnModPowInt(e, m) {
            var z;
            if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
            return this.exp(e, z);
        }

// protected
        BigInteger.prototype.copyTo = bnpCopyTo;
        BigInteger.prototype.fromInt = bnpFromInt;
        BigInteger.prototype.fromString = bnpFromString;
        BigInteger.prototype.clamp = bnpClamp;
        BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
        BigInteger.prototype.drShiftTo = bnpDRShiftTo;
        BigInteger.prototype.lShiftTo = bnpLShiftTo;
        BigInteger.prototype.rShiftTo = bnpRShiftTo;
        BigInteger.prototype.subTo = bnpSubTo;
        BigInteger.prototype.multiplyTo = bnpMultiplyTo;
        BigInteger.prototype.squareTo = bnpSquareTo;
        BigInteger.prototype.divRemTo = bnpDivRemTo;
        BigInteger.prototype.invDigit = bnpInvDigit;
        BigInteger.prototype.isEven = bnpIsEven;
        BigInteger.prototype.exp = bnpExp;

// public
        BigInteger.prototype.toString = bnToString;
        BigInteger.prototype.negate = bnNegate;
        BigInteger.prototype.abs = bnAbs;
        BigInteger.prototype.compareTo = bnCompareTo;
        BigInteger.prototype.bitLength = bnBitLength;
        BigInteger.prototype.mod = bnMod;
        BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
        BigInteger.ZERO = nbv(0);
        BigInteger.ONE = nbv(1);
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
        function bnClone() {
            var r = nbi();
            this.copyTo(r);
            return r;
        }

// (public) return value as integer
        function bnIntValue() {
            if (this.s < 0) {
                if (this.t == 1) return this[0] - this.DV;
                else if (this.t == 0) return -1;
            }
            else if (this.t == 1) return this[0];
            else if (this.t == 0) return 0;
            // assumes 16 < DB < 32
            return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
        }

// (public) return value as byte
        function bnByteValue() {
            return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
        }

// (public) return value as short (assumes DB>=16)
        function bnShortValue() {
            return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
        }

// (protected) return x s.t. r^x < DV
        function bnpChunkSize(r) {
            return Math.floor(Math.LN2 * this.DB / Math.log(r));
        }

// (public) 0 if this == 0, 1 if this > 0
        function bnSigNum() {
            if (this.s < 0) return -1;
            else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
            else return 1;
        }

// (protected) convert to radix string
        function bnpToRadix(b) {
            if (b == null) b = 10;
            if (this.signum() == 0 || b < 2 || b > 36) return "0";
            var cs = this.chunkSize(b);
            var a = Math.pow(b, cs);
            var d = nbv(a), y = nbi(), z = nbi(), r = "";
            this.divRemTo(d, y, z);
            while (y.signum() > 0) {
                r = (a + z.intValue()).toString(b).substr(1) + r;
                y.divRemTo(d, y, z);
            }
            return z.intValue().toString(b) + r;
        }

// (protected) convert from radix string
        function bnpFromRadix(s, b) {
            this.fromInt(0);
            if (b == null) b = 10;
            var cs = this.chunkSize(b);
            var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
            for (var i = 0; i < s.length; ++i) {
                var x = intAt(s, i);
                if (x < 0) {
                    if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
                    continue;
                }
                w = b * w + x;
                if (++j >= cs) {
                    this.dMultiply(d);
                    this.dAddOffset(w, 0);
                    j = 0;
                    w = 0;
                }
            }
            if (j > 0) {
                this.dMultiply(Math.pow(b, j));
                this.dAddOffset(w, 0);
            }
            if (mi) BigInteger.ZERO.subTo(this, this);
        }

// (protected) alternate constructor
        function bnpFromNumber(a, b, c) {
            if ("number" == typeof b) {
                // new BigInteger(int,int,RNG)
                if (a < 2) this.fromInt(1);
                else {
                    this.fromNumber(a, c);
                    if (!this.testBit(a - 1))	// force MSB set
                        this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
                    if (this.isEven()) this.dAddOffset(1, 0); // force odd
                    while (!this.isProbablePrime(b)) {
                        this.dAddOffset(2, 0);
                        if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
                    }
                }
            }
            else {
                // new BigInteger(int,RNG)
                var x = new Array(), t = a & 7;
                x.length = (a >> 3) + 1;
                b.nextBytes(x);
                if (t > 0) x[0] &= ((1 << t) - 1); else x[0] = 0;
                this.fromString(x, 256);
            }
        }

// (public) convert to bigendian byte array
        function bnToByteArray() {
            var i = this.t, r = new Array();
            r[0] = this.s;
            var p = this.DB - (i * this.DB) % 8, d, k = 0;
            if (i-- > 0) {
                if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
                    r[k++] = d | (this.s << (this.DB - p));
                while (i >= 0) {
                    if (p < 8) {
                        d = (this[i] & ((1 << p) - 1)) << (8 - p);
                        d |= this[--i] >> (p += this.DB - 8);
                    }
                    else {
                        d = (this[i] >> (p -= 8)) & 0xff;
                        if (p <= 0) {
                            p += this.DB;
                            --i;
                        }
                    }
                    if ((d & 0x80) != 0) d |= -256;
                    if (k == 0 && (this.s & 0x80) != (d & 0x80)) ++k;
                    if (k > 0 || d != this.s) r[k++] = d;
                }
            }
            return r;
        }

        function bnEquals(a) {
            return (this.compareTo(a) == 0);
        }

        function bnMin(a) {
            return (this.compareTo(a) < 0) ? this : a;
        }

        function bnMax(a) {
            return (this.compareTo(a) > 0) ? this : a;
        }

// (protected) r = this op a (bitwise)
        function bnpBitwiseTo(a, op, r) {
            var i, f, m = Math.min(a.t, this.t);
            for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
            if (a.t < this.t) {
                f = a.s & this.DM;
                for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
                r.t = this.t;
            }
            else {
                f = this.s & this.DM;
                for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
                r.t = a.t;
            }
            r.s = op(this.s, a.s);
            r.clamp();
        }

// (public) this & a
        function op_and(x, y) {
            return x & y;
        }

        function bnAnd(a) {
            var r = nbi();
            this.bitwiseTo(a, op_and, r);
            return r;
        }

// (public) this | a
        function op_or(x, y) {
            return x | y;
        }

        function bnOr(a) {
            var r = nbi();
            this.bitwiseTo(a, op_or, r);
            return r;
        }

// (public) this ^ a
        function op_xor(x, y) {
            return x ^ y;
        }

        function bnXor(a) {
            var r = nbi();
            this.bitwiseTo(a, op_xor, r);
            return r;
        }

// (public) this & ~a
        function op_andnot(x, y) {
            return x & ~y;
        }

        function bnAndNot(a) {
            var r = nbi();
            this.bitwiseTo(a, op_andnot, r);
            return r;
        }

// (public) ~this
        function bnNot() {
            var r = nbi();
            for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
            r.t = this.t;
            r.s = ~this.s;
            return r;
        }

// (public) this << n
        function bnShiftLeft(n) {
            var r = nbi();
            if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r);
            return r;
        }

// (public) this >> n
        function bnShiftRight(n) {
            var r = nbi();
            if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r);
            return r;
        }

// return index of lowest 1-bit in x, x < 2^31
        function lbit(x) {
            if (x == 0) return -1;
            var r = 0;
            if ((x & 0xffff) == 0) {
                x >>= 16;
                r += 16;
            }
            if ((x & 0xff) == 0) {
                x >>= 8;
                r += 8;
            }
            if ((x & 0xf) == 0) {
                x >>= 4;
                r += 4;
            }
            if ((x & 3) == 0) {
                x >>= 2;
                r += 2;
            }
            if ((x & 1) == 0) ++r;
            return r;
        }

// (public) returns index of lowest 1-bit (or -1 if none)
        function bnGetLowestSetBit() {
            for (var i = 0; i < this.t; ++i)
                if (this[i] != 0) return i * this.DB + lbit(this[i]);
            if (this.s < 0) return this.t * this.DB;
            return -1;
        }

// return number of 1 bits in x
        function cbit(x) {
            var r = 0;
            while (x != 0) {
                x &= x - 1;
                ++r;
            }
            return r;
        }

// (public) return number of set bits
        function bnBitCount() {
            var r = 0, x = this.s & this.DM;
            for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
            return r;
        }

// (public) true iff nth bit is set
        function bnTestBit(n) {
            var j = Math.floor(n / this.DB);
            if (j >= this.t) return (this.s != 0);
            return ((this[j] & (1 << (n % this.DB))) != 0);
        }

// (protected) this op (1<<n)
        function bnpChangeBit(n, op) {
            var r = BigInteger.ONE.shiftLeft(n);
            this.bitwiseTo(r, op, r);
            return r;
        }

// (public) this | (1<<n)
        function bnSetBit(n) {
            return this.changeBit(n, op_or);
        }

// (public) this & ~(1<<n)
        function bnClearBit(n) {
            return this.changeBit(n, op_andnot);
        }

// (public) this ^ (1<<n)
        function bnFlipBit(n) {
            return this.changeBit(n, op_xor);
        }

// (protected) r = this + a
        function bnpAddTo(a, r) {
            var i = 0, c = 0, m = Math.min(a.t, this.t);
            while (i < m) {
                c += this[i] + a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            if (a.t < this.t) {
                c += a.s;
                while (i < this.t) {
                    c += this[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB;
                }
                c += this.s;
            }
            else {
                c += this.s;
                while (i < a.t) {
                    c += a[i];
                    r[i++] = c & this.DM;
                    c >>= this.DB;
                }
                c += a.s;
            }
            r.s = (c < 0) ? -1 : 0;
            if (c > 0) r[i++] = c;
            else if (c < -1) r[i++] = this.DV + c;
            r.t = i;
            r.clamp();
        }

// (public) this + a
        function bnAdd(a) {
            var r = nbi();
            this.addTo(a, r);
            return r;
        }

// (public) this - a
        function bnSubtract(a) {
            var r = nbi();
            this.subTo(a, r);
            return r;
        }

// (public) this * a
        function bnMultiply(a) {
            var r = nbi();
            this.multiplyTo(a, r);
            return r;
        }

// (public) this^2
        function bnSquare() {
            var r = nbi();
            this.squareTo(r);
            return r;
        }

// (public) this / a
        function bnDivide(a) {
            var r = nbi();
            this.divRemTo(a, r, null);
            return r;
        }

// (public) this % a
        function bnRemainder(a) {
            var r = nbi();
            this.divRemTo(a, null, r);
            return r;
        }

// (public) [this/a,this%a]
        function bnDivideAndRemainder(a) {
            var q = nbi(), r = nbi();
            this.divRemTo(a, q, r);
            return new Array(q, r);
        }

// (protected) this *= n, this >= 0, 1 < n < DV
        function bnpDMultiply(n) {
            this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
            ++this.t;
            this.clamp();
        }

// (protected) this += n << w words, this >= 0
        function bnpDAddOffset(n, w) {
            if (n == 0) return;
            while (this.t <= w) this[this.t++] = 0;
            this[w] += n;
            while (this[w] >= this.DV) {
                this[w] -= this.DV;
                if (++w >= this.t) this[this.t++] = 0;
                ++this[w];
            }
        }

// A "null" reducer
        function NullExp() {
        }

        function nNop(x) {
            return x;
        }

        function nMulTo(x, y, r) {
            x.multiplyTo(y, r);
        }

        function nSqrTo(x, r) {
            x.squareTo(r);
        }

        NullExp.prototype.convert = nNop;
        NullExp.prototype.revert = nNop;
        NullExp.prototype.mulTo = nMulTo;
        NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
        function bnPow(e) {
            return this.exp(e, new NullExp());
        }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
        function bnpMultiplyLowerTo(a, n, r) {
            var i = Math.min(this.t + a.t, n);
            r.s = 0; // assumes a,this >= 0
            r.t = i;
            while (i > 0) r[--i] = 0;
            var j;
            for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
            for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
            r.clamp();
        }

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
        function bnpMultiplyUpperTo(a, n, r) {
            --n;
            var i = r.t = this.t + a.t - n;
            r.s = 0; // assumes a,this >= 0
            while (--i >= 0) r[i] = 0;
            for (i = Math.max(n - this.t, 0); i < a.t; ++i)
                r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
            r.clamp();
            r.drShiftTo(1, r);
        }

// Barrett modular reduction
        function Barrett(m) {
            // setup Barrett
            this.r2 = nbi();
            this.q3 = nbi();
            BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
            this.mu = this.r2.divide(m);
            this.m = m;
        }

        function barrettConvert(x) {
            if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
            else if (x.compareTo(this.m) < 0) return x;
            else {
                var r = nbi();
                x.copyTo(r);
                this.reduce(r);
                return r;
            }
        }

        function barrettRevert(x) {
            return x;
        }

// x = x mod m (HAC 14.42)
        function barrettReduce(x) {
            x.drShiftTo(this.m.t - 1, this.r2);
            if (x.t > this.m.t + 1) {
                x.t = this.m.t + 1;
                x.clamp();
            }
            this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
            this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
            while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
            x.subTo(this.r2, x);
            while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
        }

// r = x^2 mod m; x != r
        function barrettSqrTo(x, r) {
            x.squareTo(r);
            this.reduce(r);
        }

// r = x*y mod m; x,y != r
        function barrettMulTo(x, y, r) {
            x.multiplyTo(y, r);
            this.reduce(r);
        }

        Barrett.prototype.convert = barrettConvert;
        Barrett.prototype.revert = barrettRevert;
        Barrett.prototype.reduce = barrettReduce;
        Barrett.prototype.mulTo = barrettMulTo;
        Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
        function bnModPow(e, m) {
            var i = e.bitLength(), k, r = nbv(1), z;
            if (i <= 0) return r;
            else if (i < 18) k = 1;
            else if (i < 48) k = 3;
            else if (i < 144) k = 4;
            else if (i < 768) k = 5;
            else k = 6;
            if (i < 8)
                z = new Classic(m);
            else if (m.isEven())
                z = new Barrett(m);
            else
                z = new Montgomery(m);

            // precomputation
            var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
            g[1] = z.convert(this);
            if (k > 1) {
                var g2 = nbi();
                z.sqrTo(g[1], g2);
                while (n <= km) {
                    g[n] = nbi();
                    z.mulTo(g2, g[n - 2], g[n]);
                    n += 2;
                }
            }

            var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
            i = nbits(e[j]) - 1;
            while (j >= 0) {
                if (i >= k1) w = (e[j] >> (i - k1)) & km;
                else {
                    w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                    if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
                }

                n = k;
                while ((w & 1) == 0) {
                    w >>= 1;
                    --n;
                }
                if ((i -= n) < 0) {
                    i += this.DB;
                    --j;
                }
                if (is1) {	// ret == 1, don't bother squaring or multiplying it
                    g[w].copyTo(r);
                    is1 = false;
                }
                else {
                    while (n > 1) {
                        z.sqrTo(r, r2);
                        z.sqrTo(r2, r);
                        n -= 2;
                    }
                    if (n > 0) z.sqrTo(r, r2); else {
                        t = r;
                        r = r2;
                        r2 = t;
                    }
                    z.mulTo(r2, g[w], r);
                }

                while (j >= 0 && (e[j] & (1 << i)) == 0) {
                    z.sqrTo(r, r2);
                    t = r;
                    r = r2;
                    r2 = t;
                    if (--i < 0) {
                        i = this.DB - 1;
                        --j;
                    }
                }
            }
            return z.revert(r);
        }

// (public) gcd(this,a) (HAC 14.54)
        function bnGCD(a) {
            var x = (this.s < 0) ? this.negate() : this.clone();
            var y = (a.s < 0) ? a.negate() : a.clone();
            if (x.compareTo(y) < 0) {
                var t = x;
                x = y;
                y = t;
            }
            var i = x.getLowestSetBit(), g = y.getLowestSetBit();
            if (g < 0) return x;
            if (i < g) g = i;
            if (g > 0) {
                x.rShiftTo(g, x);
                y.rShiftTo(g, y);
            }
            while (x.signum() > 0) {
                if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
                if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
                if (x.compareTo(y) >= 0) {
                    x.subTo(y, x);
                    x.rShiftTo(1, x);
                }
                else {
                    y.subTo(x, y);
                    y.rShiftTo(1, y);
                }
            }
            if (g > 0) y.lShiftTo(g, y);
            return y;
        }

// (protected) this % n, n < 2^26
        function bnpModInt(n) {
            if (n <= 0) return 0;
            var d = this.DV % n, r = (this.s < 0) ? n - 1 : 0;
            if (this.t > 0)
                if (d == 0) r = this[0] % n;
                else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
            return r;
        }

// (public) 1/this % m (HAC 14.61)
        function bnModInverse(m) {
            var ac = m.isEven();
            if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
            var u = m.clone(), v = this.clone();
            var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
            while (u.signum() != 0) {
                while (u.isEven()) {
                    u.rShiftTo(1, u);
                    if (ac) {
                        if (!a.isEven() || !b.isEven()) {
                            a.addTo(this, a);
                            b.subTo(m, b);
                        }
                        a.rShiftTo(1, a);
                    }
                    else if (!b.isEven()) b.subTo(m, b);
                    b.rShiftTo(1, b);
                }
                while (v.isEven()) {
                    v.rShiftTo(1, v);
                    if (ac) {
                        if (!c.isEven() || !d.isEven()) {
                            c.addTo(this, c);
                            d.subTo(m, d);
                        }
                        c.rShiftTo(1, c);
                    }
                    else if (!d.isEven()) d.subTo(m, d);
                    d.rShiftTo(1, d);
                }
                if (u.compareTo(v) >= 0) {
                    u.subTo(v, u);
                    if (ac) a.subTo(c, a);
                    b.subTo(d, b);
                }
                else {
                    v.subTo(u, v);
                    if (ac) c.subTo(a, c);
                    d.subTo(b, d);
                }
            }
            if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
            if (d.compareTo(m) >= 0) return d.subtract(m);
            if (d.signum() < 0) d.addTo(m, d); else return d;
            if (d.signum() < 0) return d.add(m); else return d;
        }

        var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
        var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

// (public) test primality with certainty >= 1-.5^t
        function bnIsProbablePrime(t) {
            var i, x = this.abs();
            if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
                for (i = 0; i < lowprimes.length; ++i)
                    if (x[0] == lowprimes[i]) return true;
                return false;
            }
            if (x.isEven()) return false;
            i = 1;
            while (i < lowprimes.length) {
                var m = lowprimes[i], j = i + 1;
                while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
                m = x.modInt(m);
                while (i < j) if (m % lowprimes[i++] == 0) return false;
            }
            return x.millerRabin(t);
        }

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
        function bnpMillerRabin(t) {
            var n1 = this.subtract(BigInteger.ONE);
            var k = n1.getLowestSetBit();
            if (k <= 0) return false;
            var r = n1.shiftRight(k);
            t = (t + 1) >> 1;
            if (t > lowprimes.length) t = lowprimes.length;
            var a = nbi();
            for (var i = 0; i < t; ++i) {
                //Pick bases at random, instead of starting at 2
                a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
                var y = a.modPow(r, this);
                if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
                    var j = 1;
                    while (j++ < k && y.compareTo(n1) != 0) {
                        y = y.modPowInt(2, this);
                        if (y.compareTo(BigInteger.ONE) == 0) return false;
                    }
                    if (y.compareTo(n1) != 0) return false;
                }
            }
            return true;
        }

// protected
        BigInteger.prototype.chunkSize = bnpChunkSize;
        BigInteger.prototype.toRadix = bnpToRadix;
        BigInteger.prototype.fromRadix = bnpFromRadix;
        BigInteger.prototype.fromNumber = bnpFromNumber;
        BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
        BigInteger.prototype.changeBit = bnpChangeBit;
        BigInteger.prototype.addTo = bnpAddTo;
        BigInteger.prototype.dMultiply = bnpDMultiply;
        BigInteger.prototype.dAddOffset = bnpDAddOffset;
        BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
        BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
        BigInteger.prototype.modInt = bnpModInt;
        BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
        BigInteger.prototype.clone = bnClone;
        BigInteger.prototype.intValue = bnIntValue;
        BigInteger.prototype.byteValue = bnByteValue;
        BigInteger.prototype.shortValue = bnShortValue;
        BigInteger.prototype.signum = bnSigNum;
        BigInteger.prototype.toByteArray = bnToByteArray;
        BigInteger.prototype.equals = bnEquals;
        BigInteger.prototype.min = bnMin;
        BigInteger.prototype.max = bnMax;
        BigInteger.prototype.and = bnAnd;
        BigInteger.prototype.or = bnOr;
        BigInteger.prototype.xor = bnXor;
        BigInteger.prototype.andNot = bnAndNot;
        BigInteger.prototype.not = bnNot;
        BigInteger.prototype.shiftLeft = bnShiftLeft;
        BigInteger.prototype.shiftRight = bnShiftRight;
        BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
        BigInteger.prototype.bitCount = bnBitCount;
        BigInteger.prototype.testBit = bnTestBit;
        BigInteger.prototype.setBit = bnSetBit;
        BigInteger.prototype.clearBit = bnClearBit;
        BigInteger.prototype.flipBit = bnFlipBit;
        BigInteger.prototype.add = bnAdd;
        BigInteger.prototype.subtract = bnSubtract;
        BigInteger.prototype.multiply = bnMultiply;
        BigInteger.prototype.divide = bnDivide;
        BigInteger.prototype.remainder = bnRemainder;
        BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
        BigInteger.prototype.modPow = bnModPow;
        BigInteger.prototype.modInverse = bnModInverse;
        BigInteger.prototype.pow = bnPow;
        BigInteger.prototype.gcd = bnGCD;
        BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
        BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
// prng4.js - uses Arcfour as a PRNG

        function Arcfour() {
            this.i = 0;
            this.j = 0;
            this.S = new Array();
        }

// Initialize arcfour context from key, an array of ints, each from [0..255]
        function ARC4init(key) {
            var i, j, t;
            for (i = 0; i < 256; ++i)
                this.S[i] = i;
            j = 0;
            for (i = 0; i < 256; ++i) {
                j = (j + this.S[i] + key[i % key.length]) & 255;
                t = this.S[i];
                this.S[i] = this.S[j];
                this.S[j] = t;
            }
            this.i = 0;
            this.j = 0;
        }

        function ARC4next() {
            var t;
            this.i = (this.i + 1) & 255;
            this.j = (this.j + this.S[this.i]) & 255;
            t = this.S[this.i];
            this.S[this.i] = this.S[this.j];
            this.S[this.j] = t;
            return this.S[(t + this.S[this.i]) & 255];
        }

        Arcfour.prototype.init = ARC4init;
        Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
        function prng_newstate() {
            return new Arcfour();
        }

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
        var rng_psize = 256;
// Random number generator - requires a PRNG backend, e.g. prng4.js
        var rng_state;
        var rng_pool;
        var rng_pptr;

// Initialize the pool with junk if needed.
        if (rng_pool == null) {
            rng_pool = new Array();
            rng_pptr = 0;
            var t;
            if (window.crypto && window.crypto.getRandomValues) {
                // Extract entropy (2048 bits) from RNG if available
                var z = new Uint32Array(256);
                window.crypto.getRandomValues(z);
                for (t = 0; t < z.length; ++t)
                    rng_pool[rng_pptr++] = z[t] & 255;
            }

            // Use mouse events for entropy, if we do not have enough entropy by the time
            // we need it, entropy will be generated by Math.random.
            var onMouseMoveListener = function (ev) {
                this.count = this.count || 0;
                if (this.count >= 256 || rng_pptr >= rng_psize) {
                    if (window.removeEventListener)
                        window.removeEventListener("mousemove", onMouseMoveListener);
                    else if (window.detachEvent)
                        window.detachEvent("onmousemove", onMouseMoveListener);
                    return;
                }
                this.count += 1;
                var mouseCoordinates = ev.x + ev.y;
                rng_pool[rng_pptr++] = mouseCoordinates & 255;
            };
            if (window.addEventListener)
                window.addEventListener("mousemove", onMouseMoveListener);
            else if (window.attachEvent)
                window.attachEvent("onmousemove", onMouseMoveListener);

        }

        function rng_get_byte() {
            if (rng_state == null) {
                rng_state = prng_newstate();
                // At this point, we may not have collected enough entropy.  If not, fall back to Math.random
                while (rng_pptr < rng_psize) {
                    var random = Math.floor(65536 * Math.random());
                    rng_pool[rng_pptr++] = random & 255;
                }
                rng_state.init(rng_pool);
                for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
                    rng_pool[rng_pptr] = 0;
                rng_pptr = 0;
            }
            // TODO: allow reseeding after first request
            return rng_state.next();
        }

        function rng_get_bytes(ba) {
            var i;
            for (i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
        }

        function SecureRandom() {
        }

        SecureRandom.prototype.nextBytes = rng_get_bytes;
// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
        function parseBigInt(str, r) {
            return new BigInteger(str, r);
        }

        function linebrk(s, n) {
            var ret = "";
            var i = 0;
            while (i + n < s.length) {
                ret += s.substring(i, i + n) + "\n";
                i += n;
            }
            return ret + s.substring(i, s.length);
        }

        function byte2Hex(b) {
            if (b < 0x10)
                return "0" + b.toString(16);
            else
                return b.toString(16);
        }

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
        function pkcs1pad2(s, n) {
            if (n < s.length + 11) { // TODO: fix for utf-8
                console.onError("Message too long for RSA");
                return null;
            }
            var ba = new Array();
            var i = s.length - 1;
            while (i >= 0 && n > 0) {
                var c = s.charCodeAt(i--);
                if (c < 128) { // encode using utf-8
                    ba[--n] = c;
                }
                else if ((c > 127) && (c < 2048)) {
                    ba[--n] = (c & 63) | 128;
                    ba[--n] = (c >> 6) | 192;
                }
                else {
                    ba[--n] = (c & 63) | 128;
                    ba[--n] = ((c >> 6) & 63) | 128;
                    ba[--n] = (c >> 12) | 224;
                }
            }
            ba[--n] = 0;
            var rng = new SecureRandom();
            var x = new Array();
            while (n > 2) { // random non-zero pad
                x[0] = 0;
                while (x[0] == 0) rng.nextBytes(x);
                ba[--n] = x[0];
            }
            ba[--n] = 2;
            ba[--n] = 0;
            return new BigInteger(ba);
        }

// "empty" RSA key constructor
        function RSAKey() {
            this.n = null;
            this.e = 0;
            this.d = null;
            this.p = null;
            this.q = null;
            this.dmp1 = null;
            this.dmq1 = null;
            this.coeff = null;
        }

// Set the public key fields N and e from hex strings
        function RSASetPublic(N, E) {
            if (N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N, 16);
                this.e = parseInt(E, 16);
            }
            else
                console.onError("Invalid RSA public key");
        }

// Perform raw public operation on "x": return x^e (mod n)
        function RSADoPublic(x) {
            return x.modPowInt(this.e, this.n);
        }

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
        function RSAEncrypt(text) {
            var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
            if (m == null) return null;
            var c = this.doPublic(m);
            if (c == null) return null;
            var h = c.toString(16);
            if ((h.length & 1) == 0) return h; else return "0" + h;
        }

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
        RSAKey.prototype.doPublic = RSADoPublic;

// public
        RSAKey.prototype.setPublic = RSASetPublic;
        RSAKey.prototype.encrypt = RSAEncrypt;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;
// Depends on rsa.js and jsbn2.js

// Version 1.1: support utf-8 decoding in pkcs1unpad2

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
        function pkcs1unpad2(d, n) {
            var b = d.toByteArray();
            var i = 0;
            while (i < b.length && b[i] == 0) ++i;
            if (b.length - i != n - 1 || b[i] != 2)
                return null;
            ++i;
            while (b[i] != 0)
                if (++i >= b.length) return null;
            var ret = "";
            while (++i < b.length) {
                var c = b[i] & 255;
                if (c < 128) { // utf-8 decode
                    ret += String.fromCharCode(c);
                }
                else if ((c > 191) && (c < 224)) {
                    ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
                    ++i;
                }
                else {
                    ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
                    i += 2;
                }
            }
            return ret;
        }

// Set the private key fields N, e, and d from hex strings
        function RSASetPrivate(N, E, D) {
            if (N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N, 16);
                this.e = parseInt(E, 16);
                this.d = parseBigInt(D, 16);
            }
            else
                console.onError("Invalid RSA private key");
        }

// Set the private key fields N, e, d and CRT params from hex strings
        function RSASetPrivateEx(N, E, D, P, Q, DP, DQ, C) {
            if (N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N, 16);
                this.e = parseInt(E, 16);
                this.d = parseBigInt(D, 16);
                this.p = parseBigInt(P, 16);
                this.q = parseBigInt(Q, 16);
                this.dmp1 = parseBigInt(DP, 16);
                this.dmq1 = parseBigInt(DQ, 16);
                this.coeff = parseBigInt(C, 16);
            }
            else
                console.onError("Invalid RSA private key");
        }

// Generate a new random private key B bits long, using public expt E
        function RSAGenerate(B, E) {
            var rng = new SecureRandom();
            var qs = B >> 1;
            this.e = parseInt(E, 16);
            var ee = new BigInteger(E, 16);
            for (; ;) {
                for (; ;) {
                    this.p = new BigInteger(B - qs, 1, rng);
                    if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
                }
                for (; ;) {
                    this.q = new BigInteger(qs, 1, rng);
                    if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
                }
                if (this.p.compareTo(this.q) <= 0) {
                    var t = this.p;
                    this.p = this.q;
                    this.q = t;
                }
                var p1 = this.p.subtract(BigInteger.ONE);
                var q1 = this.q.subtract(BigInteger.ONE);
                var phi = p1.multiply(q1);
                if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
                    this.n = this.p.multiply(this.q);
                    this.d = ee.modInverse(phi);
                    this.dmp1 = this.d.mod(p1);
                    this.dmq1 = this.d.mod(q1);
                    this.coeff = this.q.modInverse(this.p);
                    break;
                }
            }
        }

// Perform raw private operation on "x": return x^d (mod n)
        function RSADoPrivate(x) {
            if (this.p == null || this.q == null)
                return x.modPow(this.d, this.n);

            // TODO: re-calculate any missing CRT params
            var xp = x.mod(this.p).modPow(this.dmp1, this.p);
            var xq = x.mod(this.q).modPow(this.dmq1, this.q);

            while (xp.compareTo(xq) < 0)
                xp = xp.add(this.p);
            return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
        }

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
        function RSADecrypt(ctext) {
            var c = parseBigInt(ctext, 16);
            var m = this.doPrivate(c);
            if (m == null) return null;
            return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
        }

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is a Base64-encoded string and the output is a plain string.
//function RSAB64Decrypt(ctext) {
//  var h = b64tohex(ctext);
//  if(h) return this.decrypt(h); else return null;
//}

// protected
        RSAKey.prototype.doPrivate = RSADoPrivate;

// public
        RSAKey.prototype.setPrivate = RSASetPrivate;
        RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
        RSAKey.prototype.generate = RSAGenerate;
        RSAKey.prototype.decrypt = RSADecrypt;
//RSAKey.prototype.b64_decrypt = RSAB64Decrypt;
// Copyright (c) 2011  Kevin M Burns Jr.
// All Rights Reserved.
// See "LICENSE" for details.
//
// Extension to jsbn which adds facilities for asynchronous RSA key generation
// Primarily created to avoid execution timeout on mobile devices
//
// http://www-cs-students.stanford.edu/~tjw/jsbn/
//
// ---

        (function () {

// Generate a new random private key B bits long, using public expt E
            var RSAGenerateAsync = function (B, E, callback) {
                //var rng = new SeededRandom();
                var rng = new SecureRandom();
                var qs = B >> 1;
                this.e = parseInt(E, 16);
                var ee = new BigInteger(E, 16);
                var rsa = this;
                // These functions have non-descript names because they were originally for(;;) loops.
                // I don't know about cryptography to give them better names than loop1-4.
                var loop1 = function () {
                    var loop4 = function () {
                        if (rsa.p.compareTo(rsa.q) <= 0) {
                            var t = rsa.p;
                            rsa.p = rsa.q;
                            rsa.q = t;
                        }
                        var p1 = rsa.p.subtract(BigInteger.ONE);
                        var q1 = rsa.q.subtract(BigInteger.ONE);
                        var phi = p1.multiply(q1);
                        if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
                            rsa.n = rsa.p.multiply(rsa.q);
                            rsa.d = ee.modInverse(phi);
                            rsa.dmp1 = rsa.d.mod(p1);
                            rsa.dmq1 = rsa.d.mod(q1);
                            rsa.coeff = rsa.q.modInverse(rsa.p);
                            setTimeout(function () {
                                callback()
                            }, 0); // escape
                        } else {
                            setTimeout(loop1, 0);
                        }
                    };
                    var loop3 = function () {
                        rsa.q = nbi();
                        rsa.q.fromNumberAsync(qs, 1, rng, function () {
                            rsa.q.subtract(BigInteger.ONE).gcda(ee, function (r) {
                                if (r.compareTo(BigInteger.ONE) == 0 && rsa.q.isProbablePrime(10)) {
                                    setTimeout(loop4, 0);
                                } else {
                                    setTimeout(loop3, 0);
                                }
                            });
                        });
                    };
                    var loop2 = function () {
                        rsa.p = nbi();
                        rsa.p.fromNumberAsync(B - qs, 1, rng, function () {
                            rsa.p.subtract(BigInteger.ONE).gcda(ee, function (r) {
                                if (r.compareTo(BigInteger.ONE) == 0 && rsa.p.isProbablePrime(10)) {
                                    setTimeout(loop3, 0);
                                } else {
                                    setTimeout(loop2, 0);
                                }
                            });
                        });
                    };
                    setTimeout(loop2, 0);
                };
                setTimeout(loop1, 0);
            };
            RSAKey.prototype.generateAsync = RSAGenerateAsync;

// Public API method
            var bnGCDAsync = function (a, callback) {
                var x = (this.s < 0) ? this.negate() : this.clone();
                var y = (a.s < 0) ? a.negate() : a.clone();
                if (x.compareTo(y) < 0) {
                    var t = x;
                    x = y;
                    y = t;
                }
                var i = x.getLowestSetBit(),
                    g = y.getLowestSetBit();
                if (g < 0) {
                    callback(x);
                    return;
                }
                if (i < g) g = i;
                if (g > 0) {
                    x.rShiftTo(g, x);
                    y.rShiftTo(g, y);
                }
                // Workhorse of the algorithm, gets called 200 - 800 times per 512 bit keygen.
                var gcda1 = function () {
                    if ((i = x.getLowestSetBit()) > 0) {
                        x.rShiftTo(i, x);
                    }
                    if ((i = y.getLowestSetBit()) > 0) {
                        y.rShiftTo(i, y);
                    }
                    if (x.compareTo(y) >= 0) {
                        x.subTo(y, x);
                        x.rShiftTo(1, x);
                    } else {
                        y.subTo(x, y);
                        y.rShiftTo(1, y);
                    }
                    if (!(x.signum() > 0)) {
                        if (g > 0) y.lShiftTo(g, y);
                        setTimeout(function () {
                            callback(y)
                        }, 0); // escape
                    } else {
                        setTimeout(gcda1, 0);
                    }
                };
                setTimeout(gcda1, 10);
            };
            BigInteger.prototype.gcda = bnGCDAsync;

// (protected) alternate constructor
            var bnpFromNumberAsync = function (a, b, c, callback) {
                if ("number" == typeof b) {
                    if (a < 2) {
                        this.fromInt(1);
                    } else {
                        this.fromNumber(a, c);
                        if (!this.testBit(a - 1)) {
                            this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
                        }
                        if (this.isEven()) {
                            this.dAddOffset(1, 0);
                        }
                        var bnp = this;
                        var bnpfn1 = function () {
                            bnp.dAddOffset(2, 0);
                            if (bnp.bitLength() > a) bnp.subTo(BigInteger.ONE.shiftLeft(a - 1), bnp);
                            if (bnp.isProbablePrime(b)) {
                                setTimeout(function () {
                                    callback()
                                }, 0); // escape
                            } else {
                                setTimeout(bnpfn1, 0);
                            }
                        };
                        setTimeout(bnpfn1, 0);
                    }
                } else {
                    var x = new Array(), t = a & 7;
                    x.length = (a >> 3) + 1;
                    b.nextBytes(x);
                    if (t > 0) x[0] &= ((1 << t) - 1); else x[0] = 0;
                    this.fromString(x, 256);
                }
            };
            BigInteger.prototype.fromNumberAsync = bnpFromNumberAsync;

        })();
        var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var b64pad = "=";

        function hex2b64(h) {
            var i;
            var c;
            var ret = "";
            for (i = 0; i + 3 <= h.length; i += 3) {
                c = parseInt(h.substring(i, i + 3), 16);
                ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
            }
            if (i + 1 == h.length) {
                c = parseInt(h.substring(i, i + 1), 16);
                ret += b64map.charAt(c << 2);
            }
            else if (i + 2 == h.length) {
                c = parseInt(h.substring(i, i + 2), 16);
                ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
            }
            while ((ret.length & 3) > 0) ret += b64pad;
            return ret;
        }

// convert a base64 string to hex
        function b64tohex(s) {
            var ret = ""
            var i;
            var k = 0; // b64 state, 0-3
            var slop;
            for (i = 0; i < s.length; ++i) {
                if (s.charAt(i) == b64pad) break;
                v = b64map.indexOf(s.charAt(i));
                if (v < 0) continue;
                if (k == 0) {
                    ret += int2char(v >> 2);
                    slop = v & 3;
                    k = 1;
                }
                else if (k == 1) {
                    ret += int2char((slop << 2) | (v >> 4));
                    slop = v & 0xf;
                    k = 2;
                }
                else if (k == 2) {
                    ret += int2char(slop);
                    ret += int2char(v >> 2);
                    slop = v & 3;
                    k = 3;
                }
                else {
                    ret += int2char((slop << 2) | (v >> 4));
                    ret += int2char(v & 0xf);
                    k = 0;
                }
            }
            if (k == 1)
                ret += int2char(slop << 2);
            return ret;
        }

// convert a base64 string to a byte/number array
        function b64toBA(s) {
            //piggyback on b64tohex for now, optimize later
            var h = b64tohex(s);
            var i;
            var a = new Array();
            for (i = 0; 2 * i < h.length; ++i) {
                a[i] = parseInt(h.substring(2 * i, 2 * i + 2), 16);
            }
            return a;
        }

        /*! asn1-1.0.2.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
         */

        var JSX = JSX || {};
        JSX.env = JSX.env || {};

        var L = JSX, OP = Object.prototype, FUNCTION_TOSTRING = '[object Function]', ADD = ["toString", "valueOf"];

        JSX.env.parseUA = function (agent) {

            var numberify = function (s) {
                    var c = 0;
                    return parseFloat(s.replace(/\./g, function () {
                        return (c++ == 1) ? '' : '.';
                    }));
                },

                nav = navigator,
                o = {
                    ie: 0,
                    opera: 0,
                    gecko: 0,
                    webkit: 0,
                    chrome: 0,
                    mobile: null,
                    air: 0,
                    ipad: 0,
                    iphone: 0,
                    ipod: 0,
                    ios: null,
                    android: 0,
                    webos: 0,
                    caja: nav && nav.cajaVersion,
                    secure: false,
                    os: null

                },

                ua = agent || (navigator && navigator.userAgent),
                loc = window && window.location,
                href = loc && loc.href,
                m;

            o.secure = href && (href.toLowerCase().indexOf("https") === 0);

            if (ua) {

                if ((/windows|win32/i).test(ua)) {
                    o.os = 'windows';
                } else if ((/macintosh/i).test(ua)) {
                    o.os = 'macintosh';
                } else if ((/rhino/i).test(ua)) {
                    o.os = 'rhino';
                }
                if ((/KHTML/).test(ua)) {
                    o.webkit = 1;
                }
                m = ua.match(/AppleWebKit\/([^\s]*)/);
                if (m && m[1]) {
                    o.webkit = numberify(m[1]);
                    if (/ Mobile\//.test(ua)) {
                        o.mobile = 'Apple'; // iPhone or iPod Touch
                        m = ua.match(/OS ([^\s]*)/);
                        if (m && m[1]) {
                            m = numberify(m[1].replace('_', '.'));
                        }
                        o.ios = m;
                        o.ipad = o.ipod = o.iphone = 0;
                        m = ua.match(/iPad|iPod|iPhone/);
                        if (m && m[0]) {
                            o[m[0].toLowerCase()] = o.ios;
                        }
                    } else {
                        m = ua.match(/NokiaN[^\/]*|Android \d\.\d|webOS\/\d\.\d/);
                        if (m) {
                            o.mobile = m[0];
                        }
                        if (/webOS/.test(ua)) {
                            o.mobile = 'WebOS';
                            m = ua.match(/webOS\/([^\s]*);/);
                            if (m && m[1]) {
                                o.webos = numberify(m[1]);
                            }
                        }
                        if (/ Android/.test(ua)) {
                            o.mobile = 'Android';
                            m = ua.match(/Android ([^\s]*);/);
                            if (m && m[1]) {
                                o.android = numberify(m[1]);
                            }
                        }
                    }
                    m = ua.match(/Chrome\/([^\s]*)/);
                    if (m && m[1]) {
                        o.chrome = numberify(m[1]); // Chrome
                    } else {
                        m = ua.match(/AdobeAIR\/([^\s]*)/);
                        if (m) {
                            o.air = m[0]; // Adobe AIR 1.0 or better
                        }
                    }
                }
                if (!o.webkit) {
                    m = ua.match(/Opera[\s\/]([^\s]*)/);
                    if (m && m[1]) {
                        o.opera = numberify(m[1]);
                        m = ua.match(/Version\/([^\s]*)/);
                        if (m && m[1]) {
                            o.opera = numberify(m[1]); // opera 10+
                        }
                        m = ua.match(/Opera Mini[^;]*/);
                        if (m) {
                            o.mobile = m[0]; // ex: Opera Mini/2.0.4509/1316
                        }
                    } else { // not opera or webkit
                        m = ua.match(/MSIE\s([^;]*)/);
                        if (m && m[1]) {
                            o.ie = numberify(m[1]);
                        } else { // not opera, webkit, or ie
                            m = ua.match(/Gecko\/([^\s]*)/);
                            if (m) {
                                o.gecko = 1; // Gecko detected, look for revision
                                m = ua.match(/rv:([^\s\)]*)/);
                                if (m && m[1]) {
                                    o.gecko = numberify(m[1]);
                                }
                            }
                        }
                    }
                }
            }
            return o;
        };

        JSX.env.ua = JSX.env.parseUA();

        JSX.isFunction = function (o) {
            return (typeof o === 'function') || OP.toString.apply(o) === FUNCTION_TOSTRING;
        };

        JSX._IEEnumFix = (JSX.env.ua.ie) ? function (r, s) {
            var i, fname, f;
            for (i = 0; i < ADD.length; i = i + 1) {

                fname = ADD[i];
                f = s[fname];

                if (L.isFunction(f) && f != OP[fname]) {
                    r[fname] = f;
                }
            }
        } : function () {
        };

        JSX.extend = function (subc, superc, overrides) {
            if (!superc || !subc) {
                throw new Error("extend failed, please check that " +
                "all dependencies are included.");
            }
            var F = function () {
            }, i;
            F.prototype = superc.prototype;
            subc.prototype = new F();
            subc.prototype.constructor = subc;
            subc.superclass = superc.prototype;
            if (superc.prototype.constructor == OP.constructor) {
                superc.prototype.constructor = superc;
            }

            if (overrides) {
                for (i in overrides) {
                    if (L.hasOwnProperty(overrides, i)) {
                        subc.prototype[i] = overrides[i];
                    }
                }

                L._IEEnumFix(subc.prototype, overrides);
            }
        };

        /*
         * asn1.js - ASN.1 DER encoder classes
         *
         * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
         *
         * This software is licensed under the terms of the MIT License.
         * http://kjur.github.com/jsrsasign/license
         *
         * The above copyright and license notice shall be
         * included in all copies or substantial portions of the Software.
         */

        /**
         * @fileOverview
         * @name asn1-1.0.js
         * @author Kenji Urushima kenji.urushima@gmail.com
         * @version 1.0.2 (2013-May-30)
         * @since 2.1
         * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
         */

        /**
         * kjur's class library name space
         * <p>
         * This name space provides following name spaces:
         * <ul>
         * <li>{@link KJUR.asn1} - ASN.1 primitive hexadecimal encoder</li>
         * <li>{@link KJUR.asn1.x509} - ASN.1 structure for X.509 certificate and CRL</li>
         * <li>{@link KJUR.crypto} - Java Cryptographic Extension(JCE) style MessageDigest/Signature
         * class and utilities</li>
         * </ul>
         * </p>
         * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
         * @name KJUR
         * @namespace kjur's class library name space
         */
        if (typeof KJUR == "undefined" || !KJUR) KJUR = {};

        /**
         * kjur's ASN.1 class library name space
         * <p>
         * This is ITU-T X.690 ASN.1 DER encoder class library and
         * class structure and methods is very similar to
         * org.bouncycastle.asn1 package of
         * well known BouncyCaslte Cryptography Library.
         *
         * <h4>PROVIDING ASN.1 PRIMITIVES</h4>
         * Here are ASN.1 DER primitive classes.
         * <ul>
         * <li>{@link KJUR.asn1.DERBoolean}</li>
         * <li>{@link KJUR.asn1.DERInteger}</li>
         * <li>{@link KJUR.asn1.DERBitString}</li>
         * <li>{@link KJUR.asn1.DEROctetString}</li>
         * <li>{@link KJUR.asn1.DERNull}</li>
         * <li>{@link KJUR.asn1.DERObjectIdentifier}</li>
         * <li>{@link KJUR.asn1.DERUTF8String}</li>
         * <li>{@link KJUR.asn1.DERNumericString}</li>
         * <li>{@link KJUR.asn1.DERPrintableString}</li>
         * <li>{@link KJUR.asn1.DERTeletexString}</li>
         * <li>{@link KJUR.asn1.DERIA5String}</li>
         * <li>{@link KJUR.asn1.DERUTCTime}</li>
         * <li>{@link KJUR.asn1.DERGeneralizedTime}</li>
         * <li>{@link KJUR.asn1.DERSequence}</li>
         * <li>{@link KJUR.asn1.DERSet}</li>
         * </ul>
         *
         * <h4>OTHER ASN.1 CLASSES</h4>
         * <ul>
         * <li>{@link KJUR.asn1.ASN1Object}</li>
         * <li>{@link KJUR.asn1.DERAbstractString}</li>
         * <li>{@link KJUR.asn1.DERAbstractTime}</li>
         * <li>{@link KJUR.asn1.DERAbstractStructured}</li>
         * <li>{@link KJUR.asn1.DERTaggedObject}</li>
         * </ul>
         * </p>
         * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
         * @name KJUR.asn1
         * @namespace
         */
        if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) KJUR.asn1 = {};

        /**
         * ASN1 utilities class
         * @name KJUR.asn1.ASN1Util
         * @classs ASN1 utilities class
         * @since asn1 1.0.2
         */
        KJUR.asn1.ASN1Util = new function () {
            this.integerToByteHex = function (i) {
                var h = i.toString(16);
                if ((h.length % 2) == 1) h = '0' + h;
                return h;
            };
            this.bigIntToMinTwosComplementsHex = function (bigIntegerValue) {
                var h = bigIntegerValue.toString(16);
                if (h.substr(0, 1) != '-') {
                    if (h.length % 2 == 1) {
                        h = '0' + h;
                    } else {
                        if (!h.match(/^[0-7]/)) {
                            h = '00' + h;
                        }
                    }
                } else {
                    var hPos = h.substr(1);
                    var xorLen = hPos.length;
                    if (xorLen % 2 == 1) {
                        xorLen += 1;
                    } else {
                        if (!h.match(/^[0-7]/)) {
                            xorLen += 2;
                        }
                    }
                    var hMask = '';
                    for (var i = 0; i < xorLen; i++) {
                        hMask += 'f';
                    }
                    var biMask = new BigInteger(hMask, 16);
                    var biNeg = biMask.xor(bigIntegerValue).add(BigInteger.ONE);
                    h = biNeg.toString(16).replace(/^-/, '');
                }
                return h;
            };
            /**
             * get PEM string from hexadecimal data and header string
             * @name getPEMStringFromHex
             * @memberOf KJUR.asn1.ASN1Util
             * @function
             * @param {String} dataHex hexadecimal string of PEM body
             * @param {String} pemHeader PEM header string (ex. 'RSA PRIVATE KEY')
             * @return {String} PEM formatted string of input data
             * @description
             * @example
             * var pem  = KJUR.asn1.ASN1Util.getPEMStringFromHex('616161', 'RSA PRIVATE KEY');
             * // value of pem will be:
             * -----BEGIN PRIVATE KEY-----
             * YWFh
             * -----END PRIVATE KEY-----
             */
            this.getPEMStringFromHex = function (dataHex, pemHeader) {
                var dataWA = CryptoJS.enc.Hex.parse(dataHex);
                var dataB64 = CryptoJS.enc.Base64.stringify(dataWA);
                var pemBody = dataB64.replace(/(.{64})/g, "$1\r\n");
                pemBody = pemBody.replace(/\r\n$/, '');
                return "-----BEGIN " + pemHeader + "-----\r\n" +
                    pemBody +
                    "\r\n-----END " + pemHeader + "-----\r\n";
            };
        };

// ********************************************************************
//  Abstract ASN.1 Classes
// ********************************************************************

// ********************************************************************

        /**
         * base class for ASN.1 DER encoder object
         * @name KJUR.asn1.ASN1Object
         * @class base class for ASN.1 DER encoder object
         * @property {Boolean} isModified flag whether internal data was changed
         * @property {String} hTLV hexadecimal string of ASN.1 TLV
         * @property {String} hT hexadecimal string of ASN.1 TLV tag(T)
         * @property {String} hL hexadecimal string of ASN.1 TLV length(L)
         * @property {String} hV hexadecimal string of ASN.1 TLV value(V)
         * @description
         */
        KJUR.asn1.ASN1Object = function () {
            var isModified = true;
            var hTLV = null;
            var hT = '00'
            var hL = '00';
            var hV = '';

            /**
             * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
             * @name getLengthHexFromValue
             * @memberOf KJUR.asn1.ASN1Object
             * @function
             * @return {String} hexadecimal string of ASN.1 TLV length(L)
             */
            this.getLengthHexFromValue = function () {
                if (typeof this.hV == "undefined" || this.hV == null) {
                    throw "this.hV is null or undefined.";
                }
                if (this.hV.length % 2 == 1) {
                    throw "value hex must be even length: n=" + hV.length + ",v=" + this.hV;
                }
                var n = this.hV.length / 2;
                var hN = n.toString(16);
                if (hN.length % 2 == 1) {
                    hN = "0" + hN;
                }
                if (n < 128) {
                    return hN;
                } else {
                    var hNlen = hN.length / 2;
                    if (hNlen > 15) {
                        throw "ASN.1 length too long to represent by 8x: n = " + n.toString(16);
                    }
                    var head = 128 + hNlen;
                    return head.toString(16) + hN;
                }
            };

            /**
             * get hexadecimal string of ASN.1 TLV bytes
             * @name getEncodedHex
             * @memberOf KJUR.asn1.ASN1Object
             * @function
             * @return {String} hexadecimal string of ASN.1 TLV
             */
            this.getEncodedHex = function () {
                if (this.hTLV == null || this.isModified) {
                    this.hV = this.getFreshValueHex();
                    this.hL = this.getLengthHexFromValue();
                    this.hTLV = this.hT + this.hL + this.hV;
                    this.isModified = false;
                    //console.error("first time: " + this.hTLV);
                }
                return this.hTLV;
            };

            /**
             * get hexadecimal string of ASN.1 TLV value(V) bytes
             * @name getValueHex
             * @memberOf KJUR.asn1.ASN1Object
             * @function
             * @return {String} hexadecimal string of ASN.1 TLV value(V) bytes
             */
            this.getValueHex = function () {
                this.getEncodedHex();
                return this.hV;
            }

            this.getFreshValueHex = function () {
                return '';
            };
        };

// == BEGIN DERAbstractString ================================================
        /**
         * base class for ASN.1 DER string classes
         * @name KJUR.asn1.DERAbstractString
         * @class base class for ASN.1 DER string classes
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @property {String} s internal string of value
         * @extends KJUR.asn1.ASN1Object
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>str - specify initial ASN.1 value(V) by a string</li>
         * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERAbstractString = function (params) {
            KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
            var s = null;
            var hV = null;

            /**
             * get string value of this string object
             * @name getString
             * @memberOf KJUR.asn1.DERAbstractString
             * @function
             * @return {String} string value of this string object
             */
            this.getString = function () {
                return this.s;
            };

            /**
             * set value by a string
             * @name setString
             * @memberOf KJUR.asn1.DERAbstractString
             * @function
             * @param {String} newS value by a string to set
             */
            this.setString = function (newS) {
                this.hTLV = null;
                this.isModified = true;
                this.s = newS;
                this.hV = stohex(this.s);
            };

            /**
             * set value by a hexadecimal string
             * @name setStringHex
             * @memberOf KJUR.asn1.DERAbstractString
             * @function
             * @param {String} newHexString value by a hexadecimal string to set
             */
            this.setStringHex = function (newHexString) {
                this.hTLV = null;
                this.isModified = true;
                this.s = null;
                this.hV = newHexString;
            };

            this.getFreshValueHex = function () {
                return this.hV;
            };

            if (typeof params != "undefined") {
                if (typeof params['str'] != "undefined") {
                    this.setString(params['str']);
                } else if (typeof params['hex'] != "undefined") {
                    this.setStringHex(params['hex']);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERAbstractString, KJUR.asn1.ASN1Object);
// == END   DERAbstractString ================================================

// == BEGIN DERAbstractTime ==================================================
        /**
         * base class for ASN.1 DER Generalized/UTCTime class
         * @name KJUR.asn1.DERAbstractTime
         * @class base class for ASN.1 DER Generalized/UTCTime class
         * @param {Array} params associative array of parameters (ex. {'str': '130430235959Z'})
         * @extends KJUR.asn1.ASN1Object
         * @description
         * @see KJUR.asn1.ASN1Object - superclass
         */
        KJUR.asn1.DERAbstractTime = function (params) {
            KJUR.asn1.DERAbstractTime.superclass.constructor.call(this);
            var s = null;
            var date = null;

            // --- PRIVATE METHODS --------------------
            this.localDateToUTC = function (d) {
                utc = d.getTime() + (d.getTimezoneOffset() * 60000);
                var utcDate = new Date(utc);
                return utcDate;
            };

            this.formatDate = function (dateObject, type) {
                var pad = this.zeroPadding;
                var d = this.localDateToUTC(dateObject);
                var year = String(d.getFullYear());
                if (type == 'utc') year = year.substr(2, 2);
                var month = pad(String(d.getMonth() + 1), 2);
                var day = pad(String(d.getDate()), 2);
                var hour = pad(String(d.getHours()), 2);
                var min = pad(String(d.getMinutes()), 2);
                var sec = pad(String(d.getSeconds()), 2);
                return year + month + day + hour + min + sec + 'Z';
            };

            this.zeroPadding = function (s, len) {
                if (s.length >= len) return s;
                return new Array(len - s.length + 1).join('0') + s;
            };

            // --- PUBLIC METHODS --------------------
            /**
             * get string value of this string object
             * @name getString
             * @memberOf KJUR.asn1.DERAbstractTime
             * @function
             * @return {String} string value of this time object
             */
            this.getString = function () {
                return this.s;
            };

            /**
             * set value by a string
             * @name setString
             * @memberOf KJUR.asn1.DERAbstractTime
             * @function
             * @param {String} newS value by a string to set such like "130430235959Z"
             */
            this.setString = function (newS) {
                this.hTLV = null;
                this.isModified = true;
                this.s = newS;
                this.hV = stohex(this.s);
            };

            /**
             * set value by a Date object
             * @name setByDateValue
             * @memberOf KJUR.asn1.DERAbstractTime
             * @function
             * @param {Integer} year year of date (ex. 2013)
             * @param {Integer} month month of date between 1 and 12 (ex. 12)
             * @param {Integer} day day of month
             * @param {Integer} hour hours of date
             * @param {Integer} min minutes of date
             * @param {Integer} sec seconds of date
             */
            this.setByDateValue = function (year, month, day, hour, min, sec) {
                var dateObject = new Date(Date.UTC(year, month - 1, day, hour, min, sec, 0));
                this.setByDate(dateObject);
            };

            this.getFreshValueHex = function () {
                return this.hV;
            };
        };
        JSX.extend(KJUR.asn1.DERAbstractTime, KJUR.asn1.ASN1Object);
// == END   DERAbstractTime ==================================================

// == BEGIN DERAbstractStructured ============================================
        /**
         * base class for ASN.1 DER structured class
         * @name KJUR.asn1.DERAbstractStructured
         * @class base class for ASN.1 DER structured class
         * @property {Array} asn1Array internal array of ASN1Object
         * @extends KJUR.asn1.ASN1Object
         * @description
         * @see KJUR.asn1.ASN1Object - superclass
         */
        KJUR.asn1.DERAbstractStructured = function (params) {
            KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
            var asn1Array = null;

            /**
             * set value by array of ASN1Object
             * @name setByASN1ObjectArray
             * @memberOf KJUR.asn1.DERAbstractStructured
             * @function
             * @param {array} asn1ObjectArray array of ASN1Object to set
             */
            this.setByASN1ObjectArray = function (asn1ObjectArray) {
                this.hTLV = null;
                this.isModified = true;
                this.asn1Array = asn1ObjectArray;
            };

            /**
             * append an ASN1Object to internal array
             * @name appendASN1Object
             * @memberOf KJUR.asn1.DERAbstractStructured
             * @function
             * @param {ASN1Object} asn1Object to add
             */
            this.appendASN1Object = function (asn1Object) {
                this.hTLV = null;
                this.isModified = true;
                this.asn1Array.push(asn1Object);
            };

            this.asn1Array = new Array();
            if (typeof params != "undefined") {
                if (typeof params['array'] != "undefined") {
                    this.asn1Array = params['array'];
                }
            }
        };
        JSX.extend(KJUR.asn1.DERAbstractStructured, KJUR.asn1.ASN1Object);


// ********************************************************************
//  ASN.1 Object Classes
// ********************************************************************

// ********************************************************************
        /**
         * class for ASN.1 DER Boolean
         * @name KJUR.asn1.DERBoolean
         * @class class for ASN.1 DER Boolean
         * @extends KJUR.asn1.ASN1Object
         * @description
         * @see KJUR.asn1.ASN1Object - superclass
         */
        KJUR.asn1.DERBoolean = function () {
            KJUR.asn1.DERBoolean.superclass.constructor.call(this);
            this.hT = "01";
            this.hTLV = "0101ff";
        };
        JSX.extend(KJUR.asn1.DERBoolean, KJUR.asn1.ASN1Object);

// ********************************************************************
        /**
         * class for ASN.1 DER Integer
         * @name KJUR.asn1.DERInteger
         * @class class for ASN.1 DER Integer
         * @extends KJUR.asn1.ASN1Object
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>int - specify initial ASN.1 value(V) by integer value</li>
         * <li>bigint - specify initial ASN.1 value(V) by BigInteger object</li>
         * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERInteger = function (params) {
            KJUR.asn1.DERInteger.superclass.constructor.call(this);
            this.hT = "02";

            /**
             * set value by Tom Wu's BigInteger object
             * @name setByBigInteger
             * @memberOf KJUR.asn1.DERInteger
             * @function
             * @param {BigInteger} bigIntegerValue to set
             */
            this.setByBigInteger = function (bigIntegerValue) {
                this.hTLV = null;
                this.isModified = true;
                this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(bigIntegerValue);
            };

            /**
             * set value by integer value
             * @name setByInteger
             * @memberOf KJUR.asn1.DERInteger
             * @function
             * @param {Integer} integer value to set
             */
            this.setByInteger = function (intValue) {
                var bi = new BigInteger(String(intValue), 10);
                this.setByBigInteger(bi);
            };

            /**
             * set value by integer value
             * @name setValueHex
             * @memberOf KJUR.asn1.DERInteger
             * @function
             * @param {String} hexadecimal string of integer value
             * @description
             * <br/>
             * NOTE: Value shall be represented by minimum octet length of
             * two's complement representation.
             */
            this.setValueHex = function (newHexString) {
                this.hV = newHexString;
            };

            this.getFreshValueHex = function () {
                return this.hV;
            };

            if (typeof params != "undefined") {
                if (typeof params['bigint'] != "undefined") {
                    this.setByBigInteger(params['bigint']);
                } else if (typeof params['int'] != "undefined") {
                    this.setByInteger(params['int']);
                } else if (typeof params['hex'] != "undefined") {
                    this.setValueHex(params['hex']);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERInteger, KJUR.asn1.ASN1Object);

// ********************************************************************
        /**
         * class for ASN.1 DER encoded BitString primitive
         * @name KJUR.asn1.DERBitString
         * @class class for ASN.1 DER encoded BitString primitive
         * @extends KJUR.asn1.ASN1Object
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>bin - specify binary string (ex. '10111')</li>
         * <li>array - specify array of boolean (ex. [true,false,true,true])</li>
         * <li>hex - specify hexadecimal string of ASN.1 value(V) including unused bits</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERBitString = function (params) {
            KJUR.asn1.DERBitString.superclass.constructor.call(this);
            this.hT = "03";

            /**
             * set ASN.1 value(V) by a hexadecimal string including unused bits
             * @name setHexValueIncludingUnusedBits
             * @memberOf KJUR.asn1.DERBitString
             * @function
             * @param {String} newHexStringIncludingUnusedBits
             */
            this.setHexValueIncludingUnusedBits = function (newHexStringIncludingUnusedBits) {
                this.hTLV = null;
                this.isModified = true;
                this.hV = newHexStringIncludingUnusedBits;
            };

            /**
             * set ASN.1 value(V) by unused bit and hexadecimal string of value
             * @name setUnusedBitsAndHexValue
             * @memberOf KJUR.asn1.DERBitString
             * @function
             * @param {Integer} unusedBits
             * @param {String} hValue
             */
            this.setUnusedBitsAndHexValue = function (unusedBits, hValue) {
                if (unusedBits < 0 || 7 < unusedBits) {
                    throw "unused bits shall be from 0 to 7: u = " + unusedBits;
                }
                var hUnusedBits = "0" + unusedBits;
                this.hTLV = null;
                this.isModified = true;
                this.hV = hUnusedBits + hValue;
            };

            /**
             * set ASN.1 DER BitString by binary string
             * @name setByBinaryString
             * @memberOf KJUR.asn1.DERBitString
             * @function
             * @param {String} binaryString binary value string (i.e. '10111')
             * @description
             * Its unused bits will be calculated automatically by length of
             * 'binaryValue'. <br/>
             * NOTE: Trailing zeros '0' will be ignored.
             */
            this.setByBinaryString = function (binaryString) {
                binaryString = binaryString.replace(/0+$/, '');
                var unusedBits = 8 - binaryString.length % 8;
                if (unusedBits == 8) unusedBits = 0;
                for (var i = 0; i <= unusedBits; i++) {
                    binaryString += '0';
                }
                var h = '';
                for (var i = 0; i < binaryString.length - 1; i += 8) {
                    var b = binaryString.substr(i, 8);
                    var x = parseInt(b, 2).toString(16);
                    if (x.length == 1) x = '0' + x;
                    h += x;
                }
                this.hTLV = null;
                this.isModified = true;
                this.hV = '0' + unusedBits + h;
            };

            /**
             * set ASN.1 TLV value(V) by an array of boolean
             * @name setByBooleanArray
             * @memberOf KJUR.asn1.DERBitString
             * @function
             * @param {array} booleanArray array of boolean (ex. [true, false, true])
             * @description
             * NOTE: Trailing falses will be ignored.
             */
            this.setByBooleanArray = function (booleanArray) {
                var s = '';
                for (var i = 0; i < booleanArray.length; i++) {
                    if (booleanArray[i] == true) {
                        s += '1';
                    } else {
                        s += '0';
                    }
                }
                this.setByBinaryString(s);
            };

            /**
             * generate an array of false with specified length
             * @name newFalseArray
             * @memberOf KJUR.asn1.DERBitString
             * @function
             * @param {Integer} nLength length of array to generate
             * @return {array} array of boolean faluse
             * @description
             * This static method may be useful to initialize boolean array.
             */
            this.newFalseArray = function (nLength) {
                var a = new Array(nLength);
                for (var i = 0; i < nLength; i++) {
                    a[i] = false;
                }
                return a;
            };

            this.getFreshValueHex = function () {
                return this.hV;
            };

            if (typeof params != "undefined") {
                if (typeof params['hex'] != "undefined") {
                    this.setHexValueIncludingUnusedBits(params['hex']);
                } else if (typeof params['bin'] != "undefined") {
                    this.setByBinaryString(params['bin']);
                } else if (typeof params['array'] != "undefined") {
                    this.setByBooleanArray(params['array']);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERBitString, KJUR.asn1.ASN1Object);

// ********************************************************************
        /**
         * class for ASN.1 DER OctetString
         * @name KJUR.asn1.DEROctetString
         * @class class for ASN.1 DER OctetString
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @extends KJUR.asn1.DERAbstractString
         * @description
         * @see KJUR.asn1.DERAbstractString - superclass
         */
        KJUR.asn1.DEROctetString = function (params) {
            KJUR.asn1.DEROctetString.superclass.constructor.call(this, params);
            this.hT = "04";
        };
        JSX.extend(KJUR.asn1.DEROctetString, KJUR.asn1.DERAbstractString);

// ********************************************************************
        /**
         * class for ASN.1 DER Null
         * @name KJUR.asn1.DERNull
         * @class class for ASN.1 DER Null
         * @extends KJUR.asn1.ASN1Object
         * @description
         * @see KJUR.asn1.ASN1Object - superclass
         */
        KJUR.asn1.DERNull = function () {
            KJUR.asn1.DERNull.superclass.constructor.call(this);
            this.hT = "05";
            this.hTLV = "0500";
        };
        JSX.extend(KJUR.asn1.DERNull, KJUR.asn1.ASN1Object);

// ********************************************************************
        /**
         * class for ASN.1 DER ObjectIdentifier
         * @name KJUR.asn1.DERObjectIdentifier
         * @class class for ASN.1 DER ObjectIdentifier
         * @param {Array} params associative array of parameters (ex. {'oid': '2.5.4.5'})
         * @extends KJUR.asn1.ASN1Object
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>oid - specify initial ASN.1 value(V) by a oid string (ex. 2.5.4.13)</li>
         * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERObjectIdentifier = function (params) {
            var itox = function (i) {
                var h = i.toString(16);
                if (h.length == 1) h = '0' + h;
                return h;
            };
            var roidtox = function (roid) {
                var h = '';
                var bi = new BigInteger(roid, 10);
                var b = bi.toString(2);
                var padLen = 7 - b.length % 7;
                if (padLen == 7) padLen = 0;
                var bPad = '';
                for (var i = 0; i < padLen; i++) bPad += '0';
                b = bPad + b;
                for (var i = 0; i < b.length - 1; i += 7) {
                    var b8 = b.substr(i, 7);
                    if (i != b.length - 7) b8 = '1' + b8;
                    h += itox(parseInt(b8, 2));
                }
                return h;
            }

            KJUR.asn1.DERObjectIdentifier.superclass.constructor.call(this);
            this.hT = "06";

            /**
             * set value by a hexadecimal string
             * @name setValueHex
             * @memberOf KJUR.asn1.DERObjectIdentifier
             * @function
             * @param {String} newHexString hexadecimal value of OID bytes
             */
            this.setValueHex = function (newHexString) {
                this.hTLV = null;
                this.isModified = true;
                this.s = null;
                this.hV = newHexString;
            };

            /**
             * set value by a OID string
             * @name setValueOidString
             * @memberOf KJUR.asn1.DERObjectIdentifier
             * @function
             * @param {String} oidString OID string (ex. 2.5.4.13)
             */
            this.setValueOidString = function (oidString) {
                if (!oidString.match(/^[0-9.]+$/)) {
                    throw "malformed oid string: " + oidString;
                }
                var h = '';
                var a = oidString.split('.');
                var i0 = parseInt(a[0]) * 40 + parseInt(a[1]);
                h += itox(i0);
                a.splice(0, 2);
                for (var i = 0; i < a.length; i++) {
                    h += roidtox(a[i]);
                }
                this.hTLV = null;
                this.isModified = true;
                this.s = null;
                this.hV = h;
            };

            /**
             * set value by a OID name
             * @name setValueName
             * @memberOf KJUR.asn1.DERObjectIdentifier
             * @function
             * @param {String} oidName OID name (ex. 'serverAuth')
             * @since 1.0.1
             * @description
             * OID name shall be defined in 'KJUR.asn1.x509.OID.name2oidList'.
             * Otherwise raise error.
             */
            this.setValueName = function (oidName) {
                if (typeof KJUR.asn1.x509.OID.name2oidList[oidName] != "undefined") {
                    var oid = KJUR.asn1.x509.OID.name2oidList[oidName];
                    this.setValueOidString(oid);
                } else {
                    throw "DERObjectIdentifier oidName undefined: " + oidName;
                }
            };

            this.getFreshValueHex = function () {
                return this.hV;
            };

            if (typeof params != "undefined") {
                if (typeof params['oid'] != "undefined") {
                    this.setValueOidString(params['oid']);
                } else if (typeof params['hex'] != "undefined") {
                    this.setValueHex(params['hex']);
                } else if (typeof params['name'] != "undefined") {
                    this.setValueName(params['name']);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERObjectIdentifier, KJUR.asn1.ASN1Object);

// ********************************************************************
        /**
         * class for ASN.1 DER UTF8String
         * @name KJUR.asn1.DERUTF8String
         * @class class for ASN.1 DER UTF8String
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @extends KJUR.asn1.DERAbstractString
         * @description
         * @see KJUR.asn1.DERAbstractString - superclass
         */
        KJUR.asn1.DERUTF8String = function (params) {
            KJUR.asn1.DERUTF8String.superclass.constructor.call(this, params);
            this.hT = "0c";
        };
        JSX.extend(KJUR.asn1.DERUTF8String, KJUR.asn1.DERAbstractString);

// ********************************************************************
        /**
         * class for ASN.1 DER NumericString
         * @name KJUR.asn1.DERNumericString
         * @class class for ASN.1 DER NumericString
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @extends KJUR.asn1.DERAbstractString
         * @description
         * @see KJUR.asn1.DERAbstractString - superclass
         */
        KJUR.asn1.DERNumericString = function (params) {
            KJUR.asn1.DERNumericString.superclass.constructor.call(this, params);
            this.hT = "12";
        };
        JSX.extend(KJUR.asn1.DERNumericString, KJUR.asn1.DERAbstractString);

// ********************************************************************
        /**
         * class for ASN.1 DER PrintableString
         * @name KJUR.asn1.DERPrintableString
         * @class class for ASN.1 DER PrintableString
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @extends KJUR.asn1.DERAbstractString
         * @description
         * @see KJUR.asn1.DERAbstractString - superclass
         */
        KJUR.asn1.DERPrintableString = function (params) {
            KJUR.asn1.DERPrintableString.superclass.constructor.call(this, params);
            this.hT = "13";
        };
        JSX.extend(KJUR.asn1.DERPrintableString, KJUR.asn1.DERAbstractString);

// ********************************************************************
        /**
         * class for ASN.1 DER TeletexString
         * @name KJUR.asn1.DERTeletexString
         * @class class for ASN.1 DER TeletexString
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @extends KJUR.asn1.DERAbstractString
         * @description
         * @see KJUR.asn1.DERAbstractString - superclass
         */
        KJUR.asn1.DERTeletexString = function (params) {
            KJUR.asn1.DERTeletexString.superclass.constructor.call(this, params);
            this.hT = "14";
        };
        JSX.extend(KJUR.asn1.DERTeletexString, KJUR.asn1.DERAbstractString);

// ********************************************************************
        /**
         * class for ASN.1 DER IA5String
         * @name KJUR.asn1.DERIA5String
         * @class class for ASN.1 DER IA5String
         * @param {Array} params associative array of parameters (ex. {'str': 'aaa'})
         * @extends KJUR.asn1.DERAbstractString
         * @description
         * @see KJUR.asn1.DERAbstractString - superclass
         */
        KJUR.asn1.DERIA5String = function (params) {
            KJUR.asn1.DERIA5String.superclass.constructor.call(this, params);
            this.hT = "16";
        };
        JSX.extend(KJUR.asn1.DERIA5String, KJUR.asn1.DERAbstractString);

// ********************************************************************
        /**
         * class for ASN.1 DER UTCTime
         * @name KJUR.asn1.DERUTCTime
         * @class class for ASN.1 DER UTCTime
         * @param {Array} params associative array of parameters (ex. {'str': '130430235959Z'})
         * @extends KJUR.asn1.DERAbstractTime
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>str - specify initial ASN.1 value(V) by a string (ex.'130430235959Z')</li>
         * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
         * <li>date - specify Date object.</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         * <h4>EXAMPLES</h4>
         * @example
         * var d1 = new KJUR.asn1.DERUTCTime();
         * d1.setString('130430125959Z');
         *
         * var d2 = new KJUR.asn1.DERUTCTime({'str': '130430125959Z'});
         *
         * var d3 = new KJUR.asn1.DERUTCTime({'date': new Date(Date.UTC(2015, 0, 31, 0, 0, 0, 0))});
         */
        KJUR.asn1.DERUTCTime = function (params) {
            KJUR.asn1.DERUTCTime.superclass.constructor.call(this, params);
            this.hT = "17";

            /**
             * set value by a Date object
             * @name setByDate
             * @memberOf KJUR.asn1.DERUTCTime
             * @function
             * @param {Date} dateObject Date object to set ASN.1 value(V)
             */
            this.setByDate = function (dateObject) {
                this.hTLV = null;
                this.isModified = true;
                this.date = dateObject;
                this.s = this.formatDate(this.date, 'utc');
                this.hV = stohex(this.s);
            };

            if (typeof params != "undefined") {
                if (typeof params['str'] != "undefined") {
                    this.setString(params['str']);
                } else if (typeof params['hex'] != "undefined") {
                    this.setStringHex(params['hex']);
                } else if (typeof params['date'] != "undefined") {
                    this.setByDate(params['date']);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERUTCTime, KJUR.asn1.DERAbstractTime);

// ********************************************************************
        /**
         * class for ASN.1 DER GeneralizedTime
         * @name KJUR.asn1.DERGeneralizedTime
         * @class class for ASN.1 DER GeneralizedTime
         * @param {Array} params associative array of parameters (ex. {'str': '20130430235959Z'})
         * @extends KJUR.asn1.DERAbstractTime
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>str - specify initial ASN.1 value(V) by a string (ex.'20130430235959Z')</li>
         * <li>hex - specify initial ASN.1 value(V) by a hexadecimal string</li>
         * <li>date - specify Date object.</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERGeneralizedTime = function (params) {
            KJUR.asn1.DERGeneralizedTime.superclass.constructor.call(this, params);
            this.hT = "18";

            /**
             * set value by a Date object
             * @name setByDate
             * @memberOf KJUR.asn1.DERGeneralizedTime
             * @function
             * @param {Date} dateObject Date object to set ASN.1 value(V)
             * @example
             * When you specify UTC time, use 'Date.UTC' method like this:<br/>
             * var o = new DERUTCTime();
             * var date = new Date(Date.UTC(2015, 0, 31, 23, 59, 59, 0)); #2015JAN31 23:59:59
             * o.setByDate(date);
             */
            this.setByDate = function (dateObject) {
                this.hTLV = null;
                this.isModified = true;
                this.date = dateObject;
                this.s = this.formatDate(this.date, 'gen');
                this.hV = stohex(this.s);
            };

            if (typeof params != "undefined") {
                if (typeof params['str'] != "undefined") {
                    this.setString(params['str']);
                } else if (typeof params['hex'] != "undefined") {
                    this.setStringHex(params['hex']);
                } else if (typeof params['date'] != "undefined") {
                    this.setByDate(params['date']);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERGeneralizedTime, KJUR.asn1.DERAbstractTime);

// ********************************************************************
        /**
         * class for ASN.1 DER Sequence
         * @name KJUR.asn1.DERSequence
         * @class class for ASN.1 DER Sequence
         * @extends KJUR.asn1.DERAbstractStructured
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>array - specify array of ASN1Object to set elements of content</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERSequence = function (params) {
            KJUR.asn1.DERSequence.superclass.constructor.call(this, params);
            this.hT = "30";
            this.getFreshValueHex = function () {
                var h = '';
                for (var i = 0; i < this.asn1Array.length; i++) {
                    var asn1Obj = this.asn1Array[i];
                    h += asn1Obj.getEncodedHex();
                }
                this.hV = h;
                return this.hV;
            };
        };
        JSX.extend(KJUR.asn1.DERSequence, KJUR.asn1.DERAbstractStructured);

// ********************************************************************
        /**
         * class for ASN.1 DER Set
         * @name KJUR.asn1.DERSet
         * @class class for ASN.1 DER Set
         * @extends KJUR.asn1.DERAbstractStructured
         * @description
         * <br/>
         * As for argument 'params' for constructor, you can specify one of
         * following properties:
         * <ul>
         * <li>array - specify array of ASN1Object to set elements of content</li>
         * </ul>
         * NOTE: 'params' can be omitted.
         */
        KJUR.asn1.DERSet = function (params) {
            KJUR.asn1.DERSet.superclass.constructor.call(this, params);
            this.hT = "31";
            this.getFreshValueHex = function () {
                var a = new Array();
                for (var i = 0; i < this.asn1Array.length; i++) {
                    var asn1Obj = this.asn1Array[i];
                    a.push(asn1Obj.getEncodedHex());
                }
                a.sort();
                this.hV = a.join('');
                return this.hV;
            };
        };
        JSX.extend(KJUR.asn1.DERSet, KJUR.asn1.DERAbstractStructured);

// ********************************************************************
        /**
         * class for ASN.1 DER TaggedObject
         * @name KJUR.asn1.DERTaggedObject
         * @class class for ASN.1 DER TaggedObject
         * @extends KJUR.asn1.ASN1Object
         * @description
         * <br/>
         * Parameter 'tagNoNex' is ASN.1 tag(T) value for this object.
         * For example, if you find '[1]' tag in a ASN.1 dump,
         * 'tagNoHex' will be 'a1'.
         * <br/>
         * As for optional argument 'params' for constructor, you can specify *ANY* of
         * following properties:
         * <ul>
         * <li>explicit - specify true if this is explicit tag otherwise false
         *     (default is 'true').</li>
         * <li>tag - specify tag (default is 'a0' which means [0])</li>
         * <li>obj - specify ASN1Object which is tagged</li>
         * </ul>
         * @example
         * d1 = new KJUR.asn1.DERUTF8String({'str':'a'});
         * d2 = new KJUR.asn1.DERTaggedObject({'obj': d1});
         * hex = d2.getEncodedHex();
         */
        KJUR.asn1.DERTaggedObject = function (params) {
            KJUR.asn1.DERTaggedObject.superclass.constructor.call(this);
            this.hT = "a0";
            this.hV = '';
            this.isExplicit = true;
            this.asn1Object = null;

            /**
             * set value by an ASN1Object
             * @name setString
             * @memberOf KJUR.asn1.DERTaggedObject
             * @function
             * @param {Boolean} isExplicitFlag flag for explicit/implicit tag
             * @param {Integer} tagNoHex hexadecimal string of ASN.1 tag
             * @param {ASN1Object} asn1Object ASN.1 to encapsulate
             */
            this.setASN1Object = function (isExplicitFlag, tagNoHex, asn1Object) {
                this.hT = tagNoHex;
                this.isExplicit = isExplicitFlag;
                this.asn1Object = asn1Object;
                if (this.isExplicit) {
                    this.hV = this.asn1Object.getEncodedHex();
                    this.hTLV = null;
                    this.isModified = true;
                } else {
                    this.hV = null;
                    this.hTLV = asn1Object.getEncodedHex();
                    this.hTLV = this.hTLV.replace(/^../, tagNoHex);
                    this.isModified = false;
                }
            };

            this.getFreshValueHex = function () {
                return this.hV;
            };

            if (typeof params != "undefined") {
                if (typeof params['tag'] != "undefined") {
                    this.hT = params['tag'];
                }
                if (typeof params['explicit'] != "undefined") {
                    this.isExplicit = params['explicit'];
                }
                if (typeof params['obj'] != "undefined") {
                    this.asn1Object = params['obj'];
                    this.setASN1Object(this.isExplicit, this.hT, this.asn1Object);
                }
            }
        };
        JSX.extend(KJUR.asn1.DERTaggedObject, KJUR.asn1.ASN1Object);// Hex JavaScript decoder
// Copyright (c) 2008-2013 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

        /*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
        (function (undefined) {
            "use strict";

            var Hex = {},
                decoder;

            Hex.decode = function (a) {
                var i;
                if (decoder === undefined) {
                    var hex = "0123456789ABCDEF",
                        ignore = " \f\n\r\t\u00A0\u2028\u2029";
                    decoder = [];
                    for (i = 0; i < 16; ++i)
                        decoder[hex.charAt(i)] = i;
                    hex = hex.toLowerCase();
                    for (i = 10; i < 16; ++i)
                        decoder[hex.charAt(i)] = i;
                    for (i = 0; i < ignore.length; ++i)
                        decoder[ignore.charAt(i)] = -1;
                }
                var out = [],
                    bits = 0,
                    char_count = 0;
                for (i = 0; i < a.length; ++i) {
                    var c = a.charAt(i);
                    if (c == '=')
                        break;
                    c = decoder[c];
                    if (c == -1)
                        continue;
                    if (c === undefined)
                        throw 'Illegal character at offset ' + i;
                    bits |= c;
                    if (++char_count >= 2) {
                        out[out.length] = bits;
                        bits = 0;
                        char_count = 0;
                    } else {
                        bits <<= 4;
                    }
                }
                if (char_count)
                    throw "Hex encoding incomplete: 4 bits missing";
                return out;
            };

// export globals
            window.Hex = Hex;
        })();// Base64 JavaScript decoder
// Copyright (c) 2008-2013 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

        /*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
        (function (undefined) {
            "use strict";

            var Base64 = {},
                decoder;

            Base64.decode = function (a) {
                var i;
                if (decoder === undefined) {
                    var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                        ignore = "= \f\n\r\t\u00A0\u2028\u2029";
                    decoder = [];
                    for (i = 0; i < 64; ++i)
                        decoder[b64.charAt(i)] = i;
                    for (i = 0; i < ignore.length; ++i)
                        decoder[ignore.charAt(i)] = -1;
                }
                var out = [];
                var bits = 0, char_count = 0;
                for (i = 0; i < a.length; ++i) {
                    var c = a.charAt(i);
                    if (c == '=')
                        break;
                    c = decoder[c];
                    if (c == -1)
                        continue;
                    if (c === undefined)
                        throw 'Illegal character at offset ' + i;
                    bits |= c;
                    if (++char_count >= 4) {
                        out[out.length] = (bits >> 16);
                        out[out.length] = (bits >> 8) & 0xFF;
                        out[out.length] = bits & 0xFF;
                        bits = 0;
                        char_count = 0;
                    } else {
                        bits <<= 6;
                    }
                }
                switch (char_count) {
                    case 1:
                        throw "Base64 encoding incomplete: at least 2 bits missing";
                    case 2:
                        out[out.length] = (bits >> 10);
                        break;
                    case 3:
                        out[out.length] = (bits >> 16);
                        out[out.length] = (bits >> 8) & 0xFF;
                        break;
                }
                return out;
            };

            Base64.re = /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
            Base64.unarmor = function (a) {
                var m = Base64.re.exec(a);
                if (m) {
                    if (m[1])
                        a = m[1];
                    else if (m[2])
                        a = m[2];
                    else
                        throw "RegExp out of sync";
                }
                return Base64.decode(a);
            };

// export globals
            window.Base64 = Base64;
        })();// ASN.1 JavaScript decoder
// Copyright (c) 2008-2013 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

        /*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
        /*global oids */
        (function (undefined) {
            "use strict";

            var hardLimit = 100,
                ellipsis = "\u2026",
                DOM = {
                    tag: function (tagName, className) {
                        var t = document.createElement(tagName);
                        t.className = className;
                        return t;
                    },
                    text: function (str) {
                        return document.createTextNode(str);
                    }
                };

            function Stream(enc, pos) {
                if (enc instanceof Stream) {
                    this.enc = enc.enc;
                    this.pos = enc.pos;
                } else {
                    this.enc = enc;
                    this.pos = pos;
                }
            }

            Stream.prototype.get = function (pos) {
                if (pos === undefined)
                    pos = this.pos++;
                if (pos >= this.enc.length)
                    throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;
                return this.enc[pos];
            };
            Stream.prototype.hexDigits = "0123456789ABCDEF";
            Stream.prototype.hexByte = function (b) {
                return this.hexDigits.charAt((b >> 4) & 0xF) + this.hexDigits.charAt(b & 0xF);
            };
            Stream.prototype.hexDump = function (start, end, raw) {
                var s = "";
                for (var i = start; i < end; ++i) {
                    s += this.hexByte(this.get(i));
                    if (raw !== true)
                        switch (i & 0xF) {
                            case 0x7:
                                s += "  ";
                                break;
                            case 0xF:
                                s += "\n";
                                break;
                            default:
                                s += " ";
                        }
                }
                return s;
            };
            Stream.prototype.parseStringISO = function (start, end) {
                var s = "";
                for (var i = start; i < end; ++i)
                    s += String.fromCharCode(this.get(i));
                return s;
            };
            Stream.prototype.parseStringUTF = function (start, end) {
                var s = "";
                for (var i = start; i < end;) {
                    var c = this.get(i++);
                    if (c < 128)
                        s += String.fromCharCode(c);
                    else if ((c > 191) && (c < 224))
                        s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
                    else
                        s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
                }
                return s;
            };
            Stream.prototype.parseStringBMP = function (start, end) {
                var str = ""
                for (var i = start; i < end; i += 2) {
                    var high_byte = this.get(i);
                    var low_byte = this.get(i + 1);
                    str += String.fromCharCode((high_byte << 8) + low_byte);
                }

                return str;
            };
            Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
            Stream.prototype.parseTime = function (start, end) {
                var s = this.parseStringISO(start, end),
                    m = this.reTime.exec(s);
                if (!m)
                    return "Unrecognized time: " + s;
                s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
                if (m[5]) {
                    s += ":" + m[5];
                    if (m[6]) {
                        s += ":" + m[6];
                        if (m[7])
                            s += "." + m[7];
                    }
                }
                if (m[8]) {
                    s += " UTC";
                    if (m[8] != 'Z') {
                        s += m[8];
                        if (m[9])
                            s += ":" + m[9];
                    }
                }
                return s;
            };
            Stream.prototype.parseInteger = function (start, end) {
                //TODO support negative numbers
                var len = end - start;
                if (len > 4) {
                    len <<= 3;
                    var s = this.get(start);
                    if (s === 0)
                        len -= 8;
                    else
                        while (s < 128) {
                            s <<= 1;
                            --len;
                        }
                    return "(" + len + " bit)";
                }
                var n = 0;
                for (var i = start; i < end; ++i)
                    n = (n << 8) | this.get(i);
                return n;
            };
            Stream.prototype.parseBitString = function (start, end) {
                var unusedBit = this.get(start),
                    lenBit = ((end - start - 1) << 3) - unusedBit,
                    s = "(" + lenBit + " bit)";
                if (lenBit <= 20) {
                    var skip = unusedBit;
                    s += " ";
                    for (var i = end - 1; i > start; --i) {
                        var b = this.get(i);
                        for (var j = skip; j < 8; ++j)
                            s += (b >> j) & 1 ? "1" : "0";
                        skip = 0;
                    }
                }
                return s;
            };
            Stream.prototype.parseOctetString = function (start, end) {
                var len = end - start,
                    s = "(" + len + " byte) ";
                if (len > hardLimit)
                    end = start + hardLimit;
                for (var i = start; i < end; ++i)
                    s += this.hexByte(this.get(i)); //TODO: also try Latin1?
                if (len > hardLimit)
                    s += ellipsis;
                return s;
            };
            Stream.prototype.parseOID = function (start, end) {
                var s = '',
                    n = 0,
                    bits = 0;
                for (var i = start; i < end; ++i) {
                    var v = this.get(i);
                    n = (n << 7) | (v & 0x7F);
                    bits += 7;
                    if (!(v & 0x80)) { // finished
                        if (s === '') {
                            var m = n < 80 ? n < 40 ? 0 : 1 : 2;
                            s = m + "." + (n - m * 40);
                        } else
                            s += "." + ((bits >= 31) ? "bigint" : n);
                        n = bits = 0;
                    }
                }
                return s;
            };

            function ASN1(stream, header, length, tag, sub) {
                this.stream = stream;
                this.header = header;
                this.length = length;
                this.tag = tag;
                this.sub = sub;
            }

            ASN1.prototype.typeName = function () {
                if (this.tag === undefined)
                    return "unknown";
                var tagClass = this.tag >> 6,
                    tagConstructed = (this.tag >> 5) & 1,
                    tagNumber = this.tag & 0x1F;
                switch (tagClass) {
                    case 0: // universal
                        switch (tagNumber) {
                            case 0x00:
                                return "EOC";
                            case 0x01:
                                return "BOOLEAN";
                            case 0x02:
                                return "INTEGER";
                            case 0x03:
                                return "BIT_STRING";
                            case 0x04:
                                return "OCTET_STRING";
                            case 0x05:
                                return "NULL";
                            case 0x06:
                                return "OBJECT_IDENTIFIER";
                            case 0x07:
                                return "ObjectDescriptor";
                            case 0x08:
                                return "EXTERNAL";
                            case 0x09:
                                return "REAL";
                            case 0x0A:
                                return "ENUMERATED";
                            case 0x0B:
                                return "EMBEDDED_PDV";
                            case 0x0C:
                                return "UTF8String";
                            case 0x10:
                                return "SEQUENCE";
                            case 0x11:
                                return "SET";
                            case 0x12:
                                return "NumericString";
                            case 0x13:
                                return "PrintableString"; // ASCII subset
                            case 0x14:
                                return "TeletexString"; // aka T61String
                            case 0x15:
                                return "VideotexString";
                            case 0x16:
                                return "IA5String"; // ASCII
                            case 0x17:
                                return "UTCTime";
                            case 0x18:
                                return "GeneralizedTime";
                            case 0x19:
                                return "GraphicString";
                            case 0x1A:
                                return "VisibleString"; // ASCII subset
                            case 0x1B:
                                return "GeneralString";
                            case 0x1C:
                                return "UniversalString";
                            case 0x1E:
                                return "BMPString";
                            default:
                                return "Universal_" + tagNumber.toString(16);
                        }
                    case 1:
                        return "Application_" + tagNumber.toString(16);
                    case 2:
                        return "[" + tagNumber + "]"; // Context
                    case 3:
                        return "Private_" + tagNumber.toString(16);
                }
            };
            ASN1.prototype.reSeemsASCII = /^[ -~]+$/;
            ASN1.prototype.content = function () {
                if (this.tag === undefined)
                    return null;
                var tagClass = this.tag >> 6,
                    tagNumber = this.tag & 0x1F,
                    content = this.posContent(),
                    len = Math.abs(this.length);
                if (tagClass !== 0) { // universal
                    if (this.sub !== null)
                        return "(" + this.sub.length + " elem)";
                    //TODO: TRY TO PARSE ASCII STRING
                    var s = this.stream.parseStringISO(content, content + Math.min(len, hardLimit));
                    if (this.reSeemsASCII.test(s))
                        return s.substring(0, 2 * hardLimit) + ((s.length > 2 * hardLimit) ? ellipsis : "");
                    else
                        return this.stream.parseOctetString(content, content + len);
                }
                switch (tagNumber) {
                    case 0x01: // BOOLEAN
                        return (this.stream.get(content) === 0) ? "false" : "true";
                    case 0x02: // INTEGER
                        return this.stream.parseInteger(content, content + len);
                    case 0x03: // BIT_STRING
                        return this.sub ? "(" + this.sub.length + " elem)" :
                            this.stream.parseBitString(content, content + len);
                    case 0x04: // OCTET_STRING
                        return this.sub ? "(" + this.sub.length + " elem)" :
                            this.stream.parseOctetString(content, content + len);
                    //case 0x05: // NULL
                    case 0x06: // OBJECT_IDENTIFIER
                        return this.stream.parseOID(content, content + len);
                    //case 0x07: // ObjectDescriptor
                    //case 0x08: // EXTERNAL
                    //case 0x09: // REAL
                    //case 0x0A: // ENUMERATED
                    //case 0x0B: // EMBEDDED_PDV
                    case 0x10: // SEQUENCE
                    case 0x11: // SET
                        return "(" + this.sub.length + " elem)";
                    case 0x0C: // UTF8String
                        return this.stream.parseStringUTF(content, content + len);
                    case 0x12: // NumericString
                    case 0x13: // PrintableString
                    case 0x14: // TeletexString
                    case 0x15: // VideotexString
                    case 0x16: // IA5String
                    //case 0x19: // GraphicString
                    case 0x1A: // VisibleString
                        //case 0x1B: // GeneralString
                        //case 0x1C: // UniversalString
                        return this.stream.parseStringISO(content, content + len);
                    case 0x1E: // BMPString
                        return this.stream.parseStringBMP(content, content + len);
                    case 0x17: // UTCTime
                    case 0x18: // GeneralizedTime
                        return this.stream.parseTime(content, content + len);
                }
                return null;
            };
            ASN1.prototype.toString = function () {
                return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub === null) ? 'null' : this.sub.length) + "]";
            };
            ASN1.prototype.print = function (indent) {
                if (indent === undefined) indent = '';
                document.writeln(indent + this);
                if (this.sub !== null) {
                    indent += '  ';
                    for (var i = 0, max = this.sub.length; i < max; ++i)
                        this.sub[i].print(indent);
                }
            };
            ASN1.prototype.toPrettyString = function (indent) {
                if (indent === undefined) indent = '';
                var s = indent + this.typeName() + " @" + this.stream.pos;
                if (this.length >= 0)
                    s += "+";
                s += this.length;
                if (this.tag & 0x20)
                    s += " (constructed)";
                else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub !== null))
                    s += " (encapsulates)";
                s += "\n";
                if (this.sub !== null) {
                    indent += '  ';
                    for (var i = 0, max = this.sub.length; i < max; ++i)
                        s += this.sub[i].toPrettyString(indent);
                }
                return s;
            };
            ASN1.prototype.toDOM = function () {
                var node = DOM.tag("div", "node");
                node.asn1 = this;
                var head = DOM.tag("div", "head");
                var s = this.typeName().replace(/_/g, " ");
                head.innerHTML = s;
                var content = this.content();
                if (content !== null) {
                    content = String(content).replace(/</g, "&lt;");
                    var preview = DOM.tag("span", "preview");
                    preview.appendChild(DOM.text(content));
                    head.appendChild(preview);
                }
                node.appendChild(head);
                this.node = node;
                this.head = head;
                var value = DOM.tag("div", "value");
                s = "Offset: " + this.stream.pos + "<br/>";
                s += "Length: " + this.header + "+";
                if (this.length >= 0)
                    s += this.length;
                else
                    s += (-this.length) + " (undefined)";
                if (this.tag & 0x20)
                    s += "<br/>(constructed)";
                else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub !== null))
                    s += "<br/>(encapsulates)";
                //TODO if (this.tag == 0x03) s += "Unused bits: "
                if (content !== null) {
                    s += "<br/>Value:<br/><b>" + content + "</b>";
                    if ((typeof oids === 'object') && (this.tag == 0x06)) {
                        var oid = oids[content];
                        if (oid) {
                            if (oid.d) s += "<br/>" + oid.d;
                            if (oid.c) s += "<br/>" + oid.c;
                            if (oid.w) s += "<br/>(warning!)";
                        }
                    }
                }
                value.innerHTML = s;
                node.appendChild(value);
                var sub = DOM.tag("div", "sub");
                if (this.sub !== null) {
                    for (var i = 0, max = this.sub.length; i < max; ++i)
                        sub.appendChild(this.sub[i].toDOM());
                }
                node.appendChild(sub);
                head.onclick = function () {
                    node.className = (node.className == "node collapsed") ? "node" : "node collapsed";
                };
                return node;
            };
            ASN1.prototype.posStart = function () {
                return this.stream.pos;
            };
            ASN1.prototype.posContent = function () {
                return this.stream.pos + this.header;
            };
            ASN1.prototype.posEnd = function () {
                return this.stream.pos + this.header + Math.abs(this.length);
            };
            ASN1.prototype.fakeHover = function (current) {
                this.node.className += " hover";
                if (current)
                    this.head.className += " hover";
            };
            ASN1.prototype.fakeOut = function (current) {
                var re = / ?hover/;
                this.node.className = this.node.className.replace(re, "");
                if (current)
                    this.head.className = this.head.className.replace(re, "");
            };
            ASN1.prototype.toHexDOM_sub = function (node, className, stream, start, end) {
                if (start >= end)
                    return;
                var sub = DOM.tag("span", className);
                sub.appendChild(DOM.text(
                    stream.hexDump(start, end)));
                node.appendChild(sub);
            };
            ASN1.prototype.toHexDOM = function (root) {
                var node = DOM.tag("span", "hex");
                if (root === undefined) root = node;
                this.head.hexNode = node;
                this.head.onmouseover = function () {
                    this.hexNode.className = "hexCurrent";
                };
                this.head.onmouseout = function () {
                    this.hexNode.className = "hex";
                };
                node.asn1 = this;
                node.onmouseover = function () {
                    var current = !root.selected;
                    if (current) {
                        root.selected = this.asn1;
                        this.className = "hexCurrent";
                    }
                    this.asn1.fakeHover(current);
                };
                node.onmouseout = function () {
                    var current = (root.selected == this.asn1);
                    this.asn1.fakeOut(current);
                    if (current) {
                        root.selected = null;
                        this.className = "hex";
                    }
                };
                this.toHexDOM_sub(node, "tag", this.stream, this.posStart(), this.posStart() + 1);
                this.toHexDOM_sub(node, (this.length >= 0) ? "dlen" : "ulen", this.stream, this.posStart() + 1, this.posContent());
                if (this.sub === null)
                    node.appendChild(DOM.text(
                        this.stream.hexDump(this.posContent(), this.posEnd())));
                else if (this.sub.length > 0) {
                    var first = this.sub[0];
                    var last = this.sub[this.sub.length - 1];
                    this.toHexDOM_sub(node, "intro", this.stream, this.posContent(), first.posStart());
                    for (var i = 0, max = this.sub.length; i < max; ++i)
                        node.appendChild(this.sub[i].toHexDOM(root));
                    this.toHexDOM_sub(node, "outro", this.stream, last.posEnd(), this.posEnd());
                }
                return node;
            };
            ASN1.prototype.toHexString = function (root) {
                return this.stream.hexDump(this.posStart(), this.posEnd(), true);
            };
            ASN1.decodeLength = function (stream) {
                var buf = stream.get(),
                    len = buf & 0x7F;
                if (len == buf)
                    return len;
                if (len > 3)
                    throw "Length over 24 bits not supported at position " + (stream.pos - 1);
                if (len === 0)
                    return -1; // undefined
                buf = 0;
                for (var i = 0; i < len; ++i)
                    buf = (buf << 8) | stream.get();
                return buf;
            };
            ASN1.hasContent = function (tag, len, stream) {
                if (tag & 0x20) // constructed
                    return true;
                if ((tag < 0x03) || (tag > 0x04))
                    return false;
                var p = new Stream(stream);
                if (tag == 0x03) p.get(); // BitString unused bits, must be in [0, 7]
                var subTag = p.get();
                if ((subTag >> 6) & 0x01) // not (universal or context)
                    return false;
                try {
                    var subLength = ASN1.decodeLength(p);
                    return ((p.pos - stream.pos) + subLength == len);
                } catch (exception) {
                    return false;
                }
            };
            ASN1.decode = function (stream) {
                if (!(stream instanceof Stream))
                    stream = new Stream(stream, 0);
                var streamStart = new Stream(stream),
                    tag = stream.get(),
                    len = ASN1.decodeLength(stream),
                    header = stream.pos - streamStart.pos,
                    sub = null;
                if (ASN1.hasContent(tag, len, stream)) {
                    // it has content, so we decode it
                    var start = stream.pos;
                    if (tag == 0x03) stream.get(); // skip BitString unused bits, must be in [0, 7]
                    sub = [];
                    if (len >= 0) {
                        // definite length
                        var end = start + len;
                        while (stream.pos < end)
                            sub[sub.length] = ASN1.decode(stream);
                        if (stream.pos != end)
                            throw "Content size is not correct for container starting at offset " + start;
                    } else {
                        // undefined length
                        try {
                            for (; ;) {
                                var s = ASN1.decode(stream);
                                if (s.tag === 0)
                                    break;
                                sub[sub.length] = s;
                            }
                            len = start - stream.pos;
                        } catch (e) {
                            throw "Exception while decoding undefined length content: " + e;
                        }
                    }
                } else
                    stream.pos += len; // skip content
                return new ASN1(streamStart, header, len, tag, sub);
            };
            ASN1.test = function () {
                var test = [
                    {value: [0x27], expected: 0x27},
                    {value: [0x81, 0xC9], expected: 0xC9},
                    {value: [0x83, 0xFE, 0xDC, 0xBA], expected: 0xFEDCBA}
                ];
                for (var i = 0, max = test.length; i < max; ++i) {
                    var pos = 0,
                        stream = new Stream(test[i].value, 0),
                        res = ASN1.decodeLength(stream);
                    if (res != test[i].expected)
                        document.write("In test[" + i + "] expected " + test[i].expected + " got " + res + "\n");
                }
            };

// export globals
            window.ASN1 = ASN1;
        })();
        /**
         * Retrieve the hexadecimal value (as a string) of the current ASN.1 element
         * @returns {string}
         * @public
         */
        ASN1.prototype.getHexStringValue = function () {
            var hexString = this.toHexString();
            var offset = this.header * 2;
            var length = this.length * 2;
            return hexString.substr(offset, length);
        };

        /**
         * Method to parse a pem encoded string containing both a public or private key.
         * The method will translate the pem encoded string in a der encoded string and
         * will parse private key and public key parameters. This method accepts public key
         * in the rsaencryption pkcs #1 format (oid: 1.2.840.113549.1.1.1).
         * @todo Check how many rsa formats use the same format of pkcs #1. The format is defined as:
         * PublicKeyInfo ::= SEQUENCE {
 *   algorithm       AlgorithmIdentifier,
 *   PublicKey       BIT STRING
 * }
         * Where AlgorithmIdentifier is:
         * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm       OBJECT IDENTIFIER,     the OID of the enc algorithm
 *   parameters      ANY DEFINED BY algorithm OPTIONAL (NULL for PKCS #1)
 * }
         * and PublicKey is a SEQUENCE encapsulated in a BIT STRING
         * RSAPublicKey ::= SEQUENCE {
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER   -- e
 * }
         * it's possible to examine the structure of the keys obtained from openssl using
         * an asn.1 dumper as the one used here to parse the components: http://lapo.it/asn1js/
         * @argument {string} pem the pem encoded string, can include the BEGIN/END header/footer
         * @private
         */
        RSAKey.prototype.parseKey = function (pem) {
            try {
                var reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/;
                var der = reHex.test(pem) ? Hex.decode(pem) : Base64.unarmor(pem);
                var asn1 = ASN1.decode(der);
                if (asn1.sub.length === 9) {
                    // the data is a Private key
                    //in order
                    //Algorithm version, n, e, d, p, q, dmp1, dmq1, coeff
                    //Alg version, modulus, public exponent, private exponent, prime 1, prime 2, exponent 1, exponent 2, coefficient
                    var modulus = asn1.sub[1].getHexStringValue(); //bigint
                    this.n = parseBigInt(modulus, 16);

                    var public_exponent = asn1.sub[2].getHexStringValue(); //int
                    this.e = parseInt(public_exponent, 16);

                    var private_exponent = asn1.sub[3].getHexStringValue(); //bigint
                    this.d = parseBigInt(private_exponent, 16);

                    var prime1 = asn1.sub[4].getHexStringValue(); //bigint
                    this.p = parseBigInt(prime1, 16);

                    var prime2 = asn1.sub[5].getHexStringValue(); //bigint
                    this.q = parseBigInt(prime2, 16);

                    var exponent1 = asn1.sub[6].getHexStringValue(); //bigint
                    this.dmp1 = parseBigInt(exponent1, 16);

                    var exponent2 = asn1.sub[7].getHexStringValue(); //bigint
                    this.dmq1 = parseBigInt(exponent2, 16);

                    var coefficient = asn1.sub[8].getHexStringValue(); //bigint
                    this.coeff = parseBigInt(coefficient, 16);

                } else if (asn1.sub.length === 2) {
                    //Public key
                    //The data PROBABLY is a public key
                    var bit_string = asn1.sub[1];
                    var sequence = bit_string.sub[0];

                    var modulus = sequence.sub[0].getHexStringValue();
                    this.n = parseBigInt(modulus, 16);
                    var public_exponent = sequence.sub[1].getHexStringValue();
                    this.e = parseInt(public_exponent, 16);

                } else {
                    return false;
                }
                return true;
            } catch (ex) {
                return false;
            }
        };

        /**
         * Translate rsa parameters in a hex encoded string representing the rsa key.
         * The translation follow the ASN.1 notation :
         * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER,  -- e
 *   privateExponent   INTEGER,  -- d
 *   prime1            INTEGER,  -- p
 *   prime2            INTEGER,  -- q
 *   exponent1         INTEGER,  -- d mod (p1)
 *   exponent2         INTEGER,  -- d mod (q-1)
 *   coefficient       INTEGER,  -- (inverse of q) mod p
 * }
         * @returns {string}  DER Encoded String representing the rsa private key
         * @private
         */
        RSAKey.prototype.getPrivateBaseKey = function () {
            //Algorithm version, n, e, d, p, q, dmp1, dmq1, coeff
            //Alg version, modulus, public exponent, private exponent, prime 1, prime 2, exponent 1, exponent 2, coefficient
            var options = {
                'array': [
                    new KJUR.asn1.DERInteger({'int': 0}),
                    new KJUR.asn1.DERInteger({'bigint': this.n}),
                    new KJUR.asn1.DERInteger({'int': this.e}),
                    new KJUR.asn1.DERInteger({'bigint': this.d}),
                    new KJUR.asn1.DERInteger({'bigint': this.p}),
                    new KJUR.asn1.DERInteger({'bigint': this.q}),
                    new KJUR.asn1.DERInteger({'bigint': this.dmp1}),
                    new KJUR.asn1.DERInteger({'bigint': this.dmq1}),
                    new KJUR.asn1.DERInteger({'bigint': this.coeff})
                ]
            };
            var seq = new KJUR.asn1.DERSequence(options);
            return seq.getEncodedHex();
        };

        /**
         * base64 (pem) encoded version of the DER encoded representation
         * @returns {string} pem encoded representation without header and footer
         * @public
         */
        RSAKey.prototype.getPrivateBaseKeyB64 = function () {
            return hex2b64(this.getPrivateBaseKey());
        };

        /**
         * Translate rsa parameters in a hex encoded string representing the rsa public key.
         * The representation follow the ASN.1 notation :
         * PublicKeyInfo ::= SEQUENCE {
 *   algorithm       AlgorithmIdentifier,
 *   PublicKey       BIT STRING
 * }
         * Where AlgorithmIdentifier is:
         * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm       OBJECT IDENTIFIER,     the OID of the enc algorithm
 *   parameters      ANY DEFINED BY algorithm OPTIONAL (NULL for PKCS #1)
 * }
         * and PublicKey is a SEQUENCE encapsulated in a BIT STRING
         * RSAPublicKey ::= SEQUENCE {
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER   -- e
 * }
         * @returns {string} DER Encoded String representing the rsa public key
         * @private
         */
        RSAKey.prototype.getPublicBaseKey = function () {
            var options = {
                'array': [
                    new KJUR.asn1.DERObjectIdentifier({'oid': '1.2.840.113549.1.1.1'}), //RSA Encryption pkcs #1 oid
                    new KJUR.asn1.DERNull()
                ]
            };
            var first_sequence = new KJUR.asn1.DERSequence(options);

            options = {
                'array': [
                    new KJUR.asn1.DERInteger({'bigint': this.n}),
                    new KJUR.asn1.DERInteger({'int': this.e})
                ]
            };
            var second_sequence = new KJUR.asn1.DERSequence(options);

            options = {
                'hex': '00' + second_sequence.getEncodedHex()
            };
            var bit_string = new KJUR.asn1.DERBitString(options);

            options = {
                'array': [
                    first_sequence,
                    bit_string
                ]
            };
            var seq = new KJUR.asn1.DERSequence(options);
            return seq.getEncodedHex();
        };

        /**
         * base64 (pem) encoded version of the DER encoded representation
         * @returns {string} pem encoded representation without header and footer
         * @public
         */
        RSAKey.prototype.getPublicBaseKeyB64 = function () {
            return hex2b64(this.getPublicBaseKey());
        };

        /**
         * wrap the string in block of width chars. The default value for rsa keys is 64
         * characters.
         * @param {string} str the pem encoded string without header and footer
         * @param {Number} [width=64] - the length the string has to be wrapped at
         * @returns {string}
         * @private
         */
        RSAKey.prototype.wordwrap = function (str, width) {
            width = width || 64;
            if (!str)
                return str;
            var regex = '(.{1,' + width + '})( +|$\n?)|(.{1,' + width + '})';
            return str.match(RegExp(regex, 'g')).join('\n');
        };

        /**
         * Retrieve the pem encoded private key
         * @returns {string} the pem encoded private key with header/footer
         * @public
         */
        RSAKey.prototype.getPrivateKey = function () {
            var key = "-----BEGIN RSA PRIVATE KEY-----\n";
            key += this.wordwrap(this.getPrivateBaseKeyB64()) + "\n";
            key += "-----END RSA PRIVATE KEY-----";
            return key;
        };

        /**
         * Retrieve the pem encoded public key
         * @returns {string} the pem encoded public key with header/footer
         * @public
         */
        RSAKey.prototype.getPublicKey = function () {
            var key = "-----BEGIN PUBLIC KEY-----\n";
            key += this.wordwrap(this.getPublicBaseKeyB64()) + "\n";
            key += "-----END PUBLIC KEY-----";
            return key;
        };

        /**
         * Check if the object contains the necessary parameters to populate the rsa modulus
         * and public exponent parameters.
         * @param {Object} [obj={}] - An object that may contain the two public key
         * parameters
         * @returns {boolean} true if the object contains both the modulus and the public exponent
         * properties (n and e)
         * @todo check for types of n and e. N should be a parseable bigInt object, E should
         * be a parseable integer number
         * @private
         */
        RSAKey.prototype.hasPublicKeyProperty = function (obj) {
            obj = obj || {};
            return obj.hasOwnProperty('n') &&
                obj.hasOwnProperty('e');
        };

        /**
         * Check if the object contains ALL the parameters of an RSA key.
         * @param {Object} [obj={}] - An object that may contain nine rsa key
         * parameters
         * @returns {boolean} true if the object contains all the parameters needed
         * @todo check for types of the parameters all the parameters but the public exponent
         * should be parseable bigint objects, the public exponent should be a parseable integer number
         * @private
         */
        RSAKey.prototype.hasPrivateKeyProperty = function (obj) {
            obj = obj || {};
            return obj.hasOwnProperty('n') &&
                obj.hasOwnProperty('e') &&
                obj.hasOwnProperty('d') &&
                obj.hasOwnProperty('p') &&
                obj.hasOwnProperty('q') &&
                obj.hasOwnProperty('dmp1') &&
                obj.hasOwnProperty('dmq1') &&
                obj.hasOwnProperty('coeff');
        };

        /**
         * Parse the properties of obj in the current rsa object. Obj should AT LEAST
         * include the modulus and public exponent (n, e) parameters.
         * @param {Object} obj - the object containing rsa parameters
         * @private
         */
        RSAKey.prototype.parsePropertiesFrom = function (obj) {
            this.n = obj.n;
            this.e = obj.e;

            if (obj.hasOwnProperty('d')) {
                this.d = obj.d;
                this.p = obj.p;
                this.q = obj.q;
                this.dmp1 = obj.dmp1;
                this.dmq1 = obj.dmq1;
                this.coeff = obj.coeff;
            }
        };

        /**
         * Create a new JSEncryptRSAKey that extends Tom Wu's RSA key object.
         * This object is just a decorator for parsing the key parameter
         * @param {string|Object} key - The key in string format, or an object containing
         * the parameters needed to build a RSAKey object.
         * @constructor
         */
        var JSEncryptRSAKey = function (key) {
            // Call the super constructor.
            RSAKey.call(this);
            // If a key key was provided.
            if (key) {
                // If this is a string...
                if (typeof key === 'string') {
                    this.parseKey(key);
                } else if (this.hasPrivateKeyProperty(key) || this.hasPublicKeyProperty(key)) {
                    // Set the values for the key.
                    this.parsePropertiesFrom(key);
                }
            }
        };

// Derive from RSAKey.
        JSEncryptRSAKey.prototype = new RSAKey();

// Reset the contructor.
        JSEncryptRSAKey.prototype.constructor = JSEncryptRSAKey;


        /**
         *
         * @param {Object} [options = {}] - An object to customize JSEncrypt behaviour
         * possible parameters are:
         * - default_key_size        {number}  default: 1024 the key size in bit
         * - default_public_exponent {string}  default: '010001' the hexadecimal representation of the public exponent
         * - log                     {boolean} default: false whether log warn/error or not
         * @constructor
         */
        var JSEncrypt = function (options) {
            options = options || {};
            this.default_key_size = parseInt(options.default_key_size) || 1024;
            this.default_public_exponent = options.default_public_exponent || '010001'; //65537 default openssl public exponent for rsa key type
            this.log = options.log || false;
            // The private and public key.
            this.key = null;
        };

        /**
         * Method to set the rsa key parameter (one method is enough to set both the public
         * and the private key, since the private key contains the public key paramenters)
         * Log a warning if logs are enabled
         * @param {Object|string} key the pem encoded string or an object (with or without header/footer)
         * @public
         */
        JSEncrypt.prototype.setKey = function (key) {
            if (this.log && this.key)
                console.warn('A key was already set, overriding existing.');
            this.key = new JSEncryptRSAKey(key);
        };

        /**
         * Proxy method for setKey, for api compatibility
         * @see setKey
         * @public
         */
        JSEncrypt.prototype.setPrivateKey = function (privkey) {
            // Create the key.
            this.setKey(privkey);
        };

        /**
         * Proxy method for setKey, for api compatibility
         * @see setKey
         * @public
         */
        JSEncrypt.prototype.setPublicKey = function (pubkey) {
            // Sets the public key.
            this.setKey(pubkey);
        };

        /**
         * Proxy method for RSAKey object's decrypt, decrypt the string using the private
         * components of the rsa key object. Note that if the object was not set will be created
         * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
         * @param {string} string base64 encoded crypted string to decrypt
         * @return {string} the decrypted string
         * @public
         */
        JSEncrypt.prototype.decrypt = function (string) {
            // Return the decrypted string.
            try {
                return this.getKey().decrypt(b64tohex(string));
            } catch (ex) {
                return false;
            }
        };

        /**
         * Proxy method for RSAKey object's encrypt, encrypt the string using the public
         * components of the rsa key object. Note that if the object was not set will be created
         * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
         * @param {string} string the string to encrypt
         * @return {string} the encrypted string encoded in base64
         * @public
         */
        JSEncrypt.prototype.encrypt = function (string) {
            // Return the encrypted string.
            try {
                return hex2b64(this.getKey().encrypt(string));
            } catch (ex) {
                return false;
            }
        };

        /**
         * Getter for the current JSEncryptRSAKey object. If it doesn't exists a new object
         * will be created and returned
         * @param {callback} [cb] the callback to be called if we want the key to be generated
         * in an async fashion
         * @returns {JSEncryptRSAKey} the JSEncryptRSAKey object
         * @public
         */
        JSEncrypt.prototype.getKey = function (cb) {
            // Only create new if it does not exist.
            if (!this.key) {
                // Get a new private key.
                this.key = new JSEncryptRSAKey();
                if (cb && {}.toString.call(cb) === '[object Function]') {
                    this.key.generateAsync(this.default_key_size, this.default_public_exponent, cb);
                    return;
                }
                // Generate the key.
                this.key.generate(this.default_key_size, this.default_public_exponent);
            }
            return this.key;
        };

        /**
         * Returns the pem encoded representation of the private key
         * If the key doesn't exists a new key will be created
         * @returns {string} pem encoded representation of the private key WITH header and footer
         * @public
         */
        JSEncrypt.prototype.getPrivateKey = function () {
            // Return the private representation of this key.
            return this.getKey().getPrivateKey();
        };

        /**
         * Returns the pem encoded representation of the private key
         * If the key doesn't exists a new key will be created
         * @returns {string} pem encoded representation of the private key WITHOUT header and footer
         * @public
         */
        JSEncrypt.prototype.getPrivateKeyB64 = function () {
            // Return the private representation of this key.
            return this.getKey().getPrivateBaseKeyB64();
        };


        /**
         * Returns the pem encoded representation of the public key
         * If the key doesn't exists a new key will be created
         * @returns {string} pem encoded representation of the public key WITH header and footer
         * @public
         */
        JSEncrypt.prototype.getPublicKey = function () {
            // Return the private representation of this key.
            return this.getKey().getPublicKey();
        };

        /**
         * Returns the pem encoded representation of the public key
         * If the key doesn't exists a new key will be created
         * @returns {string} pem encoded representation of the public key WITHOUT header and footer
         * @public
         */
        JSEncrypt.prototype.getPublicKeyB64 = function () {
            // Return the private representation of this key.
            return this.getKey().getPublicBaseKeyB64();
        };

        exports.JSEncrypt = JSEncrypt;
    })(JSEncryptExports);
    var JSEncrypt = JSEncryptExports.JSEncrypt;

    var generateRandomNumbers = function () {
        return window.crypto.getRandomValues((new Uint32Array(10)));
    };

    return {
        CryptoJS: CryptoJS,
        X509: X509,
        generateRandomNumbers: generateRandomNumbers
    };

});