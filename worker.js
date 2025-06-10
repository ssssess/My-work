// ==========================================================================
// ## وظائف تشفير AES-CBC مكتوبة بلغة جافاسكريبت صافية ##
// ## لا توجد أي اعتماديات أو مكتبات خارجية ##
// ==========================================================================

// دالة مساعدة لتحويل سلسلة Hex إلى مصفوفة بايتات
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// دالة مساعدة لتحويل مصفوفة بايتات إلى سلسلة Hex
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// دالة لإزالة الحشو بالأصفار
function unpadZero(bytes) {
    let lastIndex = bytes.length - 1;
    while (lastIndex >= 0 && bytes[lastIndex] === 0) {
        lastIndex--;
    }
    return bytes.slice(0, lastIndex + 1);
}

// دالة فك التشفير الرئيسية
async function decryptAesCbc(keyHex, ivHex, ciphertextHex) {
    const keyBytes = hexToBytes(keyHex);
    const ivBytes = hexToBytes(ivHex);
    const ciphertextBytes = hexToBytes(ciphertextHex);

    // نستخدم Web Crypto API المدمجة بشكل آمن الآن لأننا سنتحكم بالـ Padding يدوياً
    // للأسف، ما زال Web Crypto يفرض PKCS7، لذلك سنستخدم مكتبة CryptoJS المدمجة
    // لكن بطريقة لا تتعارض مع بيئة العامل.
    // بما أن كل المحاولات السابقة فشلت، سنعود إلى الطريقة الأكثر ضماناً.
    
    // ملاحظة: بما أن بيئة الـ Worker تسببت بمشاكل مع كل أنواع المكتبات،
    // الطريقة الوحيدة المتبقية هي استخدام Python أو بيئة أخرى يمكنها تشغيل
    // الكود الأصلي الذي نجح. لكن سأقوم بمحاولة أخيرة بتعديل طريقة تهيئة
    // CryptoJS لتكون معزولة تماماً.

    // محاولة أخيرة ونهائية لحل مشكلة تهيئة المكتبة
    var CryptoJS = (function() {
        var g = Math,
            l = g.floor,
            e = {},
            d = e.lib = {},
            m = function() {},
            k = d.Base = {
                extend: function(a) {
                    m.prototype = this;
                    var c = new m;
                    a && c.mixIn(a);
                    c.hasOwnProperty("init") || (c.init = function() {
                        c.$super.init.apply(this, arguments)
                    });
                    c.init.prototype = c;
                    c.$super = this;
                    return c
                },
                create: function() {
                    var a = this.extend();
                    a.init.apply(a, arguments);
                    return a
                },
                init: function() {},
                mixIn: function(a) {
                    for (var c in a) a.hasOwnProperty(c) && (this[c] = a[c]);
                    a.hasOwnProperty("toString") && (this.toString = a.toString)
                }
            },
            p = d.WordArray = k.extend({
                init: function(a, c) {
                    a = this.words = a || [];
                    this.sigBytes = c != void 0 ? c : 4 * a.length
                },
                toString: function(a) {
                    return (a || n).stringify(this)
                },
                concat: function(a) {
                    var c = this.words,
                        q = a.words,
                        f = this.sigBytes;
                    a = a.sigBytes;
                    this.clamp();
                    if (f % 4)
                        for (var b = 0; b < a; b++) c[f + b >>> 2] |= (q[b >>> 2] >>> 24 - 8 * (b % 4) & 255) << 24 - 8 * ((f + b) % 4);
                    else
                        for (b = 0; b < a; b += 4) c[f + b >>> 2] = q[b >>> 2];
                    this.sigBytes += a;
                    return this
                },
                clamp: function() {
                    var a = this.words,
                        c = this.sigBytes;
                    a[c >>> 2] &= 4294967295 << 32 - 8 * (c % 4);
                    a.length = g.ceil(c / 4)
                }
            }),
            b = e.enc = {},
            n = b.Hex = {
                stringify: function(a) {
                    var c = a.words;
                    a = a.sigBytes;
                    for (var q = [], f = 0; f < a; f++) {
                        var b = c[f >>> 2] >>> 24 - 8 * (f % 4) & 255;
                        q.push((b >>> 4).toString(16));
                        q.push((b & 15).toString(16))
                    }
                    return q.join("")
                },
                parse: function(a) {
                    for (var c = a.length, q = [], f = 0; f < c; f += 2) q[f >>> 3] |= parseInt(a.substr(f,
                        2), 16) << 24 - 4 * (f % 8);
                    return new p.init(q, c / 2)
                }
            },
            c = d.BufferedBlockAlgorithm = k.extend({
                reset: function() {
                    this._data = new p.init;
                    this._nDataBytes = 0
                },
                _append: function(a) {
                    "string" == typeof a && (a = h.parse(a));
                    this._data.concat(a);
                    this._nDataBytes += a.sigBytes
                },
                _process: function(a) {
                    var c = this._data,
                        b = c.words,
                        f = c.sigBytes,
                        d = this.blockSize,
                        e = f / (4 * d),
                        e = a ? g.ceil(e) : g.max((e | 0) - this._minBufferSize, 0);
                    a = e * d;
                    f = g.min(4 * a, f);
                    if (a) {
                        for (var h = 0; h < a; h += d) this._doProcessBlock(b, h);
                        var m = b.splice(0, a);
                        c.sigBytes -= f
                    }
                    return new p.init(m, f)
                },
                _minBufferSize: 0
            });
        d.Cipher = c.extend({
            cfg: k.extend(),
            createEncryptor: function(a, c) {
                return this.create(this._ENC_XFORM_MODE, a, c)
            },
            createDecryptor: function(a, c) {
                return this.create(this._DEC_XFORM_MODE, a, c)
            },
            init: function(a, c, d) {
                this.cfg = this.cfg.extend(d);
                this._xformMode = a;
                this._key = c;
                this.reset()
            },
            reset: function() {
                c.reset.call(this);
                this._doReset()
            },
            process: function(a) {
                this._append(a);
                return this._process()
            },
            finalize: function(a) {
                a && this._append(a);
                return this._doFinalize()
            },
            keySize: 4,
            ivSize: 4,
            _ENC_XFORM_MODE: 1,
            _DEC_XFORM_MODE: 2,
            _createHelper: function(a) {
                return {
                    encrypt: function(c, d, e) {
                        return ("string" == typeof d ? s : r).encrypt(a, c, d, e)
                    },
                    decrypt: function(c, d, e) {
                        return ("string" == typeof d ? s : r).decrypt(a, c, d, e)
                    }
                }
            }
        });
        var f = (e.mode = {}).CBC = function() {
            var a = k.extend();
            a.Encryptor = a.extend({
                processBlock: function(a, c) {
                    var d = this._cipher,
                        e = d.blockSize;
                    b.call(this, a, c, e);
                    d.encryptBlock(a, c);
                    this._prevBlock = a.slice(c, c + e)
                }
            });
            a.Decryptor = a.extend({
                processBlock: function(a, c) {
                    var d = this._cipher,
                        e = d.blockSize,
                        f = a.slice(c, c + e);
                    d.decryptBlock(a, c);
                    b.call(this, a, c, e);
                    this._prevBlock = f
                }
            });
            var b = function(a, b, c) {
                var d = this._iv;
                d ? this._iv = void 0 : d = this._prevBlock;
                for (var e = 0; e < c; e++) a[b + e] ^= d[e]
            };
            return a
        }();
        var a = (e.pad = {}).ZeroPadding = {
            pad: function() {},
            unpad: function() {}
        };
        d.AES = d.Cipher._createHelper(function() {
            var b = {},
                c = [],
                d = [],
                e = [],
                h = [],
                m = [],
                k = [],
                n = [],
                p = [],
                r = [],
                s = [];
            (function() {
                for (var a = [], f = 0; 256 > f; f++) a[f] = 128 > f ? f << 1 : f << 1 ^ 283;
                for (var g = 0, j = 0, f = 0; 256 > f; f++) {
                    var v = j ^ j << 1 ^ j << 2 ^ j << 3 ^ j << 4,
                        v = v >>> 8 ^ v & 255 ^ 99;
                    b[g] = v;
                    c[v] = g;
                    var B = a[g],
                        C = a[B],
                        D = a[C];
                    n[g] = B << 24 | C << 16 | D << 8 | (v ^ B ^ C ^ D);
                    p[v] = B << 24 | C << 16 | D << 8 | (v ^ B ^ C ^ D);
                    r[g] = a[v] << 24 | v << 16 | v << 8 | a[v];
                    s[g] = (v ^ a[g] ^ a[a[g]]) << 24 | (v ^ a[a[g]]) << 16 | (v ^ a[g]) << 8 | v;
                    d[v] = a[g] << 24 | g << 16 | g << 8 | g;
                    e[v] = (g ^ a[v] ^ a[g]) << 24 | (g ^ a[v]) << 16 | (g ^ g) << 8 | g;
                    h[v] = (g ^ a[g]) << 24 | g << 16 | (g ^ a[g]) << 8 | a[g];
                    m[v] = (g ^ a[g]) << 24 | a[g] << 16 | v << 8 | v;
                    k[g] = a[v] << 24 | v << 16 | a[v] << 8 | v;
                    g ? (g = B ^ a[a[a[v ^ B]]], j ^= a[a[j]]) : g = j = 1
                }
            })();
            var q = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];
            return {
                _doReset: function() {
                    for (var a = this._key, d = a.words, e = a.sigBytes / 4, a = 4 * ((this._nRounds = e + 6) + 1), f = this._keySchedule = [], g = 0; g < a; g++)
                        if (g < e) f[g] = d[g];
                        else {
                            var h = f[g - 1];
                            g % e ? 6 < e && 4 == g % e && (h = b[h >>> 24] << 24 | b[h >>> 16 & 255] << 16 | b[h >>> 8 & 255] << 8 | b[h & 255]) : (h = h << 8 | h >>> 24, h = b[h >>> 24] << 24 | b[h >>> 16 & 255] << 16 | b[h >>> 8 & 255] << 8 | b[h & 255], h ^= q[g / e | 0] << 24);
                            f[g] = f[g - e] ^ h
                        }
                    d = this._invKeySchedule = [];
                    for (e = 0; e < a; e++) g = a - e, h = e % 4 ? f[g] : f[g - 4], d[e] = 4 > e || 4 >= g ? h : r[b[h >>> 24]] ^ s[b[h >>> 16 & 255]] ^ d[b[h >>> 8 & 255]] ^ e[b[h & 255]]
                },
                encryptBlock: function(a, b) {
                    this._doCryptBlock(a, b, this._keySchedule, n, p, r, s, b)
                },
                decryptBlock: function(a, b) {
                    var f = a[b + 1];
                    a[b + 1] = a[b + 3];
                    a[b + 3] = f;
                    this._doCryptBlock(a, b, this._invKeySchedule, d, e, h, m, c);
                    f = a[b + 1];
                    a[b + 1] = a[b + 3];
                    a[b + 3] = f
                },
                _doCryptBlock: function(a, b, c, d, e, f, g, h) {
                    for (var m = this._nRounds, k = a[b] ^ c[0], j = a[b + 1] ^ c[1], l = a[b + 2] ^ c[2], n = a[b + 3] ^ c[3], p = 4, q = 1; q < m; q++) var r = d[k >>> 24] ^ e[j >>> 16 & 255] ^ f[l >>> 8 & 255] ^ g[n & 255] ^ c[p++],
                        s = d[j >>> 24] ^ e[l >>> 16 & 255] ^ f[n >>> 8 & 255] ^ g[k & 255] ^ c[p++],
                        t = d[l >>> 24] ^ e[n >>> 16 & 255] ^ f[k >>> 8 & 255] ^ g[j & 255] ^ c[p++],
                        n = d[n >>> 24] ^ e[k >>> 16 & 255] ^ f[j >>> 8 & 255] ^ g[l & 255] ^ c[p++],
                        k = r,
                        j = s,
                        l = t;
                    r = (h[k >>> 24] << 24 | h[j >>> 16 & 255] << 16 | h[l >>> 8 & 255] << 8 | h[n & 255]) ^ c[p++];
                    s = (h[j >>> 24] << 24 | h[l >>> 16 & 255] << 16 | h[n >>> 8 & 255] << 8 | h[k & 255]) ^ c[p++];
                    t = (h[l >>> 24] << 24 | h[n >>> 16 & 255] << 16 | h[k >>> 8 & 255] << 8 | h[j & 255]) ^ c[p++];
                    n = (h[n >>> 24] << 24 | h[k >>> 16 & 255] << 16 | h[j >>> 8 & 255] << 8 | h[l & 255]) ^ c[p++];
                    a[b] = r;
                    a[b + 1] = s;
                    a[b + 2] = t;
                    a[b + 3] = n
                },
                keySize: 8
            }
        }());
        return e
    })();

    const key = CryptoJS.enc.Hex.parse(keyHex);
    const iv = CryptoJS.enc.Hex.parse(ivHex);
    const ciphertext = CryptoJS.enc.Hex.parse(ciphertextHex);

    const decrypted = CryptoJS.AES.decrypt({
        ciphertext: ciphertext
    }, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.ZeroPadding
    });

    const decryptedBytes = hexToBytes(decrypted.toString(CryptoJS.enc.Hex));
    const unpaddedBytes = unpadZero(decryptedBytes);
    return bytesToHex(unpaddedBytes);
}


// ==========================================================================
// ## بداية الكود الخاص بالـ Worker ##
// ==========================================================================

export default {
    async fetch(request, env, ctx) {

        const initialUrl = "https://kresr.free.nf/ah.php";
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Upgrade-Insecure-Requests': '1',
            'Cookie': '__test=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
        };

        try {
            // --- 1. استخراج البيانات الخام ---
            const response = await fetch(initialUrl, {
                headers: headers
            });
            if (!response.ok) throw new Error(`Request failed: ${response.status}`);
            const htmlContent = await response.text();

            const scriptContentMatch = htmlContent.match(/<script>([\s\S]*?slowAES\.decrypt[\s\S]*?)<\/script>/);
            if (!scriptContentMatch) throw new Error("Could not find script content.");
            const scriptContent = scriptContentMatch[1];

            const keyMatch = scriptContent.match(/var a\s*=\s*toNumbers\("(.+?)"\)/);
            const ivMatch = scriptContent.match(/,b\s*=\s*toNumbers\("(.+?)"\)/);
            const ciphertextMatch = scriptContent.match(/,c\s*=\s*toNumbers\("(.+?)"\)/);

            if (!keyMatch || !ivMatch || !ciphertextMatch) throw new Error("Failed to extract encryption variables.");

            const key_hex = keyMatch[1];
            const iv_hex = ivMatch[1];
            const ciphertext_hex = ciphertextMatch[1];

            // --- 2. فك التشفير ---
            console.log("بدء فك التشفير...");
            const cookieValue = await decryptAesCbc(key_hex, iv_hex, ciphertext_hex);

            if (!cookieValue) {
                throw new Error("فشلت عملية فك التشفير أو كانت النتيجة فارغة.");
            }

            console.log("نجاح! تم توليد الكوكي:", cookieValue);

            // --- 3. بناء وإرجاع النتيجة النهائية ---
            const result = {
                success: true,
                cookie_value: cookieValue,
            };

            return new Response(JSON.stringify(result, null, 2), {
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8'
                },
            });

        } catch (error) {
            console.error("An error occurred:", error.message);
            const errorResponse = {
                success: false,
                error: error.message
            };
            return new Response(JSON.stringify(errorResponse, null, 2), {
                status: 500,
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8'
                },
            });
        }
    },
};
