// Ying.js —— 由 Ying.py 移植的 JS 版(CatVod QuickJS 格式)
// 自带 AES / Base64 / UTF-8 实现,不依赖任何外部库,单文件即可运行

const HOST = 'http://cms.lyyytv.cn';
const CMS_KEY = 'wP5bvxoc3yv7FoBQENFZuAF0EUYr4LTy';
const PARSE_API = 'http://61.184.23.217:6163/api/index?parsesId=4&appid=10001&videoUrl=';
const HEADERS = { 'User-Agent': 'okhttp/4.12.0' };
const PARSE_HEADERS = { 'User-Agent': 'okhttp-okgo/jeasonlzy' };

// ====================== 基础工具:Base64 / UTF-8 / AES-128-CBC ======================

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// strict=true 对应 Python validate=True:出现非法字符或长度不对直接返回 null
// strict=false 对应默认行为:丢弃非法字符,但补位不对仍然失败
function b64decode(str, strict) {
    let s = str;
    if (strict) {
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
    } else {
        s = s.replace(/[^A-Za-z0-9+/=]/g, '');
    }
    if (s.length % 4 !== 0) return null;
    const out = [];
    for (let i = 0; i < s.length; i += 4) {
        const c = [0, 1, 2, 3].map((k) => s[i + k]);
        const pad = c.filter((x) => x === '=').length;
        if (pad > 0 && i + 4 < s.length) return null;
        const n = c.map((x) => (x === '=' ? 0 : B64.indexOf(x)));
        if (n.some((x) => x < 0)) return null;
        const v = (n[0] << 18) | (n[1] << 12) | (n[2] << 6) | n[3];
        out.push((v >> 16) & 255);
        if (pad < 2) out.push((v >> 8) & 255);
        if (pad < 1) out.push(v & 255);
    }
    return out;
}

// 宽松 UTF-8 解码(对应 Python errors='ignore')
function utf8Decode(b) {
    let out = '';
    let i = 0;
    const cont = (k) => i + k < b.length && (b[i + k] & 0xc0) === 0x80;
    while (i < b.length) {
        const x = b[i];
        if (x < 0x80) {
            out += String.fromCharCode(x);
            i++;
        } else if (x >= 0xc2 && x < 0xe0 && cont(1)) {
            out += String.fromCharCode(((x & 0x1f) << 6) | (b[i + 1] & 0x3f));
            i += 2;
        } else if (x >= 0xe0 && x < 0xf0 && cont(1) && cont(2)) {
            out += String.fromCharCode(((x & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f));
            i += 3;
        } else if (x >= 0xf0 && x < 0xf5 && cont(1) && cont(2) && cont(3)) {
            const cp = ((x & 0x07) << 18) | ((b[i + 1] & 0x3f) << 12) | ((b[i + 2] & 0x3f) << 6) | (b[i + 3] & 0x3f);
            out += String.fromCodePoint(cp);
            i += 4;
        } else {
            i++;
        }
    }
    return out;
}

function utf8Encode(str) {
    const out = [];
    for (const ch of str) {
        const c = ch.codePointAt(0);
        if (c < 0x80) out.push(c);
        else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
        else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
        else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
}

// ---- AES-128 解密 ----
const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
(function initSbox() {
    const rotl = (x, n) => ((x << n) | (x >> (8 - n))) & 255;
    let p = 1;
    let q = 1;
    do {
        p = (p ^ (p << 1) ^ (p & 0x80 ? 0x11b : 0)) & 255;
        q = (q ^ (q << 1)) & 255;
        q = (q ^ (q << 2)) & 255;
        q = (q ^ (q << 4)) & 255;
        if (q & 0x80) q ^= 0x09;
        SBOX[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63;
    } while (p !== 1);
    SBOX[0] = 0x63;
    for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
})();

function xtime(a) {
    return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 255;
}

function gmul(a, b) {
    let r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

function expandKey(key) {
    const w = new Uint8Array(176);
    w.set(key);
    let rcon = 1;
    for (let i = 16; i < 176; i += 4) {
        let t = [w[i - 4], w[i - 3], w[i - 2], w[i - 1]];
        if (i % 16 === 0) {
            t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
            rcon = xtime(rcon);
        }
        for (let j = 0; j < 4; j++) w[i + j] = w[i - 16 + j] ^ t[j];
    }
    return w;
}

function decryptBlock(rk, input) {
    let s = Uint8Array.from(input);
    const addKey = (r) => {
        for (let i = 0; i < 16; i++) s[i] ^= rk[16 * r + i];
    };
    const invShiftSub = () => {
        const t = new Uint8Array(16);
        for (let r = 0; r < 4; r++) {
            for (let c = 0; c < 4; c++) {
                t[r + 4 * ((c + r) % 4)] = INV_SBOX[s[r + 4 * c]];
            }
        }
        s = t;
    };
    const invMix = () => {
        for (let c = 0; c < 4; c++) {
            const a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
            s[4 * c] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
            s[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
            s[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
            s[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
        }
    };
    addKey(10);
    for (let r = 9; r >= 1; r--) {
        invShiftSub();
        addKey(r);
        invMix();
    }
    invShiftSub();
    addKey(0);
    return s;
}

// AES-128-CBC 解密(不去填充),失败返回 null
function aesCbcDecrypt(data, key, iv) {
    if (key.length !== 16 || iv.length !== 16) return null;
    if (data.length === 0 || data.length % 16 !== 0) return null;
    const rk = expandKey(key);
    const out = [];
    let prev = iv;
    for (let i = 0; i < data.length; i += 16) {
        const block = data.slice(i, i + 16);
        const dec = decryptBlock(rk, block);
        for (let j = 0; j < 16; j++) out.push(dec[j] ^ prev[j]);
        prev = block;
    }
    return out;
}

// ====================== 业务解密:lvdou / ldmax ======================

// 对应 Python lvdou():处理 "lvdou+" 开头的播放地址,失败原样返回
function lvdou(text) {
    const prefix = 'lvdou+';
    if (!text || !text.startsWith(prefix)) return text;
    try {
        const key = utf8Encode(CMS_KEY.slice(0, 16));
        const iv = utf8Encode(CMS_KEY.slice(-16));
        const ct = b64decode(text.slice(prefix.length), false);
        if (!ct) return text;
        const pt = aesCbcDecrypt(ct, key, iv);
        if (!pt) return text;
        const pad = pt[pt.length - 1];
        if (pad < 1 || pad > 16) return text;
        for (let i = 0; i < pad; i++) {
            if (pt[pt.length - 1 - i] !== pad) return text;
        }
        return utf8Decode(pt.slice(0, pt.length - pad));
    } catch (e) {
        return text;
    }
}

// 对应 Python ldmax_decrypt 的核心:处理已解出的明文 url
function ldmaxDecryptPlain(url, depth) {
    if (depth > 5) return null;
    if (url.indexOf('ldmax.cooom') < 0) return url;
    const path = url.replace(/https?:\/\/ldmax\.cooom\//g, '');
    if (path.length < 16) return null;
    const key = utf8Encode(path.slice(0, 16).split('').reverse().join(''));
    const ct = b64decode(path.slice(16).replace(/\s+/g, ''), true);
    if (!ct) return null;
    const dec = aesCbcDecrypt(ct, key, key);
    if (!dec) return null;
    let bytes = dec;
    const pad = bytes[bytes.length - 1];
    if (pad > 0 && pad <= 16) bytes = bytes.slice(0, bytes.length - pad);
    const result = utf8Decode(bytes).trim();
    if (result.indexOf('ldmax.cooom') >= 0) {
        return ldmaxDecryptPlain(result.replace(/\s+/g, ''), depth + 1);
    }
    return result;
}

// 对应 Python ldmax_decrypt:非法 base64(如明文URL)原样返回
function ldmaxDecrypt(encrypted, depth) {
    if (depth > 5) return null;
    const cleaned = String(encrypted).replace(/\s+/g, '');
    const bytes = b64decode(cleaned, true);
    if (!bytes) return encrypted;
    const url = utf8Decode(bytes).replace(/\s+/g, '');
    return ldmaxDecryptPlain(url, depth);
}

// 对应 Python quote(safe=''),只保留 A-Za-z0-9_.-~
function quoteAll(s) {
    return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

async function getJson(url, headers, timeout) {
    const res = await req(url, { method: 'get', headers: headers || HEADERS, timeout: timeout || 15000 });
    const text = typeof res === 'string' ? res : res.content;
    return JSON.parse(text);
}

async function ldmaxParse(videoUrl) {
    const decrypted = ldmaxDecrypt(videoUrl, 0);
    if (!decrypted || !/^https?:\/\//.test(decrypted)) return null;
    let resp;
    try {
        resp = await getJson(PARSE_API + quoteAll(decrypted), PARSE_HEADERS, 30000);
    } catch (e) {
        return null;
    }
    if (!resp || resp.code !== 200 || !resp.url) return null;
    const finalUrl = ldmaxDecrypt(resp.url, 0);
    if (finalUrl && /^https?:\/\//.test(finalUrl)) {
        return { url: finalUrl, type: resp.type || 'video' };
    }
    return null;
}

function checkPlayUrl(content) {
    return /https?:\/\/.*(?:\.(?:mp4|m3u8|flv|avi|mkv|ts|mov|wmv|webm)|lyyytv\.cn\/)/i.test(content);
}

// ====================== TVBox 接口 ======================

async function init(cfg) {}

async function home(filter) {
    const data = await getJson(`${HOST}/api.php/app/nav?token=`);
    const keys = ['class', 'area', 'lang', 'year', 'letter', 'by', 'sort'];
    const classes = [];
    const filters = {};
    for (const item of data.list) {
        const ext = item.type_extend || {};
        const tid = String(item.type_id);
        classes.push({ type_id: tid, type_name: item.type_name });
        const arr = [];
        for (const k of Object.keys(ext)) {
            if (keys.indexOf(k) < 0) continue;
            const raw = String(ext[k] || '').trim();
            if (raw === '') continue;
            const value = raw
                .split(',')
                .map((v) => v.trim())
                .filter((v) => v !== '')
                .map((v) => ({ n: v, v: v }));
            arr.push({ key: k, name: k, value: value });
        }
        if (arr.length > 0) filters[tid] = arr;
    }
    return JSON.stringify({ class: classes, filters: filters });
}

async function homeVod() {
    const data = await getJson(`${HOST}/api.php/app/index_video?token=`);
    let videos = [];
    for (const item of data.list) {
        videos = videos.concat(item.vlist || []);
    }
    return JSON.stringify({ list: videos });
}

async function category(tid, pg, filter, extend) {
    pg = pg || 1;
    extend = extend || {};
    const q = [`tid=${tid}`, `pg=${pg}`, 'limit=18'];
    for (const k of ['class', 'area', 'lang', 'year']) {
        if (extend[k]) q.push(`${k}=${encodeURIComponent(extend[k])}`);
    }
    const data = await getJson(`${HOST}/api.php/app/video?` + q.join('&'));
    if (data.page === undefined) data.page = Number(pg);
    if (!data.list) data.list = [];
    return JSON.stringify(data);
}

async function search(wd, quick, pg) {
    pg = pg || 1;
    const data = await getJson(`${HOST}/api.php/app/search?text=${encodeURIComponent(wd)}&pg=${pg}`);
    const list = data.list || [];
    for (const item of list) delete item.type;
    return JSON.stringify({ list: list, page: Number(pg) });
}

async function detail(id) {
    const vid = Array.isArray(id) ? id[0] : id;
    const data = (await getJson(`${HOST}/api.php/app/video_detail?id=${vid}`)).data;
    const show = [];
    const playUrls = [];
    for (const p of data.vod_url_with_player || []) {
        const parts = [];
        for (const j of String(p.url).split('#')) {
            if (!j) continue;
            const idx = j.indexOf('$');
            if (idx < 0) continue;
            parts.push(`${j.slice(0, idx)}$${lvdou(j.slice(idx + 1))}`);
        }
        playUrls.push(parts.join('#'));
        show.push(String(p.name).trim());
    }
    delete data.vod_url_with_player;
    data.vod_play_from = show.join('$$$');
    data.vod_play_url = playUrls.join('$$$');
    return JSON.stringify({ list: [data] });
}

async function play(flag, id, flags) {
    // 直接删除 %XX 百分号编码(与 Python 版一致)
    let vid = String(id).replace(/%[0-9A-Fa-f]{2}/g, '');
    const isPlain = /^https?:\/\//.test(vid);
    if (!isPlain || vid.indexOf('lyyytv.cn') >= 0) {
        const parsed = await ldmaxParse(vid);
        if (parsed) {
            return JSON.stringify({ parse: 0, jx: 0, playUrl: '', url: parsed.url, header: HEADERS });
        }
    }
    if (checkPlayUrl(vid)) {
        return JSON.stringify({ parse: 0, jx: 0, playUrl: '', url: vid, header: HEADERS });
    }
    // 其他情况交给盒子外置解析
    return JSON.stringify({ parse: 1, jx: 1, playUrl: '', url: vid, header: HEADERS });
}

export function __jsEvalReturn() {
    return {
        init: init,
        home: home,
        homeVod: homeVod,
        category: category,
        detail: detail,
        play: play,
        search: search,
    };
}
