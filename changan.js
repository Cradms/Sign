/*
 * 脚本名称：长安汽车（changan.js）
 * 功能：自动抓取 token 并执行每日签到
 *
 * Quantumult X 配置：
 *
 * [MITM]
 * hostname = wxapi.uni.changan.com.cn
 *
 * [rewrite_local]
 * # 拦截获取用户信息的请求，执行脚本来保存 token
 * ^https?:\/\/wxapi\.uni\.changan\.com\.cn\/user\/home\/info url script-request-header https://raw.githubusercontent.com/Cradms/Sign/main/changan.js
 *
 * [task_local]
 * # 每天定时执行签到任务
 * 0 0 10 * * ? https://raw.githubusercontent.com/Cradms/Sign/main/changan.js, tag=长安汽车签到
 *
 */

// ====== 加密和签名函数 ======
const CryptoJS = require('crypto-js');
const NodeRSA = require('node-rsa'); // 纯JS的RSA库，可能需要在QX中手动引入
const Base64 = require('base-64');

// 生成16位随机字符串作为AES密钥
function generate_random_key(length = 16) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// AES加密，key和iv
function aes_encrypt(text, key) {
    const keyBytes = CryptoJS.enc.Utf8.parse(key);
    const iv = keyBytes;
    const padded = CryptoJS.enc.Utf8.parse(text);
    const encrypted = CryptoJS.AES.encrypt(padded, keyBytes, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString(CryptoJS.enc.Base64);
}

// RSA加密key生成codeEncryptedStr
function rsa_encrypt(text) {
    const public_key = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCd0x5KWJKH+99QIvadRgvaYxD1
HXxwvy/v7H0AYLu/CCaKGGZERtNJiar8d2LcYeeD5FQ+/9bwX5pNnxefwMQgLHyt
xpGsKO/pIjrSytZX1bvNA6WIWbGH/an//md/cBXOQvq1hrNsKfwdZWIOgIj1N5MY
cc7cLPLJToq2XqpP9QIDAQAB
-----END PUBLIC KEY-----`;

    const rsa = new NodeRSA(public_key, 'pkcs1-public-pem');
    const encrypted = rsa.encrypt(text, 'base64');
    return encrypted;
}

// 生成sign，MD5加密paramEncryptedStr参数 + 时间戳 + 固定字符串并转大写
function generate_sign(param_str, timestamp) {
    const sign_str = `${param_str}${timestamp}hyzh-unistar-5KWJKH291IvadR`;
    const hash = CryptoJS.MD5(sign_str);
    return hash.toString(CryptoJS.enc.Hex).toUpperCase();
}

// ============================================

// 主入口
if (typeof $request !== 'undefined') {
    // === MIMT 模式：抓取 token ===
    const headers = $request.headers;
    const token = headers['token'] || headers['Token'];

    if (token) {
        const savedToken = $prefs.valueForKey('changan_token');
        if (token !== savedToken) {
            $prefs.setValueForKey(token, 'changan_token');
            $notification.post("长安汽车", "Token 更新成功 🎉", "新 Token 已保存，可继续自动签到。");
            console.log(`[长安汽车] Token 更新成功: ${token}`);
        } else {
            console.log(`[长安汽车] Token 未变化，无需更新。`);
        }
    } else {
        console.log(`[长安汽车] 未在请求头中找到 Token。`);
    }
    $done();
} else {
    // === 定时任务模式：执行签到 ===
    const token = $prefs.valueForKey('changan_token');

    if (!token) {
        $notification.post("长安签到失败", "Token 不存在", "请进入长安小程序个人主页重新获取 Token。");
        $done();
        return;
    }

    send_request(token);
}


// 发送签到请求的函数
function send_request(token) {
    const body = "{}";
    const random_key = generate_random_key();
    const timestamp = Date.now();
     
    const param_encrypted_str = aes_encrypt(body, random_key);
    const code_encrypted_str = rsa_encrypt(random_key);
    const sign = generate_sign(JSON.stringify({"paramEncryptedStr": param_encrypted_str}), timestamp);
     
    const headers = {
        "Content-Type": "application/json",
        "timestamp": String(timestamp),
        "codeEncryptedStr": code_encrypted_str,
        "sign": sign,
        "token": token,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) XWEB/8555"
    };
     
    const data = {
        "paramEncryptedStr": param_encrypted_str
    };
     
    const request = {
        url: "https://wxapi.uni.changan.com.cn/user/signIn",
        method: "POST",
        headers: headers,
        body: JSON.stringify(data)
    };
     
    $task.fetch(request).then(response => {
        const title = "长安汽车签到";
        try {
            const result = JSON.parse(response.body);
            if (result.code === 200) {
                $notification.post(title, "签到成功 ✅", `获得积分：${result.data.addIntegral}，连续签到天数：${result.data.serialDay}`);
            } else {
                $notification.post(title, "签到失败 ❌", `原因：${result.msg}`);
            }
        } catch (e) {
            $notification.post(title, "签到结果解析失败", `状态码: ${response.statusCode}`);
        }
        $done();
    }, reason => {
        $notification.post("长安签到", "请求失败 ❌", `错误信息: ${reason.error}`);
        $done();
    });
}
