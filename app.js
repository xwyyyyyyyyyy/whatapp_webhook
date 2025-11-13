// Import Express.js and crypto
const express = require('express');
const crypto = require('crypto');

// Create an Express app
const app = express();

// Middleware to parse JSON bodies and preserve raw body
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appSecret = process.env.APP_SECRET;

/**
 * 验证 Facebook webhook 请求的签名
 * @param {string} rawBody - 原始请求体（字符串格式）
 * @param {string} signature - X-Hub-Signature-256 header 的值（包含 sha256= 前缀）
 * @param {string} secret - Facebook App Secret
 * @returns {boolean} - 验证是否通过
 */
function verifyWebhookSignature(rawBody, signatureHash, secret) {
    if (!signature || !secret) {
        console.log('Missing signature or secret');
        return false;
    }

    // 从 header 中提取哈希值（去掉 "sha256=" 前缀）
    const signatureHash = signature.replace('sha256=', '');

    // 使用 HMAC-SHA256 生成哈希
    const expectedHash = crypto
        .createHmac('sha256', secret)
        .update(rawBody, 'utf8')
        .digest('hex');

    // 使用时间安全的比较函数来防止时序攻击
    const isValid = crypto.timingSafeEqual(
        Buffer.from(signatureHash, 'hex'),
        Buffer.from(expectedHash, 'hex')
    );

    return isValid;
}

// Route for GET requests
app.get('/', (req, res) => {
    const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

    if (mode === 'subscribe' && token === verifyToken) {
        console.log('WEBHOOK VERIFIED');
        res.status(200).send(challenge);
    } else {
        res.status(403).end();
    }
});

// Route for POST requests
app.post('/', (req, res) => {
    const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    console.log(`\n\nWebhook received ${timestamp}\n`);

    // 打印原始请求体
    console.log('\n=== Raw Request Body ===');
    console.log(req.rawBody);

    // 打印 X-Hub-Signature-256 header
    const signature = req.header('x-hub-signature-256');
    console.log('\n=== Request Header[X-Hub-Signature-256] ===');
    console.log(signature);

    // 提取纯哈希值（去掉 sha256= 前缀）
    const signatureHash = signature ? signature.replace('sha256=', '') : '';
    console.log(`\n=== Signature Hash (without sha256=) ===`);
    console.log(signatureHash);

    // 验证签名
    console.log(`\nverify request result: valid: ${verifyWebhookSignature(req.rawBody, signatureHash, appSecret)}`);

    // 打印解析后的 JSON body（可选，用于参考）
    console.log('\n=== Parsed JSON Body ===');
    console.log(JSON.stringify(req.body, null, 2));

    res.status(200).end();
});

// Start the server
app.listen(port, () => {
    console.log(`\nListening on port ${port}\n`);
});