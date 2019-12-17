var Buffer = require('buffer/').Buffer  // note: the trailing slash is important!
var argon2 = require('./argon2-wasm-pro/lib/argon2')  // note: the trailing slash is important!
var ed25519 = require('ed25519-wasm-pro')  // note: the trailing slash is important!
var crypto = require('./crypto')  // note: the trailing slash is important!
const bs58check = require("./bs58check");

/* 封装Accounts类 */
function encodeAccount(pub) {
    let version = Buffer.from([0x01]);
    let v_pub = Buffer.concat([version, pub]);
    return "czr_" + bs58check.encode(v_pub);
}
let Accounts = function (dev) {
    if (dev) {
        //如果是测试环境
        this.COSTNUM = 256;
    } else {
        this.COSTNUM = 16 * 1024;
    }
};
async function createAccount(password, COSTNUM) {
    let kdf_salt = crypto.randomBytes(16);
    let iv = crypto.randomBytes(16);
    let privateKey = crypto.randomBytes(32);

    //测试的
    // let kdf_salt = Buffer.from("AF8460A7D28A396C62D6C51620B87789", "hex");
    // let iv = Buffer.from("A695DDC35ED9F3183A09FED1E6D92083", "hex");
    // let privateKey = Buffer.from("5E844EE4D2E26920F8B0C4B7846929057CFCE48BF40BA269B173648999630053", "hex");

    //password hashing
    let kdf_option = {
        pass: password.toString(),
        salt: kdf_salt,
        type: argon2.argon2id,
        time: 1,
        mem: COSTNUM,
        parallelism: 1,
        hashLen: 32
    };

    try {
        let derivePwd = await argon2.hash(kdf_option);
        let cipher = crypto.createCipheriv("aes-256-ctr", Buffer.from(derivePwd.hash.buffer), iv);//加密方法aes-256-ctr
        let ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);

        let promise = new Promise(function (resolve, reject) {
            try {
                // 生成公钥
                ed25519.ready(function () {
                    const keypair = ed25519.createKeyPair(privateKey)
                    let publicKey = Buffer.from(keypair.publicKey.buffer);
                    crypto.randomBytes(32);
                    crypto.randomBytes(32);
                    let accFile = {
                        account: encodeAccount(publicKey),
                        kdf_salt: kdf_salt.toString('hex').toUpperCase(),
                        iv: iv.toString('hex').toUpperCase(),
                        ciphertext: ciphertext.toString('hex').toUpperCase()
                    }
                    resolve(accFile)
                })
            } catch (e) {
                reject(e)
            }
        });
        return promise;
    } catch (err) {
        throw err;
    }

}

async function decryptAccount(keystore, password, COSTNUM) {
    keystore.kdf_salt = Buffer.from(keystore.kdf_salt, "hex");
    keystore.iv = Buffer.from(keystore.iv, "hex");
    keystore.ciphertext = Buffer.from(keystore.ciphertext, "hex");

    let kdf_option = {
        pass: password.toString(),
        salt: keystore.kdf_salt,
        type: argon2.argon2id,
        time: 1,
        mem: COSTNUM,
        parallelism: 1,
        hashLen: 32,

        // raw: true,
        // version: 0x13
    };

    //password hashing
    try {
        let derivePwd = await argon2.hash(kdf_option);
        //从ciphertext解密私钥
        let decipher = crypto.createDecipheriv("aes-256-ctr", Buffer.from(derivePwd.hash.buffer), keystore.iv);
        let privateKey = Buffer.concat([decipher.update(keystore.ciphertext), decipher.final()]);
        return privateKey.toString('hex').toUpperCase();
    } catch (err) {
        throw err;
    }

}

function signBlock(block, privateKey) {
    let promise = new Promise(function (resolve, reject) {
        try {
            ed25519.ready(function () {
                block = Buffer.from(block, "hex");
                privateKey = Buffer.from(privateKey, "hex");
                const keys = ed25519.createKeyPair(privateKey)
                let signature = ed25519.sign(block, keys.publicKey, keys.secretKey)
                let result = Buffer.from(signature.buffer).toString('hex').toUpperCase();
                resolve(result);
            })
        } catch (e) {
            reject(e)
        }
    });
    return promise;
}

async function validateAccount(keystore, password, COSTNUM) {
    let prv1 = await decryptAccount(keystore, password, COSTNUM);
    let promise = new Promise(function (resolve, reject) {
        try {
            ed25519.ready(function () {
                const keypair = ed25519.createKeyPair(Buffer.from(prv1, "hex"))
                let compare = Buffer.from(keypair.publicKey.buffer);
                if (encodeAccount(compare) === keystore.account) {
                    resolve(true);
                } else {
                    resolve(false);
                }
            })
        } catch (e) {
            reject(e)
        }
    });
    return promise;
}


/*
* 创建账户
* parame: pwd
* return: account object
*
{
    "account":"czr_3M3dbuG3hWoeykQroyhJssdS15Bzocyh7wryG75qUWDxoyzBca",
    "kdf_salt":"xxx",
    "iv":"xxxx",
    "ciphertext":"xxxx"
}
*/

/**
 * create account
 * @param password - account password
 * @return Promise{accountFile | Error} - accountFile { account, kdf_salt, iv, ciphertext }
 * */
Accounts.prototype.create = function (password) {
    return createAccount(password, this.COSTNUM);
};

/*
* 验证keystore文件
* parame: keystore pwd
* return: boolena
* */
Accounts.prototype.validateAccount = function (key, password) {
    return validateAccount(key, password, this.COSTNUM);
};

/*
* 解密账户私钥
* parame: keystore pwd
* return: privateKey
*
* */
Accounts.prototype.decrypt = async function (keystore, password) {
    let isValidate = await validateAccount(keystore, password, this.COSTNUM);
    if (isValidate) {
        return decryptAccount(keystore, password, this.COSTNUM)
    } else {
        let exception = new Error("Parameter (password)'s value invalid");
        throw exception;
    }
};

/*
* 签名
* parame: block,privateKey
* return: signature
* */
Accounts.prototype.sign = async function (block, privateKey) {
    return await signBlock(block, privateKey);

};

module.exports = Accounts;