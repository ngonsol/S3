import crypto from 'crypto';

const common = {

    createDataKey: () => {
        /* AES-256 Key */
        return crypto.randomBytes(32);
    },

    createSalt: () => {
        return crypto.randomBytes(8);
    },
    
    _incrementIV: (derivedIV, counter) => {
        let newIV = derivedIV.copy();
        let len = derivedIV.length;
        let i = len - 1;
        while (counter !== 0) {
            let mod = (counter + newIV[i]) % 256;
            counter = Math.floor((counter + newIV[i]) / 256);
            newIV[i] = mod;
            i -= 1;
            if (i < 0) {
                i = len - 1;
            }
        }
        return newIV;
    },
    
    //cb(err, derivedKey, derivedIV)
    _deriveKey: (dataKey, salt, log, cb) => {
        const iterations = 1;
        const keySize = 256;
        crypto.pbkdf2(dataKey, salt, iterations, keySize, 'sha1', (err, derivedKey) => {
            if (err) {
                cb(err);
                return;
            }
            crypto.pbkdf2(derivedKey, salt, iterations, keySize, 'sha1', (err, derivedIV) => {
                if (err) {
                    cb(err);
                    return;
                }
                cb(null, derivedKey, derivedIV);
            });
        });
    },

    //cb(err, decipher: ReadWritable.stream)
    createDecipher: (dataKey, salt, offset, log, cb) => {
        this._deriveKey(dataKey, salt, log, (err, derivedKey, derivedIV) => {
            if (err) {
                cb(err);
                return;
            }
            const iv = this._incrementIV(derivedIV, offset);
            let cipher = crypto.createDecipheriv('aes-256-ctr', derivedKey, iv);
            cb(null, cipher);
        });
    },

    //cb(err, cipher: ReadWritable.stream)
    createCipher: (dataKey, salt, offset, log, cb) => {
        //aes-256-ctr decipher is both ways
        this.creadeDecipher(dataKey, salt, offset, log, cb);
    },


};

export default common;
