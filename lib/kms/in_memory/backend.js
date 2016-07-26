import common from '../common';

export const kms = [];
let count = 1;
const serverSalt = new Buffer('bravo!');

export const backend = {
    /*
     * Target implementation will be async in some aspects. let mimic it
     */

    //cb(err, bucketKeyId: string)
    createBucketKey: function createBucketKeyMem(bucketName, log, cb) {
        process.nextTick(() => {
            kms[count] = common.createDataKey();
            cb(null, count++);
        });
    },
    
    //cb(err, cipheredDataKey: Buffer)
    cipherDataKey: function cipherDataKeyMem(bucketKeyId, plainTextDataKey, log, cb) {
        process.nextTick(() => {
            common.createCipher(kms[bucketKeyId], serverSalt, 0, log, (err, cipher) => {
                let cipheredDataKey = cipher.update(plainTextDataKey);
                cipheredDataKey += cipher.final();
                cb(null, cipheredDataKey);
            });
        });
    },

    //cb(err, plainTextDataKey: Buffer)
    decipherDataKey: function decipherDataKeyMem(bucketKeyId, cipheredDataKey, log, cb) {
        process.nextTick(() => {
            common.createDecipher(kms[bucketKeyId], serverSalt, 0, log, (err, decipher) => {
                let plainTextDataKey = decipher.update(cipheredDataKey);
                plainTextDataKey += decipher.final();
                cb(null, plainTextDataKey);
            });
        });
    },

};

export default backend;
