import config from '../Config';
import inMemory from './in_memory/backend';
import common from './common';

let client;
let implName;

if (config.backends.kms === 'mem') {
    client = inMemory;
    implName = 'memoryKms';
} else if (config.backends.kms === 'file') {
    throw new Error('KMS backend not implemented');    
} else if (config.backends.kms === 'scality') {
    throw new Error('KMS backend not implemented');
}


const KMS = {

    //cb(err, bucketKeyId: string)
    createBucketKey: (bucketName, log, cb) => {
        log.debug('creating a new bucket key');
        client.createBucketKey(bucketName, log, (err, bucketKeyId) => {
            if (err) {
                log.warn('error from kms', { implName, error: err });
                return cb(err);
            }
            log.trace('bucket key created in kms');
            return cb(null, bucketKeyId);
        });
    },

    createDataKey: () => {
        log.debug('creating a new data key');
        let newKey = common.createDataKey();
        log.trace('data key created by the kms');
        return newKey;
    },

    createSalt: () => {
        log.debug('creating a new salt value');
        let newSalt = common.createSalt();
        log.trace('salt value created by the kms');
        return newSalt;
    },
    
    //cb(err, cipheredDataKey: Buffer)
    cipherDataKey: (bucketKeyId, plainTextDataKey, log, cb) => {
        log.debug('ciphering a data key');
        client.cipherDataKey(bucketKeyId, plainTextDataKey, log,
                             (err, cipheredDataKey) => {
            if (err) {
                log.warn('error from kms', { implName, error: err });
                return cb(err);
            }
            log.trace('data key ciphered by the kms');
            return cb(null, cipheredDataKey);
        });
    },

    //cb(err, plainTextDataKey: Buffer)
    decipherDataKey: (bucketKeyId, cipheredDataKey, log, cb) => {
        log.debug('deciphering a data key');
        client.decipherDataKey(bucketKeyId, cipheredDataKey, log,
                               (err, plainTextDataKey) => {
            if (err) {
                log.warn('error from kms', { implName, error: err });
                return cb(err);
            }
            log.trace('data key deciphered by the kms');
            return cb(null, plainTextDataKey);
        });
    },

    //cb(err, cipher: ReadWritable.stream)
    createCipher: (dataKey, salt, offset, log, cb) => {
        log.debug('creating a cipher');
        common.createCipher(dataKey, salt, offset, log, (err, cipher) => {
            if (err) {
                log.warn('error from kms', { implName, error: err });
                return cb(err);
            }
            log.trace('cipher created by the kms');
            return cb(null, cipher);
        });
    },

    //cb(err, decipher: ReadWritable.stream)
    createDecipher: (dataKey, salt, offset, log, cb) => {
        log.debug('creating a decipher');
        common.createCipher(dataKey, salt, offset, log, (err, decipher) => {
            if (err) {
                log.warn('error from kms', { implName, error: err });
                return cb(err);
            }
            log.trace('decipher created by the kms');
            return cb(null, decipher);
        });
    },

};

export default KMS;
