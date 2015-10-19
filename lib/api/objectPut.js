'use strict';

const utils = require('../utils.js');
const services = require('../services.js');
const dataConnect = services.dataConnect;
const metadataConnect = services.metadataConnect;
const async = require('async');

/**
 * PUT Object in the requested bucket. Steps include:
 * validating metadata for authorization, bucket and object existence etc.
 * store object data in datastore upon successful authorization
 * store object location returned by datastore and object's (custom) headers in metadata
 * return the result in final callback
 *
 * @param  {string}   accessKey - user access key
 * @param  {datastore}   datastore - data storage endpoint
 * @param  {metastore}   metastore - metadata storage endpoint
 * @param  {request}   request   - request object given by router, includes normalized headers
 * @param  {Function} callback  - final callback to call with the result
 */
let objectPut = function (accessKey, datastore, metastore, request, callback) {
    let bucketname = utils.getResourceNames(request).bucket;
    let objectKey = utils.getResourceNames(request).object;
    let contentMD5 = request.calculatedMD5;
    let metaHeaders = utils.getMetaHeaders(request.lowerCaseHeaders);
    let objectUID = utils.getResourceUID(request.namespace, bucketname + objectKey);
    let bucketUID = utils.getResourceUID(request.namespace, bucketname);
    let metadataValParams = {accessKey: accessKey, bucketUID: bucketUID, objectKey: objectKey, metastore: metastore};
    let dataStoreParams = {contentMD5: contentMD5, headers: request.lowerCaseHeaders, value: request.post, objectUID: objectUID};
    let metadataStoreParams = {objectKey: objectKey, accessKey: accessKey, objectUID: objectUID, metaHeaders: metaHeaders, headers: request.lowerCaseHeaders, contentMD5: contentMD5};

    async.waterfall([
            function (next) {
                services.metadataValidateAuthorization(metadataValParams, next);
            },
            function (bucket, objectMetadata, next) {
                services.dataStore(bucket, objectMetadata, datastore, dataStoreParams, next);
            },
            function (bucket, objectMetadata, newLocation, next) {
                services.metadataStoreObject(bucket, objectMetadata, newLocation, metastore, metadataStoreParams, next);
            }
    ], function (err, result) {
        return callback(err, result);
    });

};


module.exports = objectPut;