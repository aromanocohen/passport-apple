/**
 * Generates a client secret for Apple auth
 * using the private key.
 * @author: Ananay Arora <i@ananayarora.com>
 */

//const jwt = require('jsonwebtoken');
//const fs = require('fs');

//class AppleClientSecret {
    
    /**
     * 
     * @param {object} config 
     * @param {string} config.client_id 
     * @param {string} config.team_id 
     * @param {string} config.redirect_uri 
     * @param {string} config.key_id 
     * @param {string} privateKeyLocation 
     * @param {string} privateKeyString
     */
    /*constructor(config, privateKeyLocation, privateKeyString) {
        this._config = config;
        this._privateKeyLocation = privateKeyLocation;
        this._privateKeyString = privateKeyString;
        this.generate = this.generate.bind(this);
        this._generateToken = this._generateToken.bind(this);
    }*/
    
    /**
     * Generates the JWT token
     * @param {string} clientId 
     * @param {string} teamId 
     * @param {string} privateKey 
     * @param {int} expiration 
     * @returns {Promise<string>} token 
     */
    /*_generateToken(clientId, teamId, privateKey, exp, keyid) {
        return new Promise (
            function(resolve, reject) {
                // Curate the claims
                const claims = {
                    iss: teamId,
                    iat: Math.floor(Date.now() / 1000),
                    exp,
                    aud: 'https://appleid.apple.com',
                    sub: clientId,
                };
                // Sign the claims using the private key
                jwt.sign(claims, privateKey, {
                    algorithm: 'ES256',
                    keyid
                }, function(err, token) {
                    if (err) {
                        reject("AppleAuth Error – Error occurred while signing: " + err);
                    }
                    resolve(token);
                });
            }
            );
        }*/
        
    /**
     * Reads the private key file calls 
     * the token generation method
     * @returns {Promise<string>} token - The generated client secret
     */
    /*generate() {
        return new Promise (
            var self = this;
            function(resolve, reject) {
                let privateKey;
                try {
                    privateKey = self._privateKeyLocation ? fs.readFileSync(self._privateKeyLocation) : self._privateKeyString;
                } catch (err) {
                    return reject("AppleAuth Error - Couldn't read your Private Key file: " + err);
                }

                let exp = Math.floor(Date.now() / 1000) + ( 86400 * 180 ); // Make it expire within 6 months
                self._generateToken(
                    self._config.client_id, 
                    self._config.team_id, 
                    privateKey,
                    exp, 
                    self._config.key_id
                ).then(function(token) {
                    resolve(token);
                }).catch(function(err) {
                    reject(err);
                });
            
            }
        );
    }*/
//}

//module.exports = AppleClientSecret;