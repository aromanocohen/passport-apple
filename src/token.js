var jwt = require('jsonwebtoken');
var fs = require('fs');
var me = null;

function AppleClientSecret(config, privateKeyLocation, privateKeyString) {
    this._config = config;
    this._privateKeyLocation = privateKeyLocation;
    this._privateKeyString = privateKeyString;
    this.generate = this.generate.bind(this);
    this._generateToken = this._generateToken.bind(this);
    me = this;
}

AppleClientSecret.prototype._generateToken = function(clientId, teamId, privateKey, exp, keyid) {
    return new Promise (
        function(resolve, reject) {
            // Curate the claims
            const claims = {
                iss: teamId,
                iat: Math.floor(Date.now() / 1000),
                exp: exp,
                aud: 'https://appleid.apple.com',
                sub: clientId,
            };
            // Sign the claims using the private key
            jwt.sign(claims, privateKey, {
                algorithm: 'ES256',
                keyid: keyid
            }, function(err, token) {
                if (err) {
                    reject("AppleAuth Error – Error occurred while signing: " + err);
                }
                resolve(token);
            });
        }
        );
    };
    
AppleClientSecret.prototype.generate = function() {
    var self = me;        
    return new Promise (
        function(resolve, reject) {
            var privateKey;
            try {
                privateKey = self._privateKeyLocation ? fs.readFileSync(self._privateKeyLocation) : self._privateKeyString;
            } catch (err) {
                return reject("AppleAuth Error - Couldn't read your Private Key file: " + err);
            }

            var exp = Math.floor(Date.now() / 1000) + ( 86400 * 180 ); // Make it expire within 6 months
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
};    



module.exports = AppleClientSecret;
