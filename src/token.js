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
            console.log('_generateToken->claims->',claims);
            console.log('_generateToken->privateKey->',privateKey);
            console.log('_generateToken->keyid->',keyid);
            // Sign the claims using the private key
            console.log('_generateToken->jwt.sign->',jwt.sign);
            try {
                jwt.sign(claims, privateKey, {
                    algorithm: 'ES256',
                    keyid: keyid
                }, function(err, token) {
                    console.log('_generateToken->err->',err);
                    console.log('_generateToken->token->',token);
                    console.log('_generateToken->resolve->',resolve);
                    if (err) {
                        reject("AppleAuth Error – Error occurred while signing: " + err);
                    }
                    resolve(token);
                });                
            } catch (e) {
                console.log('error al firmar',e);
                reject("AppleAuth Error – Error occurred al firmar: " + e);    
            }

        }
        );
    };
    
AppleClientSecret.prototype.generate = function() {
    var self = this;        
    return new Promise (
        function(resolve, reject) {
            console.log('generate->_privateKeyLocation->',self._privateKeyLocation);
            var privateKey;
            try {
                privateKey = self._privateKeyLocation ? fs.readFileSync(self._privateKeyLocation) : self._privateKeyString;
                console.log('generate->privateKey->',privateKey);
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
                console.log('token->',token);
                console.log('resolve->',resolve);
                resolve(token);
            }).catch(function(err) {
                console.log('err->',err);
                reject(err);
            });
        
        }
    );
};    



module.exports = AppleClientSecret;
