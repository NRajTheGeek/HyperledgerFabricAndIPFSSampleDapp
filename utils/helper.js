/**
 * Copyright 2017 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an 'AS IS' BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
"use strict";
var log4js = require("log4js");
var logger = log4js.getLogger("Helper");
logger.level = "DEBUG";

var path = require("path");
var util = require("util");
var fs = require("fs-extra");
var User = require("fabric-client/lib/User.js");
var crypto = require("crypto");
var copService = require("fabric-ca-client");
var bcrypt = require("bcrypt");
var hfc = require("fabric-client");
hfc.setLogger(logger);
var ORGS = hfc.getConfigSetting("network-config");
var NodeRSA = require("node-rsa");

var userModel = require("../models/users");
var docModel = require("../models/documents");

var clients = {};
var channels = {};
var caClients = {};

// set up the client and channel objects for each org
for (let key in ORGS) {
  if (key.indexOf("org") === 0) {
    let client = new hfc();

    let cryptoSuite = hfc.newCryptoSuite();
    cryptoSuite.setCryptoKeyStore(
      hfc.newCryptoKeyStore({ path: getKeyStoreForOrg(ORGS[key].name) })
    );
    client.setCryptoSuite(cryptoSuite);

    let channel = client.newChannel(hfc.getConfigSetting("channelName"));
    channel.addOrderer(newOrderer(client));

    clients[key] = client;
    channels[key] = channel;

    setupPeers(channel, key, client);

    let caUrl = ORGS[key].ca;
    caClients[key] = new copService(
      caUrl,
      null /*defautl TLS opts*/,
      "" /* default CA */,
      cryptoSuite
    );
  }
}

function getErrorMessage(field) {
  var response = {
    success: false,
    message: field + " field is missing or Invalid in the request"
  };
  return response;
}

function setupPeers(channel, org, client) {
  for (let key in ORGS[org].peers) {
    let data = fs.readFileSync(
      path.join(__dirname, ORGS[org].peers[key]["tls_cacerts"])
    );
    let peer = client.newPeer(ORGS[org].peers[key].requests, {
      pem: Buffer.from(data).toString(),
      "ssl-target-name-override": ORGS[org].peers[key]["server-hostname"]
    });
    peer.setName(key);

    channel.addPeer(peer);
  }
}

function newOrderer(client) {
  var caRootsPath = ORGS.orderer.tls_cacerts;
  let data = fs.readFileSync(path.join(__dirname, caRootsPath));
  let caroots = Buffer.from(data).toString();
  return client.newOrderer(ORGS.orderer.url, {
    pem: caroots,
    "ssl-target-name-override": ORGS.orderer["server-hostname"]
  });
}

function readAllFiles(dir) {
  var files = fs.readdirSync(dir);
  var certs = [];
  files.forEach(file_name => {
    let file_path = path.join(dir, file_name);
    let data = fs.readFileSync(file_path);
    certs.push(data);
  });
  return certs;
}

function getOrgName(org) {
  return ORGS[org].name;
}

function getKeyStoreForOrg(org) {
  return hfc.getConfigSetting("keyValueStore") + "_" + org;
}

function newRemotes(names, forPeers, userOrg) {
  let client = getClientForOrg(userOrg);

  let targets = [];
  // find the peer that match the names
  for (let idx in names) {
    let peerName = names[idx];
    if (ORGS[userOrg].peers[peerName]) {
      // found a peer matching the name
      let data = fs.readFileSync(
        path.join(__dirname, ORGS[userOrg].peers[peerName]["tls_cacerts"])
      );
      let grpcOpts = {
        pem: Buffer.from(data).toString(),
        "ssl-target-name-override":
          ORGS[userOrg].peers[peerName]["server-hostname"]
      };

      if (forPeers) {
        targets.push(
          client.newPeer(ORGS[userOrg].peers[peerName].requests, grpcOpts)
        );
      } else {
        let eh = client.newEventHub();
        eh.setPeerAddr(ORGS[userOrg].peers[peerName].events, grpcOpts);
        targets.push(eh);
      }
    }
  }

  if (targets.length === 0) {
    logger.error(
      util.format("Failed to find peers matching the names %s", names)
    );
  }

  return targets;
}

//-------------------------------------//
// APIs
//-------------------------------------//
var getChannelForOrg = function(org) {
  return channels[org];
};

var getClientForOrg = function(org) {
  return clients[org];
};

var newPeers = function(names, org) {
  return newRemotes(names, true, org);
};

var newEventHubs = function(names, org) {
  return newRemotes(names, false, org);
};

var getMspID = function(org) {
  logger.debug("Msp ID : " + ORGS[org].mspid);
  return ORGS[org].mspid;
};

var getAdminUser = function(userOrg) {
  var users = hfc.getConfigSetting("admins");
  var username = users[0].username;
  var password = users[0].secret;
  var member;
  var client = getClientForOrg(userOrg);

  return hfc
    .newDefaultKeyValueStore({
      path: getKeyStoreForOrg(getOrgName(userOrg))
    })
    .then(store => {
      client.setStateStore(store);
      // clearing the user context before switching
      client._userContext = null;
      return client.getUserContext(username, true).then(user => {
        if (user && user.isEnrolled()) {
          logger.info("Successfully loaded member from persistence");
          return user;
        } else {
          let caClient = caClients[userOrg];
          // need to enroll it with CA server
          return caClient
            .enroll({
              enrollmentID: username,
              enrollmentSecret: password
            })
            .then(enrollment => {
              logger.info("Successfully enrolled user '" + username + "'");
              member = new User(username);
              member.setCryptoSuite(client.getCryptoSuite());
              return member.setEnrollment(
                enrollment.key,
                enrollment.certificate,
                getMspID(userOrg)
              );
            })
            .then(() => {
              return client.setUserContext(member);
            })
            .then(() => {
              return member;
            })
            .catch(err => {
              logger.error(
                "Failed to enroll and persist user. Error: " + err.stack
                  ? err.stack
                  : err
              );
              return null;
            });
        }
      });
    });
};

var generateRSAKeyPair = function() {
  return new Promise((resolve, reject) => {
    var key = new NodeRSA();
    // 512 bit RSA key is more than enough for this demo
    key.generateKeyPair(512);

    var pub_k = key.exportKey("pkcs8-public-pem");
    var pri_k = key.exportKey("pkcs8-private-pem");

    var keyPair = {
      RSAPrivateKey: pri_k,
      RSAPublicKey: pub_k
    };
    resolve({
      err: null,
      data: keyPair
    });
  });
};

var getCaClientForOrg = function(org) {
  return caClients[org];
};

var getRegisteredUsers = function(username, userOrg, isJson) {
  var member;
  var client = getClientForOrg(userOrg);
  var enrollmentSecret = null;
  return hfc
    .newDefaultKeyValueStore({
      path: getKeyStoreForOrg(getOrgName(userOrg))
    })
    .then(store => {
      client.setStateStore(store);
      // clearing the user context before switching
      client._userContext = null;
      return client.getUserContext(username, true).then(user => {
        if (user && user.isEnrolled()) {
          logger.info("Successfully loaded member from persistence");
          return user;
        } else {
          let caClient = caClients[userOrg];
          return getAdminUser(userOrg)
            .then(function(adminUserObj) {
              member = adminUserObj;
              return caClient.register(
                {
                  enrollmentID: username,
                  affiliation: userOrg + ".department1"
                },
                member
              );
            })
            .then(
              secret => {
                enrollmentSecret = secret;
                logger.debug(username + " registered successfully");
                return caClient.enroll({
                  enrollmentID: username,
                  enrollmentSecret: secret
                });
              },
              err => {
                logger.debug(username + " failed to register");
                return "" + err;
                //return 'Failed to register '+username+'. Error: ' + err.stack ? err.stack : err;
              }
            )
            .then(message => {
              if (
                message &&
                typeof message === "string" &&
                message.includes("Error:")
              ) {
                logger.error(username + " enrollment failed");
                return message;
              }
              logger.debug(username + " enrolled successfully");

              member = new User(username);
              member._enrollmentSecret = enrollmentSecret;
              return member.setEnrollment(
                message.key,
                message.certificate,
                getMspID(userOrg)
              );
            })
            .then(
              () => {
                client.setUserContext(member);
                return member;
              },
              err => {
                logger.error(
                  util.format(
                    "%s enroll failed: %s",
                    username,
                    err.stack ? err.stack : err
                  )
                );
                return "" + err;
              }
            );
        }
      });
    })
    .then(
      user => {
        if (isJson && isJson === true) {
          var response = {
            success: true,
            secret: user._enrollmentSecret,
            message: username + " enrolled Successfully"
          };
          return response;
        }
        return user;
      },
      err => {
        logger.error(
          util.format(
            "Failed to get registered user: %s, error: %s",
            username,
            err.stack ? err.stack : err
          )
        );
        return "" + err;
      }
    );
};
/**
 * TODO: add functionality
 */
var saveUserContextToDB = function(userContext) {};

var getOrgAdmin = function(userOrg) {
  var admin = ORGS[userOrg].admin;
  var keyPath = path.join(__dirname, admin.key);
  var keyPEM = Buffer.from(readAllFiles(keyPath)[0]).toString();
  var certPath = path.join(__dirname, admin.cert);
  var certPEM = readAllFiles(certPath)[0].toString();

  var client = getClientForOrg(userOrg);
  var cryptoSuite = hfc.newCryptoSuite();
  if (userOrg) {
    cryptoSuite.setCryptoKeyStore(
      hfc.newCryptoKeyStore({ path: getKeyStoreForOrg(getOrgName(userOrg)) })
    );
    client.setCryptoSuite(cryptoSuite);
  }

  return hfc
    .newDefaultKeyValueStore({
      path: getKeyStoreForOrg(getOrgName(userOrg))
    })
    .then(store => {
      client.setStateStore(store);

      return client.createUser({
        username: "peer" + userOrg + "Admin",
        mspid: getMspID(userOrg),
        cryptoContent: {
          privateKeyPEM: keyPEM,
          signedCertPEM: certPEM
        }
      });
    });
};

var setupChaincodeDeploy = function() {
  process.env.GOPATH = path.join(
    __dirname,
    hfc.getConfigSetting("CC_SRC_PATH")
  );
};

var getLogger = function(moduleName) {
  var logger = log4js.getLogger(moduleName);
  logger.level - "DEBUG";
  return logger;
};

bcrypt.genSaltPromised = util.promisify(bcrypt.genSalt);

var getSalt = function(saltRounds) {
  return new Promise((resolve, reject) => {
    bcrypt
      .genSaltPromised(saltRounds)
      .then(salt => {
        resolve({
          err: null,
          data: salt
        });
      })
      .catch(err => {
        reject({ err: err, data: null });
      });
  });
};

bcrypt.hashPromised = util.promisify(bcrypt.hash);

var generateHash = function(toBeHashed, salt) {
  return new Promise((resolve, reject) => {
    bcrypt
      .hashPromised(toBeHashed, salt)
      .then(hash => {
        resolve({
          err: null,
          data: hash
        });
      })
      .catch(err => {
        reject({
          err: err,
          data: null
        });
      });
  });
};

var hashingData = function(toBeHashed) {
  return new Promise((resolve, reject) => {
    const saltRounds = 10;

    getSalt(saltRounds)
      .then(saltOb => {
        return generateHash(toBeHashed, saltOb.data);
      })
      .then(resultOb => {
        resolve({
          err: null,
          data: resultOb.data
        });
      })
      .catch(errOb => {
        reject({
          err: errOb.err,
          data: null
        });
      });
  });
};

var checkAndPersistUser = function(userName, userData) {
  return new Promise((resolve, reject) => {
    userModel.getUserByUserName(userName).then(async userDetail => {
      if (userDetail.data) {
        resolve({
          err: null,
          data: "user already saved"
        });
      } else {
        var users = await userModel.getUsers();
        users.data[userName] = userData;
        let ret = await userModel.saveUser(users.data);

        resolve({
          err: null,
          data: ret.data
        });
      }
    });
  });
};

var checkAndPersistDoc = function(docHash, docJSON) {
  return new Promise((resolve, reject) => {
    docModel.getDocumentsByDocHash(docHash).then(async docDetail => {
      if (docDetail.data) {
        resolve({
          err: null,
          data: "doc already saved"
        });
      } else {
        var docs = await docModel.getDocuments();
        docs.data[docHash] = docJSON[docHash];
        let ret = await docModel.saveDocument(docs.data);

        resolve({
          err: null,
          data: ret.data
        });
      }
    });
  });
};

var checkAndPersistDocument = function(docHash, docData) {
  return new Promise((resolve, reject) => {
    docModel.getDocumentsByDocHash(docHash).then(async docDetail => {
      if (docDetail.data) {
        resolve({
          err: null,
          data: "doc already saved"
        });
      } else {
        var docs = await docModel.getDocuments();
        docs.data[docHash] = docData;
        let ret = await docModel.saveUser(docs.data);

        resolve({
          err: null,
          data: ret.data
        });
      }
    });
  });
};

var getAdminUser = function(org) {
  var users = hfc.getConfigSetting("admins");

  var uuid = users[0].username;
  var password = users[0].secret;

  var member;
  var client = getClientForOrg(org);

  return hfc
    .newDefaultKeyValueStore({
      path: getKeyStoreForOrg(getOrgName(org))
    })
    .then(store => {
      client.setStateStore(store);
      // clearing the user context before switching
      client._userContext = null;
      return client.getUserContext(uuid, true).then(user => {
        if (user && user.isEnrolled()) {
          logger.info("Successfully loaded member from persistence");
          return user;
        } else {
          let caClient = caClients[org];
          // need to enroll it with CA server
          return caClient
            .enroll({
              enrollmentID: uuid,
              enrollmentSecret: password
            })
            .then(enrollment => {
              logger.info("Successfully enrolled user '" + uuid + "'");
              client;
              member = new User(uuid);
              member.setCryptoSuite(client.getCryptoSuite());
              return member.setEnrollment(
                enrollment.key,
                enrollment.certificate,
                getMspID(org)
              );
            })
            .then(() => {
              return client.setUserContext(member);
            })
            .then(() => {
              return member;
            })
            .catch(err => {
              logger.error(
                "Failed to enroll and persist user. Error: " + err.stack
                  ? err.stack
                  : err
              );
              return null;
            });
        }
      });
    })
    .catch(function(err) {
      logger.error(
        "Error: Coud not get the key store for user:" + uuid + err.stack
          ? err.stack
          : err
      );

      returnResponse(
        false,
        "Error: Coud not get the key store for user: " + uuid,
        err
      );
    });
};

var returnResponse = function(status, message, error) {
  return (response = {
    success: status,
    message: message,
    error: error
  });
};

var aesSymmetricEncryption = function(key, data) {
  return crypto.createCipher("aes-256-ctr", key).update(data, "ust8", "hex");
};

var aesSymmetricDecryption = function(encryptedData, key) {
  if (typeof encryptedData == "undefined" || encryptedData.length <= 0) {
    throw new Error("data must not be defined");
  }

  if (typeof key == "undefined" || key.length <= 0) {
    throw new Error("key must not be defined");
  }

  return crypto
    .createDecipher("aes-256-ctr", key)
    .update(encryptedData, "hex", "utf-8");
};

module.exports = {
  generateRSAKeyPair,
  hashingData,
  getAdminUser,
  getKeyStoreForOrg,
  getOrgName,
  getCaClientForOrg,
  checkAndPersistUser,
  checkAndPersistDoc,
  checkAndPersistDocument,

  getChannelForOrg,
  getClientForOrg,
  getLogger,
  setupChaincodeDeploy,
  getMspID,
  ORGS,
  newPeers,
  newEventHubs,
  getRegisteredUsers,
  getOrgAdmin,
  getErrorMessage,
  aesSymmetricEncryption,
  aesSymmetricDecryption
};
