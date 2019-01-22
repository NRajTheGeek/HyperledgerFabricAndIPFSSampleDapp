var async = require("async");
var hfc = require("fabric-client");
const User = require("fabric-client/lib/User.js");
var helper = require("./helper");
var log4js = require("log4js");
var logger = log4js.getLogger("Helper");

var registerUserService = function(uuid, org, isJson) {
  return new Promise((resolve, reject) => {
    var client;
    try {
      client = helper.getClientForOrg(org);
    } catch (err) {
      logger.error(err.stack ? err.stack : err);
      return reject({
        err: new Error("error getting client for org."),
        data: null
      });
    }

    enrollUser(client, uuid, org)
      .then(enrolleOb => {
        var user = enrolleOb.data;
        if (user._enrollmentSecret === "") {
          var response = {
            success: false,
            message: "user enrollment failed"
          };
          // toward the next then in the chain
          return response;
        } else {
          // return generateResponse(user, uuid, org, callback, isJson);
          return generateResponse(user, uuid, org, isJson);
        }
      })
      .then(enrolleOb => {
        resolve({
          err: null,
          data: enrolleOb.data
        });
      })
      .catch(errOb => {
        resolve({
          err: errOb.err,
          data: null
        });
      });
  });
};

var enrollUser = function(client, uuid, org) {
  return new Promise((resolve, reject) => {
    var member;

    var enrollmentSecret = null;
    hfc
      .newDefaultKeyValueStore({
        path: helper.getKeyStoreForOrg(helper.getOrgName(org))
      })
      .then(store => {
        client.setStateStore(store);
        client._userContext = null;

        return client.getUserContext(uuid, true).then(user => {
          // if (user && user.isEnrolled()) {_enrollmentSecret
          if (user && user._enrollmentSecret.length > 0) {
            logger.info("Successfully loaded member from persistence");

            user.isEnrolled = true;
            return user;
          } else {
            let caClient = helper.getCaClientForOrg(org);
            return helper
              .getAdminUser(org)
              .then(function(adminUserObj) {
                member = adminUserObj;
                return caClient.register(
                  {
                    enrollmentID: uuid,
                    affiliation: org + ".department1"
                  },
                  member
                );
              })
              .then(
                secret => {
                  enrollmentSecret = secret;
                  logger.debug(uuid + " registered successfully");

                  return caClient.enroll({
                    enrollmentID: uuid,
                    enrollmentSecret: secret
                  });
                },
                err => {
                  logger.debug(uuid + " failed to register");

                  if (!err || err === undefined) {
                    err = new Error(uuid + " failed to register");
                  } else {
                    err.message =
                      uuid + " failed to register: " + err.message
                        ? err.message
                        : err;
                  }

                  reject({
                    err: err,
                    data: null
                  });
                }
              )
              .then(message => {
                if (
                  message &&
                  typeof message === "string" &&
                  message.includes("Error:")
                ) {
                  logger.error(uuid + " enrollment failed");

                  reject({
                    err: new Error(uuid + " enrollment failed"),
                    data: null
                  });
                }

                logger.debug(uuid + " enrolled successfully");
                member = new User(uuid);
                member._enrollmentSecret = enrollmentSecret;

                return member.setEnrollment(
                  message.key,
                  message.certificate,
                  helper.getMspID(org)
                );
              })
              .then(
                () => {
                  client.setUserContext(member);
                  return member;
                },
                err => {
                  logger.error(
                    uuid + " enroll failed: " + err.stack ? err.stack : err
                  );
                  if (!err || err === undefined) {
                    err = new Error("enroll failed: " + uuid);
                  } else {
                    err.message =
                      uuid + " enroll failed: " + err.message
                        ? err.message
                        : err;
                  }

                  reject({
                    err: err,
                    data: null
                  });
                }
              );
          }
        });
      })
      .then(user => {
        if (!user || user === undefined) {
          reject({
            err: new Error("An error occured in user registeration!!"),
            data: null
          });
        } else {
          resolve({ err: null, data: user });
        }
      })
      .catch(err => {
        reject({
          err: new Error("An error occured in user registeration!!"),
          data: null
        });
      });
  });
};

var generateResponse = function(user, uuid, org, isJson) {
  return new Promise(async (resolve, reject) => {
    if (user.isEnrolled === true) {
      if (!isJson || isJson === false) {
        return user;
      } else {
        var response = {
          success: false,
          message: "User already exists."
        };
        resolve({ err: null, data: response });
      }
    } else {
      if (isJson && isJson === true) {
        var response = {
          secret: user._enrollmentSecret,
          message: uuid + " enrolled Successfully"
        };

        resolve({
          err: null,
          data: response
        });

        //====================================================================================================

        keyPair = await helper.generateRSAKeyPair();
        var pub_k = keyPair.data.RSAPublicKey;
        var pri_k = keyPair.data.RSAPrivateKey;

        logger.debug(
          "\n==================================== pub_k   \n" + pub_k
        );

        logger.debug(
          "\n==================================== pri_k   \n" + pri_k
        );

        var encryptedRSAPrivKey = helper.aesSymmetricEncryption(
          user._enrollmentSecret,
          pri_k
        );
        logger.debug(
          "\n==================================== encryptedRSAPrivKey   \n" +
            encryptedRSAPrivKey
        );

        var content = {};
        content.rsaPublicKey = pub_k;
        content.encryptedRsaPrivKey = encryptedRSAPrivKey;

        //====================================================================================================
        helper
          .hashingData(user._enrollmentSecret)
          .then(async hashedEnrollmentOb => {
            logger.debug(
              " \n =========================================== \n hashedEnrollmentOb.data:   " +
                hashedEnrollmentOb.data
            );

            var userData = {
              secret: hashedEnrollmentOb.data,
              privRSA: encryptedRSAPrivKey,
              pubRSA: pub_k,
              org: org
            };
            console.log('before save');
            
            await helper.checkAndPersistUser(uuid, userData);
            // return hashedEnrollmentOb.data;
            /*
            // TODO: this needs to be implemented
            userDbOpsUtility.persistUser(
            uuid,
            org,
            hashedEnrollmentOb.data,
            content.rsaPublicKey,
            content.encryptedRsaPrivKey,
            results,
            _next
            );
            
            logger.info(results.persistUser)
            */
          })
          .catch(errOb => {
            reject({
              err:
                "Failed to get public key from keystore of user: " +
                uuid +
                " error: " +
                errOb.err,
              data: null
            });
          });
      } else {
        reject(new Error("user cretaion error!!, contact admin."));
      }
    }
  });
};

module.exports = {
  registerUserService
};
