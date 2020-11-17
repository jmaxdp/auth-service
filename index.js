const {
  AuthenticationDetails,
  CognitoUserPool,
  CognitoUser,
  CognitoUserAttribute,
  CognitoAccessToken
} = require("amazon-cognito-identity-js");

class AWSManager {
  constructor(UserPoolId, ClientId) {
    this.pool = new CognitoUserPool({ UserPoolId, ClientId });
  }

  authorizeUser(idToken) {
    return new Promise((resolve, reject) => {
      const AccessToken = new CognitoAccessToken({
        AccessToken: idToken
      });
      if (!AccessToken.payload.name) reject(new Error('Invalid Token'));
      else resolve(AccessToken);
    });
  }

  authenticate(Username, Password) {
    return new Promise((resolve, reject) => {
      const authDetails = new AuthenticationDetails({
        Username,
        Password
      });
      const cognitoUser = new CognitoUser({
        Username,
        Pool:this.pool
      });
      cognitoUser.authenticateUser(authDetails, {
        onSuccess: result => {
          console.log("Full result obj: ", result);
          resolve(result);
        },

        onFailure: err => {
          console.log("onfailure: ", err);
          reject(err);
        },
        mfaRequired: codeDeliveryDetails => {
          const verificationCode = prompt("Please input verification code", "");
          cognitoUser.sendMFACode(verificationCode, this);
          reject(new Error("Please input verification code"));
        }
      });
    });
  }

  forgotPassword(Username, ResetData) {
    return new Promise((resolve, reject) => {
      const cognitoUser = new CognitoUser({
        Username,
        Pool:this.pool
      });
      cognitoUser.forgotPassword({
        onSuccess: result => {
          console.log("Full result obj: ", result);
          resolve(result);
        },

        onFailure: err => {
          console.log("onfailure: ", err);
          reject(err);
        },
        inputVerificationCode: codeDeliveryDetails => {
          console.log('Code details: ', codeDeliveryDetails);
          // const verificationCode = prompt("Please input verification code", "");
          // cognitoUser.sendMFACode(verificationCode, this);
          // reject(new Error("Please input verification code"));
          const { code, password } = ResetData;
          if (code && password) {
            console.log('Code sent: ', code);
            cognitoUser.confirmPassword(code, password, {
              onFailure: err => {
                reject(err);
              },
              onSuccess: () => {
                resolve(cognitoUser);
              }
            });
          } else {
            reject(new Error('verification'));
          }
        }
      });
    });
  }

  signUp(data) {
    return new Promise((resolve, reject) => {
      const { email, name, password } = data;
      const attributeList = [];
      const dataEmail = {
        Name: "email",
        Value: email
      };
      const dataPersonalName = {
        Name: "name",
        Value: name
      };
      const attributeEmail = new CognitoUserAttribute(dataEmail);
      const attributePersonalName = new CognitoUserAttribute(dataPersonalName);
      attributeList.push(attributeEmail);
      attributeList.push(attributePersonalName);
      this.pool.signUp(email, password, attributeList, null, (err, result) => {
        if (err) {
          return reject(err);
        }
        const cognitoUser = result.user;
        console.log("user name is " + cognitoUser.getUsername());
        resolve(cognitoUser);
      });
    });
  }
}

module.exports = AWSManager;
