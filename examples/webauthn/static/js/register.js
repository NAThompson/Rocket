"use strict";
const registration_flow = () => {

    let challenge = document.getElementById("register").dataset.challenge;
    let user_id = document.getElementById("register").dataset.user_id;
    console.log(`The challenge is ${challenge}`);
    console.log(`The user id is ${user_id}`);


    let createCredentialOptions = {
        publicKey: {

            // Relying Party
            rp: {
                name: "localhost", // this would be your domain name
            },

            // User
            user: {
                id: new Uint8Array(64),
                // There is no need for a username with key-based login
                name: null,
                displayName: null,
            },

            authenticatorSelection : { userVerification: "preferred"},

            attestation: 'direct',

            challenge: new Uint8Array(64),

            pubKeyCredParams: [{
                type: "public-key",
                alg: -7,
            },
            {
                type: "public-key",
                alg: -257
            }],

            timeout: 60000 // Timeout after 1 minute
        }
    };

    for (let i = 0; i < challenge.length; i++) {
        createCredentialOptions.publicKey.challenge[i] = challenge.charCodeAt(i);
    }

    for (let i = 0; i < user_id.length; ++i) {
        createCredentialOptions.publicKey.user.id[i] = user_id.charCodeAt(i);
    }


    console.log("createCredentialOptions");
    console.log(createCredentialOptions);

    let promise = navigator.credentials.create(createCredentialOptions);
    promise.then( (pubKeyCred) => {

      let data = {};
      data['id'] = pubKeyCred.id;
      data['rawId'] = btoa(pubKeyCred.rawId);
      data['response'] = {};

      let decoder = new TextDecoder('utf-8');

      // Decoding the attestationObject is for debugging only:
      /*const decodedAttestationObject = CBOR.decode(pubKeyCred.response.attestationObject);
      console.log(`Decoded attestationObject:`);
      console.log(decodedAttestationObject);
      const x5c = decodedAttestationObject.attStmt.x5c[0];
      console.log(x5c);
      console.log(btoa(x5c));

      console.log(String.fromCharCode(...new Uint8Array(x5c)));*/

      data['response']['attestationObject'] = btoa(String.fromCharCode(...new Uint8Array(pubKeyCred.response.attestationObject)));

      // 'clientDataJSON' in the PubKeyCredential is a binary array, not JSON!
      // If we wish to debug this structure client-side, we can do so with the following code:
      // const clientDataJSON = JSON.parse(decoder.decode(pubKeyCred.response.clientDataJSON));
      // console.log(`decoded ClientDataJSON:`);
      // console.log(clientDataJSON);


      data['response']['clientDataJSON'] = btoa(String.fromCharCode(...new Uint8Array(pubKeyCred.response.clientDataJSON)));
      data['type'] = pubKeyCred.type;

      // Send data to relying party's servers
      let xhr = new XMLHttpRequest();
      xhr.open('POST', '/register', true);
      xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
      xhr.send(JSON.stringify(data));

      console.log(`xhr.status = ${xhr.status}`);
      const response = xhr.responseText;
      console.log(`response = ${response}`);

    }).catch(err => {  alert(`Unable to complete registration flow, error: ${err}`); });
}
