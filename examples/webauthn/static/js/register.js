"use strict";
const registration_flow = () => {

    let challenge = document.getElementById("register").dataset.challenge;
    let user_id = document.getElementById("register").dataset.user_id;
    console.log(`The challenge is ${challenge}`);
    console.log(`The user id is ${user_id}`);

    const cose_alg_ECDSA_w_SHA256 = -7;

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

            challenge: new ArrayBuffer(64),

            pubKeyCredParams: [{
                type: "public-key",
                alg: cose_alg_ECDSA_w_SHA256,
            },
            {
                type: "public-key",
                alg: -257
            }],

            timeout: 60000 // Timeout after 1 minute
        }
    };


    for (let i = 0; i < challenge.len; i++) {
        createCredentialOptions.publicKey.challenge[i] = challenge.charCodeAt(i);
    }

    for (let i = 0; i < user_id.len; ++i) {
        createCredentialOptions.publicKey.user.id[i] = user_id.charCodeAt(i);
    }


    let promise = navigator.credentials.create(createCredentialOptions);
    promise.then( (res) => {
      //console.log(res);
      //console.log(typeof(res));
      //console.log(res.response);

      let data = {};
      data['id'] = res.id;
      data['rawId'] = btoa(res.rawId);
      data['response'] = {};

      // Decoding the attestationObject is useless for transmitting across the network,
      // but very useful for examining the payload which will be delivered to the server.
      let decoder = new TextDecoder('utf-8');

      // Decoding the CBOR is for debugging only:
      const decodedAttestationObject = CBOR.decode(res.response.attestationObject);
      console.log(`Decoded attestationObject: ${decodedAttestationObject}`);


      data['response']['attestationObject'] = btoa(String.fromCharCode(...new Uint8Array(res.response.attestationObject)));

      const clientDataJSON = decoder.decode(res.response.clientDataJSON);
      console.log(`decoded ClientDataJSON: ${clientDataJSON}`);
      console.log(`ClientDataJSON: ${res.response.clientDataJSON}`);
      //const chal = res.response.clientDataJSON['challenge'];
      //console.log(res.response.clientDataJSON['challenge']);

      // 'clientDataJSON' in the PubKeyCredential is a binary array, not JSON!
      // Might as well fix that here:
      data['response']['clientDataJSON'] =  JSON.parse(decoder.decode(res.response.clientDataJSON));
      data['type'] = res.type;

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
