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
'use strict';
var log4js = require('log4js');
var logger = log4js.getLogger('SampleWebApp');
var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var http = require('http');
var util = require('util');
var app = express();
var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');
var bearerToken = require('express-bearer-token');
var cors = require('cors');

require('./config.js');
var hfc = require('fabric-client');

var helper = require('./app/helper.js');
var createChannel = require('./app/create-channel.js');
var join = require('./app/join-channel.js');
var install = require('./app/install-chaincode.js');
var instantiate = require('./app/instantiate-chaincode.js');
var invoke = require('./app/invoke-transaction.js');
var query = require('./app/query.js');
var channelConfig = require('./app/get-channel-config.js');
var host = process.env.HOST || hfc.getConfigSetting('host');
var port = process.env.PORT || hfc.getConfigSetting('port');
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// SET CONFIGURATONS ////////////////////////////
///////////////////////////////////////////////////////////////////////////////
app.options('*', cors());
app.use(cors());
//support parsing of application/json type post data
app.use(bodyParser.json());
//support parsing of application/x-www-form-urlencoded post data
app.use(bodyParser.urlencoded({
	extended: false
}));
// set secret variable
app.set('secret', 'thisismysecret');
app.use(expressJWT({
	secret: 'thisismysecret'
}).unless({
	path: ['/users']
}));
app.use(bearerToken());
app.use(function(req, res, next) {
	logger.debug(' ------>>>>>> new request for %s',req.originalUrl);
	if (req.originalUrl.indexOf('/users') >= 0) {
		return next();
	}

	var token = req.token;
	jwt.verify(token, app.get('secret'), function(err, decoded) {
		if (err) {
			res.send({
				success: false,
				message: 'Failed to authenticate token. Make sure to include the ' +
					'token returned from /users call in the authorization header ' +
					' as a Bearer token'
			});
			return;
		} else {
			// add the decoded user name and org name to the request object
			// for the downstream code to use
			req.username = decoded.username;
			req.orgname = decoded.orgName;
			logger.debug(util.format('Decoded from JWT token: username - %s, orgname - %s', decoded.username, decoded.orgName));
			return next();
		}
	});
});

///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// START SERVER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
var server = http.createServer(app).listen(port, function() {});
logger.info('****************** SERVER STARTED ************************');
logger.info('***************  http://%s:%s  ******************',host,port);
server.timeout = 240000;

function getErrorMessage(field) {
	var response = {
		success: false,
		message: field + ' field is missing or Invalid in the request'
	};
	return response;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////// REST ENDPOINTS START HERE ///////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Register and enroll user
app.post('/users', async function(req, res) {
	var username = req.body.username;
	var orgName = req.body.orgName;
	logger.debug('End point : /users');
	logger.debug('User name : ' + username);
	logger.debug('Org name  : ' + orgName);
	if (!username) {
		res.json(getErrorMessage('\'username\''));
		return;
	}
	if (!orgName) {
		res.json(getErrorMessage('\'orgName\''));
		return;
	}
	var token = jwt.sign({
		exp: Math.floor(Date.now() / 1000) + parseInt(hfc.getConfigSetting('jwt_expiretime')),
		username: username,
		orgName: orgName
	}, app.get('secret'));
	let response = await helper.getRegisteredUser(username, orgName, true);
	logger.debug('-- returned from registering the username %s for organization %s',username,orgName);
	if (response && typeof response !== 'string') {
		logger.debug('Successfully registered the username %s for organization %s',username,orgName);
		response.token = token;
		res.json(response);
	} else {
		logger.debug('Failed to register the username %s for organization %s with::%s',username,orgName,response);
		res.json({success: false, message: response});
	}

});
// Create Channel
app.post('/channels', async function(req, res) {
	logger.info('<<<<<<<<<<<<<<<<< C R E A T E  C H A N N E L >>>>>>>>>>>>>>>>>');
	logger.debug('End point : /channels');
	var channelName = req.body.channelName;
	var channelConfigPath = req.body.channelConfigPath;
	logger.debug('Channel name : ' + channelName);
	logger.debug('channelConfigPath : ' + channelConfigPath); //../artifacts/channel/mychannel.tx
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!channelConfigPath) {
		res.json(getErrorMessage('\'channelConfigPath\''));
		return;
	}

	let message = await createChannel.createChannel(channelName, channelConfigPath, req.username, req.orgname);
	res.send(message);
});
// Join Channel
app.post('/channels/:channelName/peers', async function(req, res) {
	logger.info('<<<<<<<<<<<<<<<<< J O I N  C H A N N E L >>>>>>>>>>>>>>>>>');
	var channelName = req.params.channelName;
	var peers = req.body.peers;
	logger.debug('channelName : ' + channelName);
	logger.debug('peers : ' + peers);
	logger.debug('username :' + req.username);
	logger.debug('orgname:' + req.orgname);

	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!peers || peers.length == 0) {
		res.json(getErrorMessage('\'peers\''));
		return;
	}

	let message =  await join.joinChannel(channelName, peers, req.username, req.orgname);
	res.send(message);
});

app.post('/query/config/:channelName', async function(req, res){
  logger.info('<<<<<<<<<<<<<<<<< G E T C O N F I G  O F  C H A N N E L >>>>>>>>>>>>>>>>>');
	var channelName = req.params.channelName;
	logger.debug('channelName : ' + channelName);
	logger.debug('username :' + req.username);
	logger.debug('orgname:' + req.orgname);

	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}


  let message = await channelConfig.getChannelConfig(channelName, req.username, req.orgname);
  res.send(message);
});

app.post('/query/genesis/:channelName', async function(req, res){
  logger.info('<<<<<<<<<<<<<<<<< G E T G E N E S I S  O F  C H A N N E L >>>>>>>>>>>>>>>>>');
	var channelName = req.params.channelName;
	logger.debug('channelName : ' + channelName);
	logger.debug('username :' + req.username);
	logger.debug('orgname:' + req.orgname);

	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}


  let message = await channelConfig.getChannelGenesis(channelName, req.username, req.orgname);
  res.send(message);
});

// Install chaincode on target peers
app.post('/chaincodes', async function(req, res) {
	logger.debug('==================== INSTALL CHAINCODE ==================');
	var peers = req.body.peers;
	var chaincodeName = req.body.chaincodeName;
	var chaincodePath = req.body.chaincodePath;
	var chaincodeVersion = req.body.chaincodeVersion;
	var chaincodeType = req.body.chaincodeType;
	logger.debug('peers : ' + peers); // target peers list
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('chaincodePath  : ' + chaincodePath);
	logger.debug('chaincodeVersion  : ' + chaincodeVersion);
	logger.debug('chaincodeType  : ' + chaincodeType);
	if (!peers || peers.length == 0) {
		res.json(getErrorMessage('\'peers\''));
		return;
	}
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!chaincodePath) {
		res.json(getErrorMessage('\'chaincodePath\''));
		return;
	}
	if (!chaincodeVersion) {
		res.json(getErrorMessage('\'chaincodeVersion\''));
		return;
	}
	if (!chaincodeType) {
		res.json(getErrorMessage('\'chaincodeType\''));
		return;
	}
	let message = await install.installChaincode(peers, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, req.username, req.orgname)
	res.send(message);});
// Instantiate chaincode on target peers
app.post('/channels/:channelName/chaincodes', async function(req, res) {
	logger.debug('==================== INSTANTIATE CHAINCODE ==================');
	var peers = req.body.peers;
	var chaincodeName = req.body.chaincodeName;
	var chaincodeVersion = req.body.chaincodeVersion;
	var channelName = req.params.channelName;
	var chaincodeType = req.body.chaincodeType;
	var fcn = req.body.fcn;
	var args = req.body.args;
	var endorsePolicy = req.body.endorsePolicy;
	logger.debug('peers  : ' + peers);
	logger.debug('channelName  : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('chaincodeVersion  : ' + chaincodeVersion);
	logger.debug('chaincodeType  : ' + chaincodeType);
	logger.debug('fcn  : ' + fcn);
	logger.debug('args  : ' + args);
	logger.debug('endorsePolicy  : ' + endorsePolicy);
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!chaincodeVersion) {
		res.json(getErrorMessage('\'chaincodeVersion\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!chaincodeType) {
		res.json(getErrorMessage('\'chaincodeType\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}
	if (!endorsePolicy) {
		res.json(getErrorMessage('\'endorsePolicy\''));
		return;
	}

	let message = await instantiate.instantiateChaincode(peers, channelName, chaincodeName, chaincodeVersion, chaincodeType, fcn, args, req.username, req.orgname, endorsePolicy);
	res.send(message);
});
// Invoke transaction on chaincode on target peers
app.post('/channels/:channelName/chaincodes/:chaincodeName', async function(req, res) {
	logger.debug('==================== INVOKE ON CHAINCODE ==================');
	var peers = req.body.peers;
	var chaincodeName = req.params.chaincodeName;
	var channelName = req.params.channelName;
	var fcn = req.body.fcn;
	var args = req.body.args;
	logger.debug('channelName  : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('fcn  : ' + fcn);
	logger.debug('args  : ' + args);
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!fcn) {
		res.json(getErrorMessage('\'fcn\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}

	let message = await invoke.invokeChaincode(peers, channelName, chaincodeName, fcn, args, req.username, req.orgname);
	res.send(message);
});
// Query on chaincode on target peers
app.get('/channels/:channelName/chaincodes/:chaincodeName', async function(req, res) {
	logger.debug('==================== QUERY BY CHAINCODE ==================');
	var channelName = req.params.channelName;
	var chaincodeName = req.params.chaincodeName;
	let args = req.query.args;
	let fcn = req.query.fcn;
	let peer = req.query.peer;

	logger.debug('channelName : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('fcn : ' + fcn);
	logger.debug('args : ' + args);

	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!fcn) {
		res.json(getErrorMessage('\'fcn\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}
	args = args.replace(/'/g, '"');
	args = JSON.parse(args);
	logger.debug(args);

	let message = await query.queryChaincode(peer, channelName, chaincodeName, args, fcn, req.username, req.orgname);
	res.send(message);
});
//  Query Get Block by BlockNumber
app.get('/channels/:channelName/blocks/:blockId', async function(req, res) {
	logger.debug('==================== GET BLOCK BY NUMBER ==================');
	let blockId = req.params.blockId;
	let peer = req.query.peer;
	logger.debug('channelName : ' + req.params.channelName);
	logger.debug('BlockID : ' + blockId);
	logger.debug('Peer : ' + peer);
	if (!blockId) {
		res.json(getErrorMessage('\'blockId\''));
		return;
	}

	let message = await query.getBlockByNumber(peer, req.params.channelName, blockId, req.username, req.orgname);
	res.send(message);
});
// Query Get Transaction by Transaction ID
app.get('/channels/:channelName/transactions/:trxnId', async function(req, res) {
	logger.debug('================ GET TRANSACTION BY TRANSACTION_ID ======================');
	logger.debug('channelName : ' + req.params.channelName);
	let trxnId = req.params.trxnId;
	let peer = req.query.peer;
	if (!trxnId) {
		res.json(getErrorMessage('\'trxnId\''));
		return;
	}

	let message = await query.getTransactionByID(peer, req.params.channelName, trxnId, req.username, req.orgname);
	res.send(message);
});
// Query Get Block by Hash
app.get('/channels/:channelName/blocks', async function(req, res) {
	logger.debug('================ GET BLOCK BY HASH ======================');
	logger.debug('channelName : ' + req.params.channelName);
	let hash = req.query.hash;
	let peer = req.query.peer;
	if (!hash) {
		res.json(getErrorMessage('\'hash\''));
		return;
	}

	let message = await query.getBlockByHash(peer, req.params.channelName, hash, req.username, req.orgname);
	res.send(message);
});
//Query for Channel Information
app.get('/channels/:channelName', async function(req, res) {
	logger.debug('================ GET CHANNEL INFORMATION ======================');
	logger.debug('channelName : ' + req.params.channelName);
	let peer = req.query.peer;

	let message = await query.getChainInfo(peer, req.params.channelName, req.username, req.orgname);
	res.send(message);
});
//Query for Channel instantiated chaincodes
app.get('/channels/:channelName/chaincodes', async function(req, res) {
	logger.debug('================ GET INSTANTIATED CHAINCODES ======================');
	logger.debug('channelName : ' + req.params.channelName);
	let peer = req.query.peer;

	let message = await query.getInstalledChaincodes(peer, req.params.channelName, 'instantiated', req.username, req.orgname);
	res.send(message);
});
// Query to fetch all Installed/instantiated chaincodes
app.get('/chaincodes', async function(req, res) {
	var peer = req.query.peer;
	var installType = req.query.type;
	logger.debug('================ GET INSTALLED CHAINCODES ======================');

	let message = await query.getInstalledChaincodes(peer, null, 'installed', req.username, req.orgname)
	res.send(message);
});
// Query to fetch channels
app.get('/channels', async function(req, res) {
	logger.debug('================ GET CHANNELS ======================');
	logger.debug('peer: ' + req.query.peer);
	var peer = req.query.peer;
	if (!peer) {
		res.json(getErrorMessage('\'peer\''));
		return;
	}

	let message = await query.getChannels(peer, req.username, req.orgname);
	res.send(message);
});

app.post('/query', async function (req, res) {
    // query(req.body).then((rs)=>{
    //   console.log("####"+rs);
    //   res.setHeader('Content-Type', 'application/json');
    //   res.json(JSON.parse(rs))
    // }).catch((err) => {
    //   console.log("err>"+err);
    //   res.send(err.toString());
  	// });

		console.log(req.body);
		var peers = ['peer0.ktb.cert.com'];
		var channelName = req.body.chainId;
		var chaincodeName = req.body.chaincodeId;
		var fcn = req.body.fcn;
		var args = req.body.args;

		let message = await query.queryChaincode(peer, channelName, chaincodeName, args, fcn, req.username, req.orgname);
		res.send(message);

});

app.post('/invoke', async function (req, res) {
        // invoke(req.body).then((rs)=>{
        //   res.send(rs);
        // }).catch((err) => {
        //   console.log("err>"+err);
        //   res.send(err.toString());
      	// });

				console.log(req.body);
				var peers = ['peer0.ind.cert.com', 'peer0.ktb.cert.com', 'peer0.cml.cert.com', 'peer0.pol.cert.com'];
				var channelName = req.body.chainId;
				var chaincodeName = req.body.chaincodeId;
				var fcn = req.body.fcn;
				var args = req.body.args;

				let message = await invoke.invokeChaincode(peers, channelName, chaincodeName, fcn, args, req.username, req.orgname);
				res.send(message);
});

// function invoke(request){
//   return Fabric_Client.newDefaultKeyValueStore({ path: store_path
//   }).then((state_store) => {
//   	// assign the store to the fabric client
//   	fabric_client.setStateStore(state_store);
//   	var crypto_suite = Fabric_Client.newCryptoSuite();
//   	// use the same location for the state store (where the users' certificate are kept)
//   	// and the crypto store (where the users' keys are kept)
//   	var crypto_store = Fabric_Client.newCryptoKeyStore({path: store_path});
//   	crypto_suite.setCryptoKeyStore(crypto_store);
//   	fabric_client.setCryptoSuite(crypto_suite);
//
//   	// get the enrolled user from persistence, this user will sign all requests
//   	return fabric_client.getUserContext('user1', true);
//   }).then((user_from_store) => {
//   	if (user_from_store && user_from_store.isEnrolled()) {
//   		console.log('Successfully loaded user1 from persistence');
//   		member_user = user_from_store;
//   	} else {
//   		throw new Error('Failed to get user1.... run registerUser.js');
//   	}
//
//   	// get a transaction id object based on the current user assigned to fabric client
//   	tx_id = fabric_client.newTransactionID();
//   	console.log("Assigning transaction_id: ", tx_id._transaction_id);
// request.txId = tx_id
//   	// var request = {
//   	// 	chaincodeId: 'fabcar',
//   	// 	fcn: 'newCar',
//   	// 	args: ['CAR13', 'Honda', 'Accord', 'Black', 'Gun'],
//   	// 	chainId: 'mychannel',
//   	// 	txId: tx_id
//   	// };
//
//   	// send the transaction proposal to the peers
//   	return channel.sendTransactionProposal(request);
//   }).then((results) => {
//   	var proposalResponses = results[0];
//   	var proposal = results[1];
//   	let isProposalGood = false;
//   	if (proposalResponses && proposalResponses[0].response &&
//   		proposalResponses[0].response.status === 200) {
//   			isProposalGood = true;
//   			console.log('Transaction proposal was good');
//   		} else {
//   			console.error('Transaction proposal was bad');
//   		}
//   	if (isProposalGood) {
//   		console.log(util.format(
//   			'Successfully sent Proposal and received ProposalResponse: Status - %s, message - "%s"',
//   			proposalResponses[0].response.status, proposalResponses[0].response.message));
//
//   		// build up the request for the orderer to have the transaction committed
//   		var request = {
//   			proposalResponses: proposalResponses,
//   			proposal: proposal
//   		};
//
//   		// set the transaction listener and set a timeout of 30 sec
//   		// if the transaction did not get committed within the timeout period,
//   		// report a TIMEOUT status
//   		var transaction_id_string = tx_id.getTransactionID(); //Get the transaction ID string to be used by the event processing
//   		var promises = [];
//
//   		var sendPromise = channel.sendTransaction(request);
//   		promises.push(sendPromise); //we want the send transaction first, so that we know where to check status
//
//   		// get an eventhub once the fabric client has a user assigned. The user
//   		// is required bacause the event registration must be signed
//   		let event_hub = channel.newChannelEventHub(peer);
//
//   		// using resolve the promise so that result status may be processed
//   		// under the then clause rather than having the catch clause process
//   		// the status
//   		let txPromise = new Promise((resolve, reject) => {
//   			let handle = setTimeout(() => {
//   				event_hub.unregisterTxEvent(transaction_id_string);
//   				event_hub.disconnect();
//   				resolve({event_status : 'TIMEOUT'}); //we could use reject(new Error('Trnasaction did not complete within 30 seconds'));
//   			}, 3000);
//   			event_hub.registerTxEvent(transaction_id_string, (tx, code) => {
//   				// this is the callback for transaction event status
//   				// first some clean up of event listener
//   				clearTimeout(handle);
//
//   				// now let the application know what happened
//   				var return_status = {event_status : code, tx_id : transaction_id_string};
//   				if (code !== 'VALID') {
//   					console.error('The transaction was invalid, code = ' + code);
//   					resolve(return_status); // we could use reject(new Error('Problem with the tranaction, event status ::'+code));
//   				} else {
//   					console.log('The transaction has been committed on peer ' + event_hub.getPeerAddr());
//   					resolve(return_status);
//   				}
//   			}, (err) => {
//   				//this is the callback if something goes wrong with the event registration or processing
//   				reject(new Error('There was a problem with the eventhub ::'+err));
//   			},
//   				{disconnect: true} //disconnect when complete
//   			);
//   			event_hub.connect();
//
//   		});
//   		promises.push(txPromise);
//
//   		return Promise.all(promises);
//   	} else {
//   		console.error('Failed to send Proposal or receive valid response. Response null or status is not 200. exiting...', results[0][0]);
//   		throw new Error(results[0][0]);
//   	}
//   }).then((results) => {
//   	console.log('Send transaction promise and event listener promise have completed');
//   	// check the results in the order the promises were added to the promise all list
//   	if (results && results[0] && results[0].status === 'SUCCESS') {
//   		console.log('Successfully sent transaction to the orderer.');
//   	} else {
//   		console.error('Failed to order the transaction. Error code: ' + results[0].status);
//   	}
//
//   	if(results && results[1] && results[1].event_status === 'VALID') {
//   		console.log('Successfully committed the change to the ledger by the peer');
//   	} else {
//   		console.log('Transaction failed to be committed to the ledger due to ::'+results[1].event_status);
//   	}
//     // return results[0].status;
//     return tx_id._transaction_id;
//   }).catch((err) => {
//   	console.error('Failed to invoke successfully :: ' + err);
//     return 'Failed to invoke successfully :: ' + err
//   });
// }
//
// function query(request){
//
// 	return Fabric_Client.newDefaultKeyValueStore({ path: store_path
// 	}).then((state_store) => {
// 		// assign the store to the fabric client
// 		fabric_client.setStateStore(state_store);
// 		var crypto_suite = Fabric_Client.newCryptoSuite();
// 		// use the same location for the state store (where the users' certificate are kept)
// 		// and the crypto store (where the users' keys are kept)
// 		var crypto_store = Fabric_Client.newCryptoKeyStore({path: store_path});
// 		crypto_suite.setCryptoKeyStore(crypto_store);
// 		fabric_client.setCryptoSuite(crypto_suite);
//
// 		// get the enrolled user from persistence, this user will sign all requests
// 		return fabric_client.getUserContext('user1', true);
// 	}).then((user_from_store) => {
// 		if (user_from_store && user_from_store.isEnrolled()) {
// 			console.log('Successfully loaded user1 from persistence');
// 			member_user = user_from_store;
// 		} else {
// 			throw new Error('Failed to get user1.... run registerUser.js');
// 		}
//
// 		// queryCar chaincode function - requires 1 argument, ex: args: ['CAR4'],
// 		// queryAllCars chaincode function - requires no arguments , ex: args: [''],
// 		// const request = {
// 		// 	//targets : --- letting this default to the peers assigned to the channel
// 		// 	chaincodeId: 'fabcar',
// 		// 	fcn: 'queryAllCars',
// 		// 	args: ['']
// 		// };
//
// 		// send the query proposal to the peer
// 		return channel.queryByChaincode(request);
// 	}).then((query_responses) => {
// 		console.log("Query has completed, checking results");
// 		// query_responses could have more than one  results if there multiple peers were used as targets
// 		if (query_responses && query_responses.length == 1) {
// 			if (query_responses[0] instanceof Error) {
// 				console.error("error from query = ", query_responses[0]);
//       		throw new Error("error from query = "+ query_responses[0]);
// 			} else {
//         query_rs = query_responses[0].toString();
// 				console.log("Response >> ", query_rs);
//         return query_rs;
// 			}
// 		} else {
// 			console.log("No payloads were returned from query");
// 		}
// 	}).catch((err) => {
// 		console.error('Failed to query successfully :: ' + err);
//     throw new Error("error from query = "+ err);
// 	});
