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
var util = require('util');

var helper = require('./helper.js');
var logger = helper.getLogger('Join-Channel');

/*
 * Have an organization join a channel
 */
var getChannelConfig = async function(channel_name, username, org_name) {
	logger.debug('\n\n============ Join Channel start ============\n')
	var error_message = null;
	var all_eventhubs = [];
  var result = null;
	try {
		logger.info('Calling peers in organization "%s" to get config of the channel', org_name);

		// first setup the client for this org
		var client = await helper.getClientForOrg(org_name, username);
		logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
		var channel = client.getChannel(channel_name);
		if(!channel) {
			let message = util.format('Channel %s was not defined in the connection profile', channel_name);
			logger.error(message);
			throw new Error(message);
		}

		let channelConfig = await channel.getChannelConfigFromOrderer();
    console.log(channelConfig);
    result = channelConfig;
	} catch(error) {
		logger.error('Failed to get channel config due to error: ' + error.stack ? error.stack : error);
		error_message = error.toString();
	}

	// need to shutdown open event streams
	all_eventhubs.forEach((eh) => {
		eh.disconnect();
	});

	if (!error_message) {
		// build a response to send back to the REST caller
		let response = {
			success: true,
			message: result
		};
		return response;
	} else {
		let message = util.format('Failed to get channel config. cause:%s',error_message);
		logger.error(message);
		throw new Error(message);
	}
};

var getChannelGenesis = async function(channel_name, username, org_name) {
	logger.debug('\n\n============ Join Channel start ============\n')
	var error_message = null;
  var result = null;
	var all_eventhubs = [];
	try {
		logger.info('Calling peers in organization "%s" to get genesis of the channel', org_name);

		// first setup the client for this org
		var client = await helper.getClientForOrg(org_name, username);
		logger.debug('Successfully got the fabric client for the organization "%s"', org_name);
		var channel = client.getChannel(channel_name);
		if(!channel) {
			let message = util.format('Channel %s was not defined in the connection profile', channel_name);
			logger.error(message);
			throw new Error(message);
		}

		// next step is to get the genesis_block from the orderer,
		// the starting point for the channel that we want to join
		let request = {
			txId : 	client.newTransactionID(true) //get an admin based transactionID
		};
		let genesis_block = await channel.getGenesisBlock(request);
    result = genesis_block;

	} catch(error) {
		logger.error('Failed to get channel genesis due to error: ' + error.stack ? error.stack : error);
		error_message = error.toString();
	}

	// need to shutdown open event streams
	all_eventhubs.forEach((eh) => {
		eh.disconnect();
	});

	if (!error_message) {
		// build a response to send back to the REST caller
		let response = {
			success: true,
			genesisBlock: result
		};
		return response;
	} else {
		let message = util.format('Failed to get channel genesis. cause:%s',error_message);
		logger.error(message);
		throw new Error(message);
	}
};
exports.getChannelConfig = getChannelConfig;
exports.getChannelGenesis = getChannelGenesis;
