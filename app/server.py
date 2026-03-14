from aiohttp import web
import socketio
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId
import json
from threading import Thread
import asyncio
import base64
from jwt import (
    JWT,
    jwk_from_pem,
)
from hashlib import sha256
from base64 import urlsafe_b64encode
from random import choice
from itertools import chain
import os
import ssl
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv('MONGO_URI')
PUBLIC_KEY = os.getenv('PUBLIC_KEY')
if MONGO_URI is None:
    raise Exception("MONGO_URI is not set")
if PUBLIC_KEY is None:
    raise Exception("PUBLIC_KEY is not set")

mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_database('ztna')

sio = socketio.AsyncServer()
app = web.Application()
sio.attach(app)

public_key = base64.b64decode(PUBLIC_KEY).decode('ascii')
public_key = public_key.encode()

jwt = JWT()

connectorsToSockets = {} # connectorId: socketId
socketsToConnectors = {} # socketId: connectorId
networksToConnectors = {} # networkId: list of connectorIds
connectorsToNetworks = {} # connectorId: networkId

clientsToSockets = {}
socketsToClients = {}

async def watch_changes_in_db():
    while True:
        try:
            with db.watch(
                    full_document='whenAvailable',
                    full_document_before_change='whenAvailable'
                ) as stream:
                print("Watching changes in the database")
                for event in stream:
                    print(event)

                    if event["ns"]["coll"] == "resources" and event['operationType'] == 'update':
                        important_fields = ['address', 'alias', 'networkId', 'tcpStatus', 'udpStatus', 'icmpStatus', 'tcpPorts', 'udpPorts']
                        if 'updateDescription' not in event: continue
                        if 'updatedFields' not in event['updateDescription']: continue
                        if not any(field in event['updateDescription']['updatedFields'] for field in important_fields): continue

                        id = event['documentKey']['_id'] # get the id of the resource (ObjectId not str)

                        updated_resource = event['fullDocument']
                        network_id = updated_resource['networkId']

                        # send the updated resource to the connector
                        _id = str(id)
                        _resource = {}
                        _resource[_id] = {}

                        _resource[_id]['address'] = updated_resource['address']
                        _resource[_id]['alias'] = updated_resource['alias']
                        _resource[_id]['networkId'] = str(updated_resource['networkId'])
                        _resource[_id]['tcpStatus'] = updated_resource['tcpStatus']
                        _resource[_id]['udpStatus'] = updated_resource['udpStatus']
                        _resource[_id]['icmpStatus'] = updated_resource['icmpStatus']
                        _resource[_id]['tcpPorts'] = updated_resource['tcpPorts']
                        _resource[_id]['udpPorts'] = updated_resource['udpPorts']

                        _resource = json.dumps(_resource, default=str)

                        # get the connectors that are associated with the network
                        connector_ids = networksToConnectors.get(network_id, None)
                        if connector_ids is not None: # if there are connectors associated with the network
                            for connector_id in connector_ids:
                                # get the socket id of the connector
                                socket_id = connectorsToSockets.get(connector_id, None)
                                if socket_id is not None:
                                    await sio.emit('update_resource', {'resource': _resource}, room=socket_id)

                        # get the users and groups that are associated with the resource and push the updated resource to them
                        policies_collection = db.get_collection('policies')
                        policies = policies_collection.find({'resourceIds': {'$elemMatch': {'$eq': id}}}, {'_id': True, 'type': True, 'ids': True})

                        user_ids = []
                        group_ids = []
                        for policy in policies:
                            if policy['type'] == 'user':
                                user_ids.extend(policy['ids'])
                            elif policy['type'] == 'group':
                                group_ids.extend(policy['ids'])

                        user_ids = [ObjectId(userId) for userId in user_ids]
                        
                        users_collection = db.get_collection('users')
                        users = users_collection.find({'$or': [{'_id': {'$in': user_ids}}, {'groups': {'$elemMatch': {'$in': group_ids}}}]}, {'_id': True})

                        for user in users:
                            user_id = str(user['_id'])
                            socket_id = clientsToSockets.get(user_id, None)
                            if socket_id is not None:
                                await sio.emit('update_resource', {'resource': _resource}, room=socket_id)

                    elif event["ns"]["coll"] == "resources" and event['operationType'] == 'insert':
                        id = event['fullDocument']['_id']

                        inserted_resource = event['fullDocument']
                        network_id = inserted_resource['networkId']

                        _id = str(id)
                        _resource = {}
                        _resource[_id] = {}

                        _resource[_id]['address'] = inserted_resource['address']
                        _resource[_id]['alias'] = inserted_resource['alias']
                        _resource[_id]['networkId'] = str(inserted_resource['networkId'])
                        _resource[_id]['tcpStatus'] = inserted_resource['tcpStatus']
                        _resource[_id]['udpStatus'] = inserted_resource['udpStatus']
                        _resource[_id]['icmpStatus'] = inserted_resource['icmpStatus']
                        _resource[_id]['tcpPorts'] = inserted_resource['tcpPorts']
                        _resource[_id]['udpPorts'] = inserted_resource['udpPorts']

                        _resource = json.dumps(_resource, default=str)

                        # get the connectors that are associated with the network
                        connector_ids = networksToConnectors.get(network_id, None)
                        if connector_ids is not None: # if there are connectors associated with the network
                            for connector_id in connector_ids:
                                # get the socket id of the connector
                                socket_id = connectorsToSockets.get(connector_id, None)
                                if socket_id is not None:
                                    # send the inserted resource to the connector 
                                    await sio.emit('insert_resource', {'resource': _resource}, room=socket_id)

                    elif event["ns"]["coll"] == "resources" and event['operationType'] == 'delete':
                        id = str(event['documentKey']['_id'])

                        # get the network id of the deleted resource
                        deleted_resource = event['fullDocumentBeforeChange']
                        network_id = deleted_resource['networkId']

                        # get the connectors that are associated with the network
                        connector_ids = networksToConnectors.get(network_id, None)
                        if connector_ids is not None: # if there are connectors associated with the network
                            for connector_id in connector_ids: 
                                # get the socket id of the connector
                                if connector_id in connectorsToSockets:
                                    socket_id = connectorsToSockets.get(connector_id, None)
                                    if socket_id is not None:
                                        # send the deleted resource to the connector
                                        await sio.emit('delete_resource', {'resource': id}, room=socket_id)

                        # get the users and groups that are associated with the resource and push the deleted resource to them
                        policies_collection = db.get_collection('policies')
                        policies = policies_collection.find({'resourceIds': {'$elemMatch': {'$eq': id}}}, {'_id': True, 'type': True, 'ids': True})

                        user_ids = []
                        group_ids = []
                        for policy in policies:
                            if policy['type'] == 'user':
                                user_ids.extend(policy['ids'])
                            elif policy['type'] == 'group':
                                group_ids.extend(policy['ids'])

                        user_ids = [ObjectId(userId) for userId in user_ids]

                        users_collection = db.get_collection('users')
                        users = users_collection.find({'$or': [{'_id': {'$in': user_ids}}, {'groups': {'$elemMatch': {'$in': group_ids}}}]}, {'_id': True})

                        for user in users:
                            user_id = str(user['_id'])
                            socket_id = clientsToSockets.get(user_id, None)
                            if socket_id is not None:
                                await sio.emit('delete_resources', {'resources': [id]}, room=socket_id)

                    elif event["ns"]["coll"] == "users" and event['operationType'] == 'delete':
                        id = str(event['documentKey']['_id'])

                        user = event['fullDocumentBeforeChange']
                        policies_collection = db.get_collection('policies')
                        user_policies = policies_collection.find({'ids': {'$elemMatch': {'$eq': id}}, 'type': 'user'}, {'resourceIds': True})
                        group_policies = policies_collection.find({'ids': {'$elemMatch': {'$in': user['groups']}}, 'type': 'group'}, {'resourceIds': True})

                        resourcesIds = []
                        for policy in user_policies:
                            resourcesIds.extend(policy['resourceIds'])
                        for policy in group_policies:
                            resourcesIds.extend(policy['resourceIds'])

                        resourcesIds = [ObjectId(resourceId) for resourceId in resourcesIds]
                        resources_collection = db.get_collection('resources')
                        resources = resources_collection.find({'_id': {'$in': resourcesIds}}, {'networkId': True})
                        network_ids = set([resource['networkId'] for resource in resources])

                        for network_id in network_ids:
                            connector_ids = networksToConnectors.get(network_id, None)
                            if connector_ids is not None:
                                for connector_id in connector_ids:
                                    socket_id = connectorsToSockets.get(connector_id, None)
                                    if socket_id is not None:
                                        await sio.emit('delete_user', {'user': id}, room=socket_id)

                        # push the deleted user to the respective client
                        socket_id = clientsToSockets.get(id, None)
                        if socket_id is not None:
                            await sio.emit('delete_user', {'id': id}, room=socket_id)

                    elif event["ns"]["coll"] == "users" and event['operationType'] == 'update':
                        important_fields = ['status', 'groups']
                        if 'updateDescription' not in event: continue
                        if 'updatedFields' not in event['updateDescription']: continue
                        if not any(field in event['updateDescription']['updatedFields'] for field in important_fields): continue

                        id = event['documentKey']['_id'] # get the id of the user (ObjectId not str)

                        updated_user = event['fullDocument']
                        previous_user = event['fullDocumentBeforeChange']

                        _user = {}
                        _id = str(id)
                        _user[_id] = updated_user
                        if '_id' in _user[_id]: del _user[_id]['_id']
                        if 'name' in _user[_id]: del _user[_id]['name']
                        if 'email' in _user[_id]: del _user[_id]['email']
                        if 'image' in _user[_id]: del _user[_id]['image']

                        _user = json.dumps(_user, default=str)

                        policies_collection = db.get_collection('policies')
                        user_policies = policies_collection.find(
                            {'ids': {'$elemMatch': {'$eq': id}}, 'type': 'user'},
                            {'resourceIds': True}
                        )
                        new_group_policies = policies_collection.find(
                            {'ids': {'$elemMatch': {'$in': updated_user['groups']}}, 'type': 'group'},
                            {'resourceIds': True}
                        )
                        old_group_policies = policies_collection.find(
                            {'ids': {'$elemMatch': {'$in': previous_user['groups']}}, 'type': 'group'},
                            {'resourceIds': True}
                        )

                        resources = []
                        for policy in user_policies:
                            resources.extend(policy['resourceIds'])
                        for policy in new_group_policies:
                            resources.extend(policy['resourceIds'])
                        for policy in old_group_policies:
                            resources.extend(policy['resourceIds'])

                        resources = [ObjectId(resourceId) for resourceId in resources]
                        resources = db.get_collection('resources').find({'_id': {'$in': resources}}, {'networkId': True})
                        network_ids = set([resource['networkId'] for resource in resources])

                        for network_id in network_ids:
                            connector_ids = networksToConnectors.get(network_id, None)
                            if connector_ids is not None:
                                for connector_id in connector_ids:
                                    socket_id = connectorsToSockets.get(connector_id, None)
                                    if socket_id is not None:
                                        await sio.emit('update_user', {'user': _user}, room=socket_id)

                        # push the updated user to the respective client
                        client_id = str(id)
                        socket_id = clientsToSockets.get(client_id, None)
                        if socket_id is not None:
                            # check if status is updated
                            if 'status' in event['updateDescription']['updatedFields']:
                                status = updated_user['status']
                                await sio.emit('update_status', {'id': client_id, 'status': status}, room=socket_id)

                            # check if groups is updated
                            if 'groups' in event['updateDescription']['updatedFields']:
                                previous_groups = previous_user['groups']
                                new_groups = updated_user['groups']

                                policies_collection = db.get_collection('policies')
                                previous_resources = policies_collection.find(
                                    {'ids': {'$elemMatch': {'$in': previous_groups}}, 'type': 'group'},
                                    {'_id': True, 'resourceIds': True}
                                )

                                new_resources = policies_collection.find(
                                    {'ids': {'$elemMatch': {'$in': new_groups}}, 'type': 'group'},
                                    {'_id': True, 'resourceIds': True}
                                )

                                previous_resources = set(previous_resources)
                                new_resources = set(new_resources)
                                # find resources that are in the previous groups and not in the new groups
                                removed_resources = previous_resources - new_resources
                                # find resources that are in the new groups and not in the previous groups
                                added_resources = new_resources - previous_resources

                                removed_resources = list(removed_resources)
                                if len(removed_resources) > 0:
                                    await sio.emit('delete_resources', {'resources': removed_resources}, room=socket_id)

                                added_resources = list(added_resources)
                                if len(added_resources) > 0:
                                    added_resources = [ObjectId(resourceId) for resourceId in added_resources]
                                    resources = db.get_collection('resources').find({'_id': {'$in': added_resources}}, {'_id': True, 'address': True, 'alias': True, 'networkId': True, 'tcpStatus': True, 'udpStatus': True, 'icmpStatus': True, 'tcpPorts': True, 'udpPorts': True})
                                    resources = list(resources)
                                    await sio.emit('insert_resources', {'resources': resources}, room=socket_id)

                    elif event["ns"]["coll"] == "policies" and event['operationType'] == 'delete':
                        id = str(event['documentKey']['_id'])

                        # Get the resourceIds of the deleted policy
                        deleted_policy = event['fullDocumentBeforeChange']
                        resourceIds = deleted_policy['resourceIds']

                        # Convert the resourceIds to ObjectId
                        resourceIds = [ObjectId(resourceId) for resourceId in resourceIds]

                        # Get the networks of the resources
                        resources = db.get_collection('resources').find({'_id': {'$in': resourceIds}}, {'_id': True, 'networkId': True})
                        resources = list(resources)

                        # Get the connectors that are associated with the networks
                        for resource in resources:
                            network_id = resource['networkId']
                            connector_ids = networksToConnectors.get(network_id, None)
                            if connector_ids is not None:
                                for connector_id in connector_ids:
                                    socket_id = connectorsToSockets.get(connector_id, None)
                                    if socket_id is not None:
                                        await sio.emit('delete_policy', {'policy': id}, room=socket_id)

                        # Get the users and groups that are associated with the policy and push the policy to them
                        users_collection = db.get_collection('users')
                        users = None
                        resourcesIds = [str(resourceId) for resourceId in resourceIds]

                        if deleted_policy['type'] == 'user':
                            user_ids = [ObjectId(userId) for userId in deleted_policy['ids']]
                            if len(user_ids) > 0:
                                users = users_collection.find({'_id': {'$in': user_ids}}, {'_id': True, 'groups': True})
                        elif deleted_policy['type'] == 'group':
                            group_ids = [groupId for groupId in deleted_policy['ids']]
                            if len(group_ids) > 0:
                                users = users_collection.find({'groups': {'$elemMatch': {'$in': group_ids}}}, {'_id': True, 'groups': True})

                        if users is not None:
                            for user in users:
                                user_id = str(user['_id'])

                                policies_collection = db.get_collection('policies')
                                new_user_resources = policies_collection.find(
                                    {'ids': {'$elemMatch': {'$eq': user_id}}, 'type': 'user'},
                                    {'_id': True, 'resourceIds': True}
                                )
                                new_group_resources = policies_collection.find(
                                    {'ids': {'$elemMatch': {'$in': user['groups']}}, 'type': 'group'},
                                    {'_id': True, 'resourceIds': True}
                                )
                                new_user_resources = [user['resourceIds'] for user in new_user_resources]
                                new_group_resources = [user['resourceIds'] for user in new_group_resources]
                                new_user_resources = set(chain(*new_user_resources))
                                new_group_resources = set(chain(*new_group_resources))
                                new_resources = set(new_user_resources) | set(new_group_resources)

                                # find resources that should be removed from the user
                                removed_resources = set(resourcesIds) - new_resources
                                removed_resources = list(removed_resources)

                                if len(removed_resources) > 0:
                                    await sio.emit('delete_resources', {'resources': removed_resources}, room=socket_id)

                    elif event["ns"]["coll"] == "policies" and event['operationType'] == 'update':
                        important_fields = ['resourceIds', 'ids']
                        if 'updateDescription' not in event: continue
                        if 'updatedFields' not in event['updateDescription']: continue
                        if not any(field in event['updateDescription']['updatedFields'] for field in important_fields): continue

                        id = event['documentKey']['_id']

                        updated_policy = event['fullDocument']
                        previous_policy = event['fullDocumentBeforeChange']
                        
                        _policy = {}
                        _policy[str(id)] = updated_policy
                        if '_id' in _policy[str(id)]: del _policy[str(id)]['_id']
                        if 'name' in _policy[str(id)]: del _policy[str(id)]['name']
                        if 'description' in _policy[str(id)]: del _policy[str(id)]['description']

                        resourceIds: list = [*_policy[str(id)]['resourceIds']]
                        resourceIds.extend(previous_policy['resourceIds'])
                        resourceIds = [ObjectId(resourceId) for resourceId in resourceIds]
                        
                        _policy = json.dumps(_policy, default=str)

                        resources = db.get_collection('resources').find({'_id': {'$in': resourceIds}}, {'_id': True, 'networkId': True})

                        for resource in resources:
                            network_id = resource['networkId']
                            connector_ids = networksToConnectors.get(network_id, None)
                            if connector_ids is not None:
                                for connector in connector_ids:
                                    socket_id = connectorsToSockets.get(connector, None)
                                    if socket_id is not None:
                                        await sio.emit('update_policy', {'policy': _policy}, room=socket_id)

                        # Push the updated policy to the users and groups that are associated with the policy
                        removed_resources = set(previous_policy['resourceIds']) - set(updated_policy['resourceIds'])
                        added_resources = set(updated_policy['resourceIds']) - set(previous_policy['resourceIds'])

                        users = None
                        if updated_policy['type'] == 'user':
                            previous_user_ids = [ObjectId(userId) for userId in previous_policy['ids']]
                            new_user_ids = [ObjectId(userId) for userId in updated_policy['ids']]

                            removed_user_ids = set(previous_user_ids) | set(new_user_ids)
                            if len(removed_user_ids) > 0:
                                users = db.get_collection('users').find({'_id': {'$in': list(removed_user_ids)}}, {'_id': True, 'groups': True})
                        elif updated_policy['type'] == 'group':
                            previous_group_ids = [groupId for groupId in previous_policy['ids']]
                            new_group_ids = [groupId for groupId in updated_policy['ids']]

                            removed_group_ids = set(previous_group_ids) | set(new_group_ids)
                            if len(removed_group_ids) > 0:
                                users = db.get_collection('users').find({'groups': {'$elemMatch': {'$in': list(removed_group_ids)}}}, {'_id': True, 'groups': True})

                        if users is not None:
                            for user in users: 
                                user_id = str(user['_id'])
                                socket_id = clientsToSockets.get(user_id, None)
                                if socket_id is not None:
                                    user_policies = db.get_collection('policies').find({'ids': {'$elemMatch': {'$eq': user_id}}, 'type': 'user'}, {'_id': True, 'resourceIds': True})
                                    group_policies = db.get_collection('policies').find({'ids': {'$elemMatch': {'$in': user['groups']}}, 'type': 'group'}, {'_id': True, 'resourceIds': True})

                                    user_policies = [user['resourceIds'] for user in user_policies]
                                    group_policies = [user['resourceIds'] for user in group_policies]
                                    user_policies = set(chain(*user_policies))
                                    group_policies = set(chain(*group_policies))
                                    current_user_resources = set(user_policies) | set(group_policies)

                                    insert_resources = set(added_resources) & set(current_user_resources)
                                    delete_resources = set(removed_resources) - set(current_user_resources)

                                    if len(insert_resources) > 0:
                                        insert_resources = [ObjectId(resourceId) for resourceId in insert_resources]
                                        resources = db.get_collection('resources').find({'_id': {'$in': insert_resources}}, {'_id': True, 'address': True, 'alias': True, 'networkId': True, 'tcpStatus': True, 'udpStatus': True, 'icmpStatus': True, 'tcpPorts': True, 'udpPorts': True})
                                        resources = list(resources)
                                        resources = json.dumps(resources, default=str)
                                        await sio.emit('insert_resources', {'resources': resources}, room=socket_id)

                                    if len(delete_resources) > 0:
                                        await sio.emit('delete_resources', {'resources': list(delete_resources)}, room=socket_id)

                    elif event["ns"]["coll"] == "policies" and event['operationType'] == 'insert':
                        id = event['documentKey']['_id']
                        
                        inserted_policy = event['fullDocument']

                        _policy = {}
                        _policy[str(id)] = dict(inserted_policy)
                        if '_id' in _policy[str(id)]: del _policy[str(id)]['_id']
                        if 'name' in _policy[str(id)]: del _policy[str(id)]['name']
                        if 'description' in _policy[str(id)]: del _policy[str(id)]['description']

                        resourceIds = _policy[str(id)]['resourceIds']
                        resourceIds = [ObjectId(resourceId) for resourceId in resourceIds]

                        _policy = json.dumps(_policy, default=str)

                        resources = db.get_collection('resources').find({'_id': {'$in': resourceIds}}, {'_id': True, 'address': True, 'alias': True, 'networkId': True, 'tcpStatus': True, 'udpStatus': True, 'icmpStatus': True, 'tcpPorts': True, 'udpPorts': True})
                        resources = list(resources)

                        for resource in resources:
                            network_id = resource['networkId']
                            connector_ids = networksToConnectors.get(network_id, None)
                            if connector_ids is not None:
                                for connector_id in connector_ids:
                                    socket_id = connectorsToSockets.get(connector_id, None)
                                    if socket_id is not None:
                                        await sio.emit('insert_policy', {'policy': _policy}, room=socket_id)

                        # get the users/groups that are associated with the policy and push the policy to them
                        users_collection = db.get_collection('users')
                        users = None
                        if inserted_policy['type'] == 'user':
                            user_ids = [ObjectId(userId) for userId in inserted_policy['ids']]
                            if len(user_ids) > 0:
                                users = users_collection.find({'_id': {'$in': user_ids}}, {'_id': True})
                        elif inserted_policy['type'] == 'group':
                            group_ids = [groupId for groupId in inserted_policy['ids']]
                            if len(group_ids) > 0:
                                users = users_collection.find({'groups': {'$elemMatch': {'$in': group_ids}}}, {'_id': True})
                        
                        _resources = json.dumps(resources, default=str)
                        if users is not None:
                            for user in users:
                                user_id = str(user['_id'])
                                socket_id = clientsToSockets.get(user_id, None)
                                if socket_id is not None:
                                    await sio.emit('insert_resources', {'resources': _resources}, room=socket_id)

        except PyMongoError as e:
            print(e)

def run_watch_changes_in_db():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(watch_changes_in_db())

@sio.event
def connect(sid, environ):
    print("connect ", sid)

@sio.event
async def register_connector(sid, data: dict):
    print("register_connector ", data)

    access_token = data.get('access_token', None)
    if access_token is None: return

    try:
        claims = jwt.decode(access_token, jwk_from_pem(public_key), algorithms=['RS256'])
    except Exception as e:
        print(e)
        if e == "JWT Expired":
            await sio.emit('token_expired', room=sid)
        return
    
    id = claims.get('id', None)
    if id is None: return

    # Fetch connector data from the database
    connectors_collection = db.get_collection('connectors')
    connector = connectors_collection.find_one({'_id': ObjectId(id)})

    if connector is None: # if the connector does not exist in the database, then it is an anomaly
        return
    
    # Fetch network of that connector
    networks_collection = db.get_collection('networks')
    network = networks_collection.find_one({'_id': ObjectId(connector['networkId'])})

    if network is None: # if the network does not exist in the database, then it is an anomaly
        return
    
    # Add the connector to the dictionaries
    connectorsToSockets[id] = sid
    socketsToConnectors[sid] = id
    connectorsToNetworks[id] = connector['networkId']
    if networksToConnectors.get(connector['networkId'], None) is None:
        networksToConnectors[connector['networkId']] = []
    networksToConnectors[connector['networkId']].append(id)

    # Fetch Resources within the network
    resources_collection = db.get_collection('resources')
    resources = resources_collection.find(
        {
            'networkId': connector['networkId']
        }, 
        {
            '_id': True, 
            'address': True, 
            'alias': True, 
            'networkId': True, 
            'tcpStatus': True, 
            'udpStatus': True, 
            'icmpStatus': True, 
            'tcpPorts': True, 
            'udpPorts': True
        }
    )
    resources = list(resources)

    _resourceIds = []
    _resources = {}
    for resource in resources:
        _id = str(resource.pop('_id'))

        _resourceIds.append(_id)
        _resources[_id] = resource

    # Send the resources to the connector
    _resources = json.dumps(_resources, default=str)
    await sio.emit('init_resources', {'resources': _resources}, room=sid)

    # Fetch Policies wihch are associated with the resources
    policies_collection = db.get_collection('policies')
    policies = policies_collection.find(
        {
            'resourceIds': {'$elemMatch': {'$in': _resourceIds}} # find policies that are associated with the resources
        }, 
        {
            '_id': True, 
            'type': True, 
            'ids': True, 
            'resourceIds': True
        }
    )
    policies = list(policies)

    _policies = {}
    users_in_policies = []
    groups_in_policies = []
    for policy in policies:
        _id = str(policy.pop('_id'))
        _policies[_id] = policy

        if policy['type'] == 'user':
            users_in_policies.extend(policy['ids'])
        elif policy['type'] == 'group':
            groups_in_policies.extend(policy['ids'])

    # Send the policies to the connector
    _policies = json.dumps(_policies, default=str)
    await sio.emit('init_policies', {'policies': _policies}, room=sid)

    # Convert the ids to ObjectId
    users_in_policies = [ObjectId(userId) for userId in users_in_policies]
    groups_in_policies = [ObjectId(groupId) for groupId in groups_in_policies]

    # Find relevant users and relevant groups
    users_collection = db.get_collection('users')
    users = users_collection.find(
        {
            '_id': {'$in': users_in_policies}
        }, 
        {
            '_id': True, 
            'ip': True, 
            'status': True, 
            'groups': True
        }
    )

    _users = {}
    for user in users:
        _id = str(user.pop('_id'))
        _users[_id] = user

    groups_collection = db.get_collection('groups')
    groups = groups_collection.find({'_id': {'$in': groups_in_policies}}, {'_id': True})

    for group in groups:
        _gid = str(group.pop('_id'))
        __users = users_collection.find(
            {
                'groups': {'$elemMatch': {'$eq': _gid}}
            }, 
            {
                '_id': True, 
                'ip': True, 
                'status': True, 
                'groups': True
            }
        )
        
        for user in __users:
            _id = str(user.pop('_id'))
            if _id not in _users:
                _users[_id] = user

    # Send the users
    _users = json.dumps(_users, default=str)
    await sio.emit('init_users', {'users': _users}, room=sid)

@sio.event
async def register_client(sid, data: dict):
    print("register_client ", data)

    access_token = data.get('access_token', None)
    code_verifier = data.get('code_verifier', None)
    if access_token is None: return

    try:
        claims = jwt.decode(access_token, jwk_from_pem(public_key), algorithms=['RS256'])
    except Exception as e:
        print(e)
        if e == "JWT Expired":
            await sio.emit('token_expired', room=sid)
        return
    
    # Only validate code_verifier if it's provided (for GetToken workflow)
    # Treat empty string same as None
    if code_verifier is not None and code_verifier != '':
        signed_challenge = claims.get('challenge', None)
        code_challenge = urlsafe_b64encode(sha256(code_verifier.encode('ascii')).digest()).decode('ascii')[:-1]

        if signed_challenge != code_challenge:
            print("Invalid code verifier")
            return

    id = claims.get('id', None)
    if id is None:
        print("ERROR: No id in claims")
        return

    clientsToSockets[id] = sid
    socketsToClients[sid] = id

    # Fetch details of user from the database
    users_collection = db.get_collection('users')
    user = users_collection.find_one({'_id': ObjectId(id)}, {'_id': True, 'ip': True, 'status': True, 'groups': True})

    print(f"DEBUG: User lookup for id={id}, found={user is not None}")
    
    if user is None: # if the user does not exist in the database, then it is an anomaly
        print(f"ERROR: User {id} not found in database")
        return
    
    print(f"DEBUG: User status={user.get('status')}, ip={user.get('ip')}")
    
    if user['status'] == False:
        print(f"ERROR: User {id} is disabled")
        return
    
    if not user.get('ip'):
        print(f"ERROR: User {id} has no IP assigned")
        return
    
    print(f"SUCCESS: Sending set_client_ip with ip={user['ip']} to sid={sid}")
    await sio.emit('set_client_ip', {'ip': user['ip']}, room=sid)
    
@sio.event
async def get_resources_client(sid, data: dict):
    print("get_resources_client ", data)

    id = data.get('id', None)
    if id is None: return

    if id not in clientsToSockets: return

    user = db.get_collection('users').find_one({'_id': ObjectId(id)}, {'_id': True, 'groups': True})

    policies_collection = db.get_collection('policies')
    user_policies = policies_collection.find({'ids': {'$elemMatch': {'$eq': id}}, 'type': 'user'}, {'_id': True, 'type': True, 'ids': True, 'resourceIds': True})
    group_policies = policies_collection.find({'ids': {'$elemMatch': {'$in': user['groups']}}, 'type': 'group'}, {'_id': True, 'type': True, 'ids': True, 'resourceIds': True})

    resourcesIds = []
    for policy in user_policies:
        resourcesIds.extend(policy['resourceIds'])

    for policy in group_policies:
        resourcesIds.extend(policy['resourceIds'])

    resourcesIds = [ObjectId(resourceId) for resourceId in resourcesIds]

    resources_collection = db.get_collection('resources')
    resources = resources_collection.find({'_id': {'$in': resourcesIds}}, {'_id': True, 'address': True, 'alias': True, 'networkId': True, 'tcpStatus': True, 'udpStatus': True, 'icmpStatus': True, 'tcpPorts': True, 'udpPorts': True})
    
    _resources = {}
    connectors_collection = db.get_collection('connectors')
    for resource in resources:
        _id = str(resource.pop('_id'))
        _resources[_id] = resource

        network_id = resource['networkId']
        connector_ips = connectors_collection.find({'networkId': network_id, 'status': True}, {'ip': True})
        connector_ips = [connector['ip'] for connector in connector_ips]

        connecter_ip = choice(connector_ips)
        _resources[_id]['connectorIp'] = connecter_ip

    _resources = json.dumps(_resources, default=str)
    await sio.emit('init_resources', {'resources': _resources}, room=sid)

@sio.event
async def get_users(sid, data: dict):
    print("get_users ", data)

    ids = data.get('ids', None)
    if ids is None: return
    users_collection = db.get_collection('users')
    users = users_collection.find({'_id': {'$in': ids}}, {'_id': True, 'ip': True, 'status': True, 'groups': True})

    _users = {}
    for user in users:
        _id = str(user.pop('_id'))
        _users[_id] = user

    _users = json.dumps(_users, default=str)
    await sio.emit('recieve_users', {'users': _users}, room=sid)

@sio.event
async def get_groups(sid, data: dict):
    print("get_groups ", data)

    ids = data.get('ids', None)
    if ids is None: return
    users_collection = db.get_collection('users')
    users = users_collection.find({'groups': {'$elemMatch': {'$in': ids}}}, {'_id': True, 'ip': True, 'status': True, 'groups': True})

    _users = {}
    for user in users:
        _id = str(user.pop('_id'))
        _users[_id] = user

    _users = json.dumps(_users, default=str)
    await sio.emit('recieve_users', {'users': _users}, room=sid)

@sio.event
def disconnect(sid):
    print('disconnect ', sid)

    # remove the connector from the dictionaries
    id = socketsToConnectors.get(sid, None)
    if id is not None:
        connectorsToSockets.pop(id)
        socketsToConnectors.pop(sid)

        # remove the connector from the networksToConnectors and connectorsToNetworks
        network_id = connectorsToNetworks.get(id, None)
        if network_id is not None:
            networksToConnectors[network_id].remove(id)
            connectorsToNetworks.pop(id)

    # remove the client from the dictionaries
    id = socketsToClients.get(sid, None)
    if id is not None:
        clientsToSockets.pop(id)
        socketsToClients.pop(sid)

if __name__ == '__main__':    
    changes_thread = Thread(target=run_watch_changes_in_db)
    changes_thread.start()

    if os.path.isdir('/cert') and os.path.exists('/cert/fullchain.pem') and os.path.exists('/cert/privkey.pem'):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain('/cert/fullchain.pem', '/cert/privkey.pem')
        web.run_app(app, host='0.0.0.0', port=5001, ssl_context=context)
    else:
        web.run_app(app, host='0.0.0.0', port=5001)